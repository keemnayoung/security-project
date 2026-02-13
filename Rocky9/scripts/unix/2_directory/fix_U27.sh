#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-27
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : $HOME/.rhosts, hosts.equiv 사용 금지
# @Description : $HOME/.rhosts 및 /etc/hosts.equiv 파일에 대해 적절한 소유자 및 접근 권한 설정
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================


# 기본 변수
ID="U-27"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND=""
REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""

LOG_FILE_FIXED=0
FAIL_FLAG=0
FOUND=0
DETAIL_CONTENT=""
TARGET_FILE=""

CHECK_COMMAND="( [ -f /etc/hosts.equiv ] && stat -c '%U %G %a %n' /etc/hosts.equiv && grep -nE '^[[:space:]]*\\+' /etc/hosts.equiv 2>/dev/null ) ; find /home -name .rhosts -type f -print -exec stat -c '%U %G %a %n' {} \\; -exec grep -nE '^[[:space:]]*\\+' {} \\; 2>/dev/null"

# 대상 파일 수집
TARGET_LIST=()

if [ -f "/etc/hosts.equiv" ]; then
  TARGET_LIST+=("/etc/hosts.equiv")
fi

while IFS= read -r rf; do
  [ -f "$rf" ] && TARGET_LIST+=("$rf")
done < <(find /home -name ".rhosts" -type f 2>/dev/null)

if [ "${#TARGET_LIST[@]}" -gt 0 ]; then
  FOUND=1
fi

TARGET_FILE=$(printf "%s\n" "${TARGET_LIST[@]}")

# 조치 수행
if [ "$FOUND" -eq 1 ]; then
  for file in "${TARGET_LIST[@]}"; do
    [ -f "$file" ] || continue

    # 소유자 조치
    if [ "$file" = "/etc/hosts.equiv" ]; then
      OWNER=$(stat -c "%U" "$file" 2>/dev/null)
      if [ "$OWNER" != "root" ]; then
        chown root:root "$file" 2>/dev/null
      fi
    else
      FILE_USER=$(stat -c "%U" "$file" 2>/dev/null)
      [ -n "$FILE_USER" ] && chown "$FILE_USER":"$FILE_USER" "$file" 2>/dev/null
    fi

    # 권한 조치
    chmod 600 "$file" 2>/dev/null

    # '+' 제거
    sed -i '/^[[:space:]]*\+/d' "$file" 2>/dev/null
  done
fi

# 조치 후 상태 수집(조치 후 상태만 detail에 표시)
if [ "$FOUND" -eq 0 ]; then
  IS_SUCCESS=1
  REASON_LINE="조치 대상 파일이 존재하지 않아 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
  DETAIL_CONTENT=""
else
  for file in "${TARGET_LIST[@]}"; do
    [ -f "$file" ] || continue

    AFTER_OWNER=$(stat -c "%U" "$file" 2>/dev/null)
    AFTER_GROUP=$(stat -c "%G" "$file" 2>/dev/null)
    AFTER_PERM=$(stat -c "%a" "$file" 2>/dev/null)

    PLUS_AFTER=$(grep -nE '^[[:space:]]*\+' "$file" 2>/dev/null)

    DETAIL_CONTENT="${DETAIL_CONTENT}owner=$AFTER_OWNER
group=$AFTER_GROUP
perm=$AFTER_PERM
file=$file
$( [ -n "$PLUS_AFTER" ] && echo "$PLUS_AFTER" || echo "" )

"

    # 기준 검증: owner( /etc/hosts.equiv= root, .rhosts= 파일소유자 ), perm<=600, '+' 없음
    if [ "$file" = "/etc/hosts.equiv" ]; then
      [ "$AFTER_OWNER" != "root" ] && FAIL_FLAG=1
    fi

    if [ -n "$AFTER_PERM" ] && [ "$AFTER_PERM" -gt 600 ]; then
      FAIL_FLAG=1
    fi

    if [ -n "$PLUS_AFTER" ]; then
      FAIL_FLAG=1
    fi
  done

  if [ "$FAIL_FLAG" -eq 0 ]; then
    IS_SUCCESS=1
    REASON_LINE="/etc/hosts.equiv 및 .rhosts 파일의 권한이 600 이하로 설정되고 '+' 패턴이 제거되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
  else
    IS_SUCCESS=0
    REASON_LINE="조치를 수행했으나 /etc/hosts.equiv 또는 .rhosts 파일의 권한 또는 '+' 패턴 기준을 충족하지 못해 조치가 완료되지 않았습니다."
  fi
fi

# raw_evidence 구성
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

# JSON escape 처리 (따옴표, 줄바꿈)
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/"/\\"/g' \
  | sed ':a;N;$!ba;s/\n/\\n/g')

# DB 저장용 JSON 출력
echo ""
cat << EOF
{
    "item_code": "$ID",
    "action_date": "$ACTION_DATE",
    "is_success": $IS_SUCCESS,
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
}
EOF