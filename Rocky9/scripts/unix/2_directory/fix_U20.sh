#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-20
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : /etc/(x)inetd.conf 파일 소유자 및 권한 설정
# @Description : /etc/(x)inetd.conf 파일의 소유자가 root이고, 권한이 600 이하로 설정
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-20"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND=""
REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""

FILES=(
  "/etc/inetd.conf"
  "/etc/xinetd.conf"
  "/etc/systemd/system.conf"
)

DIR="/etc/systemd"

CHECK_COMMAND="for f in /etc/inetd.conf /etc/xinetd.conf /etc/systemd/system.conf; do [ -f \"\$f\" ] && stat -c '%U %G %a %n' \"\$f\"; done; [ -d /etc/systemd ] && find /etc/systemd -type f -exec stat -c '%U %G %a %n' {} \\; 2>/dev/null"
TARGET_FILE=$(printf "%s\n" "${FILES[@]}")
if [ -d "$DIR" ]; then
  TARGET_FILE="${TARGET_FILE}
$DIR/*"
fi

FAIL_FLAG=0
MODIFIED=0
DETAIL_CONTENT=""

# 개별 파일 조치
for FILE in "${FILES[@]}"; do
  if [ ! -f "$FILE" ]; then
    continue
  fi

  OWNER=$(stat -c "%U" "$FILE" 2>/dev/null)
  GROUP=$(stat -c "%G" "$FILE" 2>/dev/null)
  PERM=$(stat -c "%a" "$FILE" 2>/dev/null)

  if [ "$OWNER" != "root" ] || [ "$GROUP" != "root" ]; then
    chown root:root "$FILE" 2>/dev/null
    MODIFIED=1
  fi

  if [ -n "$PERM" ] && [ "$PERM" -gt 600 ]; then
    chmod 600 "$FILE" 2>/dev/null
    MODIFIED=1
  fi
done

# systemd 디렉터리 내 파일 조치
if [ -d "$DIR" ]; then
  while IFS= read -r FILE; do
    [ -f "$FILE" ] || continue

    OWNER=$(stat -c "%U" "$FILE" 2>/dev/null)
    GROUP=$(stat -c "%G" "$FILE" 2>/dev/null)
    PERM=$(stat -c "%a" "$FILE" 2>/dev/null)

    if [ "$OWNER" != "root" ] || [ "$GROUP" != "root" ]; then
      chown root:root "$FILE" 2>/dev/null
      MODIFIED=1
    fi

    if [ -n "$PERM" ] && [ "$PERM" -gt 600 ]; then
      chmod 600 "$FILE" 2>/dev/null
      MODIFIED=1
    fi
  done < <(find "$DIR" -type f 2>/dev/null)
fi

# 조치 후 상태 수집(조치 후 상태만 detail에 표시)
for FILE in "${FILES[@]}"; do
  if [ -f "$FILE" ]; then
    AFTER_OWNER=$(stat -c "%U" "$FILE" 2>/dev/null)
    AFTER_GROUP=$(stat -c "%G" "$FILE" 2>/dev/null)
    AFTER_PERM=$(stat -c "%a" "$FILE" 2>/dev/null)

    DETAIL_CONTENT="${DETAIL_CONTENT}owner=$AFTER_OWNER
group=$AFTER_GROUP
perm=$AFTER_PERM
file=$FILE

"

    if [ "$AFTER_OWNER" != "root" ] || [ "$AFTER_GROUP" != "root" ] || [ -n "$AFTER_PERM" ] && [ "$AFTER_PERM" -gt 600 ]; then
      FAIL_FLAG=1
    fi
  fi
done

if [ -d "$DIR" ]; then
  while IFS= read -r FILE; do
    [ -f "$FILE" ] || continue

    AFTER_OWNER=$(stat -c "%U" "$FILE" 2>/dev/null)
    AFTER_GROUP=$(stat -c "%G" "$FILE" 2>/dev/null)
    AFTER_PERM=$(stat -c "%a" "$FILE" 2>/dev/null)

    DETAIL_CONTENT="${DETAIL_CONTENT}owner=$AFTER_OWNER
group=$AFTER_GROUP
perm=$AFTER_PERM
file=$FILE

"

    if [ "$AFTER_OWNER" != "root" ] || [ "$AFTER_GROUP" != "root" ] || [ -n "$AFTER_PERM" ] && [ "$AFTER_PERM" -gt 600 ]; then
      FAIL_FLAG=1
    fi
  done < <(find "$DIR" -type f 2>/dev/null)
fi

# 최종 판정
if [ "$FAIL_FLAG" -eq 0 ]; then
  IS_SUCCESS=1
  if [ "$MODIFIED" -eq 1 ]; then
    REASON_LINE="대상 파일의 소유자와 그룹이 root로 설정되고 권한이 600 이하로 적용되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
  else
    REASON_LINE="대상 파일의 소유자와 그룹이 root이고 권한이 600 이하로 유지되어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
  fi
else
  IS_SUCCESS=0
  REASON_LINE="조치를 수행했으나 일부 파일의 소유자 또는 권한이 기준을 충족하지 못해 조치가 완료되지 않았습니다."
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