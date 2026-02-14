#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-21
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : /etc/(r)syslog.conf 파일 소유자 및 권한 설정
# @Description : /etc/(r)syslog.conf 파일의 소유자가 root(또는 bin, sys)이고, 권한이 640 이하로 설정
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-21"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND=""
REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""

LOG_FILES=("/etc/syslog.conf" "/etc/rsyslog.conf")

CHECK_COMMAND="for f in /etc/syslog.conf /etc/rsyslog.conf; do [ -f \"\$f\" ] && stat -c '%U %G %a %n' \"\$f\"; done 2>/dev/null"

FOUND=0
FAIL_FLAG=0
MODIFIED=0
DETAIL_CONTENT=""

# evidence에 넣을 실제 존재 파일 목록
TARGET_FILES_EXIST=""

# 조치 수행
for FILE in "${LOG_FILES[@]}"; do
  if [ -f "$FILE" ]; then
    FOUND=1
    TARGET_FILES_EXIST="${TARGET_FILES_EXIST}${FILE}"$'\n'

    OWNER=$(stat -c "%U" "$FILE" 2>/dev/null)
    GROUP=$(stat -c "%G" "$FILE" 2>/dev/null)
    PERM=$(stat -c "%a" "$FILE" 2>/dev/null)

    # [필수] 소유자 기준: root|bin|sys 허용 → 그 외만 root로 변경
    if ! [[ "$OWNER" =~ ^(root|bin|sys)$ ]]; then
      chown root "$FILE" 2>/dev/null
      MODIFIED=1
    fi

    # 권한 기준: 640 초과면 640으로 변경
    if [ -n "$PERM" ] && [ "$PERM" -gt 640 ]; then
      chmod 640 "$FILE" 2>/dev/null
      MODIFIED=1
    fi
  fi
done

# 조치 후 상태 수집(조치 후 상태만 detail에 표시)
for FILE in "${LOG_FILES[@]}"; do
  if [ -f "$FILE" ]; then
    AFTER_OWNER=$(stat -c "%U" "$FILE" 2>/dev/null)
    AFTER_GROUP=$(stat -c "%G" "$FILE" 2>/dev/null)
    AFTER_PERM=$(stat -c "%a" "$FILE" 2>/dev/null)

    DETAIL_CONTENT="${DETAIL_CONTENT}owner=$AFTER_OWNER
group=$AFTER_GROUP
perm=$AFTER_PERM
file=$FILE

"

    # [필수] 논리식 모호성 제거(오탐/미탐 방지)
    if { ! [[ "$AFTER_OWNER" =~ ^(root|bin|sys)$ ]]; } || { [ -n "$AFTER_PERM" ] && [ "$AFTER_PERM" -gt 640 ]; }; then
      FAIL_FLAG=1
    fi
  fi
done

# target_file 구성: 실제 존재 파일만 (없으면 원래 리스트 출력)
if [ -n "$TARGET_FILES_EXIST" ]; then
  TARGET_FILE="$(printf "%s" "$TARGET_FILES_EXIST" | sed 's/[[:space:]]*$//')"
else
  TARGET_FILE=$(printf "%s\n" "${LOG_FILES[@]}")
fi

# 최종 판정
if [ "$FOUND" -eq 0 ]; then
  IS_SUCCESS=1
  REASON_LINE="syslog 설정 파일이 존재하지 않아 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
  DETAIL_CONTENT=""
else
  if [ "$FAIL_FLAG" -eq 0 ]; then
    IS_SUCCESS=1
    if [ "$MODIFIED" -eq 1 ]; then
      REASON_LINE="syslog 설정 파일의 소유자와 권한이 기준에 맞게 적용되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
    else
      REASON_LINE="syslog 설정 파일의 소유자와 권한이 기준에 맞게 유지되어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
    fi
  else
    IS_SUCCESS=0
    REASON_LINE="조치를 수행했으나 syslog 설정 파일의 소유자 또는 권한이 기준을 충족하지 못해 조치가 완료되지 않았습니다."
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