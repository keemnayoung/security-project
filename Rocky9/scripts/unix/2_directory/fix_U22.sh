#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-22
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : /etc/services 파일 소유자 및 권한 설정
# @Description : /etc/services 파일의 소유자가 root(또는 bin, sys)이고, 권한이 644 이하로 설정
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash

# 기본 변수
ID="U-22"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND=""
REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""

TARGET_FILE="/etc/services"
CHECK_COMMAND="stat -c '%U %G %a %n' /etc/services 2>/dev/null"

# 조치 프로세스
if [ -f "$TARGET_FILE" ]; then
  MODIFIED=0

  OWNER=$(stat -c "%U" "$TARGET_FILE" 2>/dev/null)
  GROUP=$(stat -c "%G" "$TARGET_FILE" 2>/dev/null)
  PERM=$(stat -c "%a" "$TARGET_FILE" 2>/dev/null)

  if [ "$OWNER" != "root" ]; then
    chown root "$TARGET_FILE" 2>/dev/null
    MODIFIED=1
  fi

  if [ -n "$PERM" ] && [ "$PERM" -gt 644 ]; then
    chmod 644 "$TARGET_FILE" 2>/dev/null
    MODIFIED=1
  fi

  AFTER_OWNER=$(stat -c "%U" "$TARGET_FILE" 2>/dev/null)
  AFTER_GROUP=$(stat -c "%G" "$TARGET_FILE" 2>/dev/null)
  AFTER_PERM=$(stat -c "%a" "$TARGET_FILE" 2>/dev/null)

  DETAIL_CONTENT="owner=$AFTER_OWNER
group=$AFTER_GROUP
perm=$AFTER_PERM"

  if [[ "$AFTER_OWNER" =~ ^(root|bin|sys)$ ]] && [ -n "$AFTER_PERM" ] && [ "$AFTER_PERM" -le 644 ]; then
    IS_SUCCESS=1
    if [ "$MODIFIED" -eq 1 ]; then
      REASON_LINE="/etc/services 파일의 소유자와 권한이 기준에 맞게 적용되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
    else
      REASON_LINE="/etc/services 파일의 소유자와 권한이 기준에 맞게 유지되어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
    fi
  else
    IS_SUCCESS=0
    REASON_LINE="조치를 수행했으나 /etc/services 파일의 소유자 또는 권한이 기준을 충족하지 못해 조치가 완료되지 않았습니다."
  fi
else
  IS_SUCCESS=0
  REASON_LINE="조치 대상 파일(/etc/services)이 존재하지 않아 조치가 완료되지 않았습니다."
  DETAIL_CONTENT=""
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