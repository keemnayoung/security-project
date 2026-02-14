#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-07
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-63
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : sudo 명령어 접근 관리
# @Description : /etc/sudoers 파일 권한 적절성 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-63 sudo 명령어 접근 관리

# 기본 변수
ID="U-63"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND="stat -c '%U %a %n' /etc/sudoers 2>/dev/null"
REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE="/etc/sudoers"

# 유틸: JSON escape
json_escape() {
  echo "$1" | sed ':a;N;$!ba;s/\n/\\n/g' | sed 's/"/\\"/g'
}

# 로직(사용자 제공 스크립트 기반)
ACTION_RESULT="SUCCESS"
ACTION_LOG=""

if [ -f "$TARGET_FILE" ]; then
  # 현재 상태 확인
  OWNER="$(stat -c '%U' "$TARGET_FILE" 2>/dev/null)"
  PERMS="$(stat -c '%a' "$TARGET_FILE" 2>/dev/null)"

  # 소유자 변경
  if [ "$OWNER" != "root" ]; then
    chown root "$TARGET_FILE" 2>/dev/null
    ACTION_LOG="$ACTION_LOG 소유자를 root로 변경했습니다."
  fi

  # 권한 변경
  if [ -n "$PERMS" ] && [ "$PERMS" -gt 640 ]; then
    chmod 640 "$TARGET_FILE" 2>/dev/null
    ACTION_LOG="$ACTION_LOG 권한을 640으로 변경했습니다."
  fi

  # 변경 후 상태 확인(현재(after)만)
  AFTER_OWNER="$(stat -c '%U' "$TARGET_FILE" 2>/dev/null)"
  AFTER_PERMS="$(stat -c '%a' "$TARGET_FILE" 2>/dev/null)"
  DETAIL_CONTENT="/etc/sudoers 현재 설정: owner=${AFTER_OWNER:-unknown}, perm=${AFTER_PERMS:-unknown}"

else
  ACTION_RESULT="FAIL"
  ACTION_LOG="/etc/sudoers 파일이 존재하지 않습니다."
fi

# 결과 판단(사용자 제공 흐름 유지)
if [ "$ACTION_RESULT" = "FAIL" ]; then
  IS_SUCCESS=0
  REASON_LINE="/etc/sudoers 파일이 존재하지 않아 조치가 완료되지 않았습니다."
elif [ -n "$ACTION_LOG" ]; then
  IS_SUCCESS=1
  REASON_LINE="/etc/sudoers 파일의 소유자를 root로 변경하고 권한을 640으로 설정했습니다."
else
  IS_SUCCESS=1
  REASON_LINE="/etc/sudoers 파일이 이미 적절한 권한으로 설정되어 있습니다."
fi

# raw_evidence 구성(command/detail/target_file) + escape
RAW_EVIDENCE_JSON=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE
$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

RAW_EVIDENCE_ESCAPED="$(json_escape "$RAW_EVIDENCE_JSON")"

# 최종 출력 (프로젝트 표준: echo "" 후 scan 결과 JSON)
echo ""
cat << EOF
{
  "item_code": "$ID",
  "action_date": "$ACTION_DATE",
  "is_success": $IS_SUCCESS,
  "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
}
EOF