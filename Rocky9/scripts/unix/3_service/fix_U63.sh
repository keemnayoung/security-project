#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.0
# @Author: 이가영
# @Last Updated: 2026-02-16
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

TARGET_FILE="/etc/sudoers"
CHECK_COMMAND="stat -c '%U %G %a %n' /etc/sudoers 2>/dev/null || echo 'sudoers_not_found_or_stat_failed'"

REASON_LINE=""
DETAIL_CONTENT=""
ACTION_ERR_LOG=""

append_err(){ [ -z "${1:-}" ] && return 0; ACTION_ERR_LOG="${ACTION_ERR_LOG}${ACTION_ERR_LOG:+\n}$1"; }

json_escape() {
  echo "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; :a;N;$!ba;s/\n/\\n/g'
}

# 조치 로직
if [ ! -f "$TARGET_FILE" ]; then
  REASON_LINE="/etc/sudoers 파일이 존재하지 않아 조치가 완료되지 않았습니다."
else
  OWNER="$(stat -c '%U' "$TARGET_FILE" 2>/dev/null || true)"
  PERM="$(stat -c '%a' "$TARGET_FILE" 2>/dev/null || true)"

  if [ -z "$OWNER" ] || [ -z "$PERM" ] || ! echo "$PERM" | grep -Eq '^[0-7]{3,4}$'; then
    REASON_LINE="/etc/sudoers의 소유자/권한 정보를 수집하지 못해 조치가 완료되지 않았습니다."
  else
    # 1) 소유자 root로 통일(가이드)
    if [ "$OWNER" != "root" ]; then
      chown root "$TARGET_FILE" 2>/dev/null || append_err "chown_failed"
    fi

    # 2) 권한 640 이하로 조정(가이드)
    if [ "$PERM" -gt 640 ]; then
      chmod 640 "$TARGET_FILE" 2>/dev/null || append_err "chmod_failed"
    fi

    # 3) 조치 후 재수집(After only)
    AFTER_OWNER="$(stat -c '%U' "$TARGET_FILE" 2>/dev/null || echo "unknown")"
    AFTER_GROUP="$(stat -c '%G' "$TARGET_FILE" 2>/dev/null || echo "unknown")"
    AFTER_PERM="$(stat -c '%a' "$TARGET_FILE" 2>/dev/null || echo "unknown")"
    DETAIL_CONTENT="/etc/sudoers 현재 설정: owner=${AFTER_OWNER}, group=${AFTER_GROUP}, perm=${AFTER_PERM}"

    # 4) 최종 검증
    if [ -n "$ACTION_ERR_LOG" ]; then
      REASON_LINE="조치 수행 중 오류가 발생하여 조치가 완료되지 않았습니다."
    elif [ "$AFTER_OWNER" = "root" ] && echo "$AFTER_PERM" | grep -Eq '^[0-7]{3,4}$' && [ "$AFTER_PERM" -le 640 ]; then
      IS_SUCCESS=1
      REASON_LINE="/etc/sudoers 파일의 소유자를 root로 설정하고 권한을 640 이하로 적용하여 조치가 완료되었습니다."
    else
      REASON_LINE="/etc/sudoers 파일의 소유자/권한이 기준에 부합하지 않아 조치가 완료되지 않았습니다."
    fi
  fi
fi

[ -z "$DETAIL_CONTENT" ] && DETAIL_CONTENT="N/A"

# raw_evidence (command/detail/target_file) + escape
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

# 최종 출력
echo ""
cat <<EOF
{
  "item_code": "$ID",
  "action_date": "$ACTION_DATE",
  "is_success": $IS_SUCCESS,
  "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
}
EOF