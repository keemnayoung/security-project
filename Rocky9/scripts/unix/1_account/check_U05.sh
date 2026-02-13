#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 김나영
# @Last Updated: 2026-02-09
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-05
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : UID가 0인 일반 계정 존재
# @Description : root 계정 이외에 UID가 0인 계정이 존재하는지 점검
# @Criteria_Good : root 계정 이외에 UID가 0인 계정이 존재하지 않는 경우
# @Criteria_Bad : root 계정 이외에 UID가 0인 계정이 존재하는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-05"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/passwd"

# 실제 점검 커맨드(증거용): getent 우선, 실패 시 /etc/passwd로 fallback
CHECK_COMMAND='(command -v getent >/dev/null 2>&1 && getent passwd | awk -F: '\''$3 == 0 && $1 != "root" {print $1 ":" $3}'\'') || ([ -f /etc/passwd ] && awk -F: '\''$3 == 0 && $1 != "root" {print $1 ":" $3}'\'' /etc/passwd) || echo "passwd_not_found"'

REASON_LINE=""
DETAIL_CONTENT=""

UID_ZERO_ACCOUNTS=""

# 1) getent 사용 가능하면 getent 기준으로 점검 (LDAP/NIS 등 NSS 반영)
if command -v getent >/dev/null 2>&1; then
    UID_ZERO_ACCOUNTS=$(getent passwd 2>/dev/null | awk -F: '$3 == 0 && $1 != "root" {print $1}' | sed 's/[[:space:]]*$//')
    EVID_TARGET="getent_passwd"

# 2) getent 없으면 /etc/passwd로 점검
elif [ -f "$TARGET_FILE" ]; then
    UID_ZERO_ACCOUNTS=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' "$TARGET_FILE" 2>/dev/null | sed 's/[[:space:]]*$//')
    EVID_TARGET="$TARGET_FILE"

# 3) 둘 다 불가면 점검 불가
else
    UID_ZERO_ACCOUNTS=""
    EVID_TARGET="passwd_not_found"
fi

# 판정
if [ "$EVID_TARGET" = "passwd_not_found" ]; then
    STATUS="FAIL"
    REASON_LINE="사용자 계정 정보(/etc/passwd 또는 NSS passwd DB)를 확인할 수 없어 root 이외 UID=0 계정 존재 여부를 점검할 수 없으므로 취약합니다. passwd DB 또는 /etc/passwd를 복구/확인한 뒤 재점검해야 합니다."
    DETAIL_CONTENT="passwd_not_found"
else
    if [ -z "$UID_ZERO_ACCOUNTS" ]; then
        STATUS="PASS"
        REASON_LINE="root 이외 UID가 0인 계정이 존재하지 않아 관리자 권한 공유가 발생하지 않으므로 양호합니다."
        DETAIL_CONTENT="no_uid0_accounts_except_root"
    else
        STATUS="FAIL"
        REASON_LINE="root 이외 UID=0 계정이 존재하여 관리자 권한이 분산되고 권한 오남용 및 추적 곤란 위험이 있으므로 취약합니다. root 이외 UID=0 계정의 UID를 중복되지 않는 값으로 변경하거나 불필요한 계정은 제거해야 합니다."
        DETAIL_CONTENT="$(printf "%s\n" "$UID_ZERO_ACCOUNTS")"
    fi
fi

# raw_evidence 구성 (첫 줄: 평가 이유 / 다음 줄부터: 현재 설정값)
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

# scan_history 저장용 JSON 출력
echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF