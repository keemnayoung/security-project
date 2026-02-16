#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.0
# @Author: 김나영
# @Last Updated: 2026-02-13
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-04
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 비밀번호 파일 보호
# @Description : /etc/passwd 파일의 패스워드 암호화 및 /etc/shadow 파일 사용 여부 점검
# @Criteria_Good : 상용 시스템에서 쉐도우 패스워드 정책을 사용하는 경우
# @Criteria_Bad : 쉐도우 패스워드 정책을 사용하지 않고 패스워드가 노출되는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-04"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

PASSWD_FILE="/etc/passwd"
SHADOW_FILE="/etc/shadow"
TARGET_FILE="$PASSWD_FILE $SHADOW_FILE"

# 가이드 핵심: /etc/passwd에 비밀번호(평문/해시)가 저장되지 않고, shadow로 분리(x)되어 있는지 확인
# - passwd 2필드가 'x'면 정상(쉐도우 사용)
# - passwd 2필드가 '!' 또는 '*' 계열이면 잠금/비밀번호 미사용(평문/해시 저장 아님) → 취약으로 보지 않음(오탐 방지)
# - 그 외 값이면 passwd에 비밀번호(평문/해시)가 남아있을 가능성 → 취약
CHECK_COMMAND='[ -f /etc/passwd ] && awk -F: '\''$2 != "x" && $2 !~ /^(\!|\*)+$/ {print $1 ":" $2}'\'' /etc/passwd || echo "passwd_not_found"; [ -f /etc/shadow ] && echo "shadow_exists" || echo "shadow_not_found"'

REASON_LINE=""
DETAIL_CONTENT=""

UNSHADOWED_USERS=""

# 파일 존재 여부에 따른 분기
if [ -f "$PASSWD_FILE" ] && [ -f "$SHADOW_FILE" ]; then
    # /etc/passwd 내 두 번째 필드가 'x'가 아니면서, '!','*' (잠금/미사용) 계열이 아닌 계정만 추출
    UNSHADOWED_USERS=$(awk -F: '$2 != "x" && $2 !~ /^(\!|\*)+$/ {print $1 ":" $2}' "$PASSWD_FILE" 2>/dev/null)

    if [ -z "$UNSHADOWED_USERS" ]; then
        STATUS="PASS"
        REASON_LINE="/etc/passwd의 두 번째 필드가 모든 계정에서 'x'(쉐도우)로 설정되어 있거나, 잠금/비밀번호 미사용('!','*') 상태로 저장되어 /etc/passwd에 비밀번호(평문/해시)가 노출되지 않으므로 양호합니다."
        DETAIL_CONTENT="all_users_shadowed_or_locked"
    else
        STATUS="FAIL"
        REASON_LINE="/etc/passwd의 두 번째 필드에 'x'가 아닌 값(잠금/미사용 '!','*' 제외)이 존재하여 비밀번호(평문/해시)가 /etc/passwd에 저장되었을 가능성이 있으므로 취약합니다. pwconv 등을 통해 쉐도우 패스워드 정책을 적용해야 합니다."
        DETAIL_CONTENT="$UNSHADOWED_USERS"
    fi
else
    STATUS="FAIL"
    if [ ! -f "$PASSWD_FILE" ] && [ ! -f "$SHADOW_FILE" ]; then
        REASON_LINE="비밀번호 관련 필수 파일(/etc/passwd, /etc/shadow)이 모두 존재하지 않아 쉐도우 패스워드 적용 여부를 확인할 수 없으므로 취약합니다."
        DETAIL_CONTENT="passwd_not_found\nshadow_not_found"
    elif [ ! -f "$PASSWD_FILE" ]; then
        REASON_LINE="비밀번호 관련 필수 파일(/etc/passwd)이 존재하지 않아 계정 정보 및 쉐도우 정책 적용 여부를 확인할 수 없으므로 취약합니다."
        DETAIL_CONTENT="passwd_not_found\nshadow_exists"
    else
        REASON_LINE="비밀번호 관련 필수 파일(/etc/shadow)이 존재하지 않아 비밀번호 해시 분리 저장(쉐도우) 정책이 적용되지 않을 수 있으므로 취약합니다."
        DETAIL_CONTENT="passwd_exists\nshadow_not_found"
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