#!/bin/bash
# [진단] U-02 패스워드 복잡성 설정 (KISA 권고안 준수)

ID="U-02"
CATEGORY="계정관리"
TITLE="패스워드 복잡성 및 유효기간 설정"
IMPORTANCE="상"
PW_CONF="/etc/security/pwquality.conf"
LOGIN_DEFS="/etc/login.defs"

STATUS="PASS"
EVIDENCE_LIST=()

# 1. 길이 및 복잡성 체크 (pwquality.conf)
check_pwq() {
    local param=$1
    local expected=$2
    local val=$(grep -E "^${param}" $PW_CONF | awk -F'=' '{print $2}' | xargs)
    if [ -z "$val" ] || [ "$val" -lt "$expected" ]; then
        STATUS="FAIL"
        EVIDENCE_LIST+=("${param} 미흡(현재:${val:-기본값}, 기준:${expected})")
    fi
}

# 핵심 4종 체크 (길이 8, 영문/숫자/특수문자 등 종류 3가지 이상)
if [ -f "$PW_CONF" ]; then
    check_pwq "minlen" 8
    check_pwq "minclass" 3
else
    STATUS="FAIL"; EVIDENCE_LIST+=("pwquality.conf 파일 없음")
fi

# 2. 유효기간 체크 (login.defs)
MAX_DAYS=$(grep "^PASS_MAX_DAYS" $LOGIN_DEFS | awk '{print $2}')
if [ "$MAX_DAYS" -gt 90 ]; then
    STATUS="FAIL"
    EVIDENCE_LIST+=("유효기간 초과(현재:${MAX_DAYS}일, 기준:90일)")
fi

[ "$STATUS" == "PASS" ] && EVIDENCE="KISA 권고 복잡성 및 유효기간 기준을 모두 충족합니다." || EVIDENCE=$(printf "; %s" "${EVIDENCE_LIST[@]}")

echo ""
cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "${EVIDENCE#; }",
    "guide": "pwquality.conf(minlen=8, minclass=3) 및 login.defs(PASS_MAX_DAYS=90) 설정을 적용하세요.",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF