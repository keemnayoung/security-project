#!/bin/bash
# [점검] U-02 패스워드 복잡성 설정

ID="U-02"
CATEGORY="계정관리"
TITLE="패스워드 복잡성 및 유효기간 설정"
IMPORTANCE="상"
PW_CONF="/etc/security/pwquality.conf"
LOGIN_DEFS="/etc/login.defs"

STATUS="PASS"
EVIDENCE_LIST=()

# 1. pwquality.conf 체크 함수 (공백 및 주석 처리 강화)
check_pwq() {
    local param=$1
    local expected=$2
    # 주석 제외, 정확한 파라미터 매칭 후 값 추출
    local val=$(grep -iv '^#' "$PW_CONF" | grep -w "${param}" | sed 's/ //g' | cut -d'=' -f2 | tail -n 1)
    
    if [ -z "$val" ] || [ "$val" -lt "$expected" ]; then
        STATUS="FAIL"
        EVIDENCE_LIST+=("${param} 미흡(현재:${val:-기본값}, 기준:${expected})")
    fi
}

if [ -f "$PW_CONF" ]; then
    check_pwq "minlen" 8
    check_pwq "minclass" 3
else
    STATUS="FAIL"; EVIDENCE_LIST+=("pwquality.conf 파일 없음")
fi

# 2. login.defs 유효기간 체크 (주석 제외하고 정확히 매칭)
MAX_DAYS=$(grep "^PASS_MAX_DAYS" "$LOGIN_DEFS" | awk '{print $2}' | tail -n 1)
if [ -z "$MAX_DAYS" ] || [ "$MAX_DAYS" -gt 90 ]; then
    STATUS="FAIL"
    EVIDENCE_LIST+=("유효기간 초과(현재:${MAX_DAYS:-기본값}, 기준:90일)")
fi

# 최종 결과 정리
if [ "$STATUS" == "PASS" ]; then
    EVIDENCE="양호: KISA 권고 복잡성 및 유효기간 기준을 모두 충족합니다."
else
    EVIDENCE=$(printf "; %s" "${EVIDENCE_LIST[@]}")
    EVIDENCE=${EVIDENCE#; }
fi

echo ""
cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "pwquality.conf(minlen=8, minclass=3) 및 login.defs(PASS_MAX_DAYS=90) 설정을 적용하세요.",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF