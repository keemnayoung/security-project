#!/bin/bash
# [점검] U-03 계정 잠금 임계값 설정

ID="U-03"
CATEGORY="계정관리"
TITLE="계정 잠금 임계값 설정"
IMPORTANCE="상"
TARGET_FILE="/etc/security/faillock.conf"

STATUS="FAIL"
EVIDENCE="N/A"

if [ -f "$TARGET_FILE" ]; then
    # deny 설정값 확인 (주석 제외, 공백 제거 후 숫자만 추출)
    DENY_VAL=$(grep -iv '^#' "$TARGET_FILE" | grep -w "deny" | sed 's/ //g' | cut -d'=' -f2 | tail -n 1)
    
    # 10회 이하인 경우 '양호' 판정 && [ \"$DENY_VAL\" -le 10 ]; then STATUS=\"PASS\""]
    if [ -n "$DENY_VAL" ] && [ "$DENY_VAL" -le 10 ] && [ "$DENY_VAL" -gt 0 ]; then
        STATUS="PASS"
        EVIDENCE="양호: 계정 잠금 임계값이 ${DENY_VAL}회로 설정되어 있음 (기준: 10회 이하)"
    else
        STATUS="FAIL"
        EVIDENCE="취약: 현재 설정값(${DENY_VAL:-설정없음})이 기준(10회 이하)을 만족하지 않음"
    fi
else
    # 파일이 없는 경우도 취약으로 간주
    STATUS="FAIL"
    EVIDENCE="취약: 설정 파일($TARGET_FILE)이 존재하지 않음"
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
    "guide": "faillock.conf 파일에서 deny=10 이하로 설정하고 unlock_time을 지정하세요.",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF