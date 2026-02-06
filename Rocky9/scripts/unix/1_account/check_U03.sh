#!/bin/bash
# [진단] U-03 계정 잠금 임계값 설정

ID="U-03"
CATEGORY="계정관리"
TITLE="계정 잠금 임계값 설정"
IMPORTANCE="상"
TARGET_FILE="/etc/security/faillock.conf"

STATUS="FAIL"
EVIDENCE="N/A"

if [ -f "$TARGET_FILE" ]; then
    # deny 설정값 확인 (주석 제외)
    DENY_VAL=$(grep -E "^deny" $TARGET_FILE | awk -F'=' '{print $2}' | xargs)
    
    if [ -n "$DENY_VAL" ] && [ "$DENY_VAL" -le 10 ]; then
        STATUS="PASS"
        EVIDENCE="계정 잠금 임계값이 ${DENY_VAL}회로 설정되어 있음 (기준: 10회 이하)"
    else
        STATUS="FAIL"
        EVIDENCE="현재 설정값: ${DENY_VAL:-설정없음} (취약 - 10회 이하로 설정 필요)"
    fi
else
    STATUS="FAIL"
    EVIDENCE="설정 파일($TARGET_FILE)을 찾을 수 없음"
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