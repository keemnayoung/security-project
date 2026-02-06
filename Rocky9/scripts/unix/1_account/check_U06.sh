#!/bin/bash
# [진단] U-06 su 명령 사용 제한

ID="U-06"
CATEGORY="계정관리"
TITLE="su 명령 사용 제한"
IMPORTANCE="상"
TARGET_FILE="/etc/pam.d/su"

STATUS="FAIL"
EVIDENCE="N/A"

if [ -f "$TARGET_FILE" ]; then
    # pam_wheel.so 설정이 주석 해제되어 있는지 확인
    CHECK_WHEEL=$(grep "pam_wheel.so" "$TARGET_FILE" | grep "auth" | grep -v "^#")
    
    if [ -n "$CHECK_WHEEL" ]; then
        STATUS="PASS"
        EVIDENCE="su 명령어 사용이 wheel 그룹으로 제한되어 있습니다."
    else
        STATUS="FAIL"
        EVIDENCE="모든 사용자가 su 명령어를 사용할 수 있는 상태입니다."
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
    "guide": "/etc/pam.d/su 파일에서 pam_wheel.so 설정의 주석을 제거하세요.",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF