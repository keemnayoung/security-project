#!/bin/bash
# [점검] U-06 su 명령 사용 제한

ID="U-06"
CATEGORY="계정관리"
TITLE="su 명령 사용 제한"
IMPORTANCE="상"
TARGET_FILE="/etc/pam.d/su"

STATUS="FAIL"
EVIDENCE="N/A"

if [ -f "$TARGET_FILE" ]; then
    # 1. pam_wheel.so 설정이 주석 해제되어 활성화된 라인 확인
    # 현업 기준: auth required pam_wheel.so use_uid 형태가 표준
    CHECK_WHEEL=$(grep -v '^#' "$TARGET_FILE" | grep "pam_wheel.so" | grep "auth" | grep "required")
    
    if [ -n "$CHECK_WHEEL" ]; then
        STATUS="PASS"
        # 실제 설정된 라인을 근거로 제시
        EVIDENCE="양호: su 사용 제한 설정이 활성화됨 ($(echo $CHECK_WHEEL | xargs))"
    else
        STATUS="FAIL"
        EVIDENCE="취약: pam_wheel.so 설정이 비활성화되어 모든 사용자가 su 명령을 시도할 수 있음"
    fi
else
    STATUS="FAIL"
    EVIDENCE="취약: 설정 파일($TARGET_FILE)을 찾을 수 없음"
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
    "guide": "/etc/pam.d/su 파일에서 pam_wheel.so 설정의 주석을 제거하여 wheel 그룹으로 제한하세요.",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF