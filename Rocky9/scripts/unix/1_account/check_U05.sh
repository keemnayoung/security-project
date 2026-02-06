#!/bin/bash
# [점검] U-05 UID가 0인 일반 계정 존재

ID="U-05"
CATEGORY="계정관리"
TITLE="UID가 0인 일반 계정 존재"
IMPORTANCE="상"
TARGET_FILE="/etc/passwd"

STATUS="PASS"
EVIDENCE="N/A"

if [ -f "$TARGET_FILE" ]; then
    # root 계정 외에 UID가 0인 계정 리스트 추출
    UID_ZERO_ACCOUNTS=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' "$TARGET_FILE" | xargs | sed 's/ /, /g')
    
    if [ -z "$UID_ZERO_ACCOUNTS" ]; then
        STATUS="PASS"
        EVIDENCE="양호: root 계정 외에 UID가 0인 계정이 존재하지 않습니다."
    else
        STATUS="FAIL"
        EVIDENCE="취약: UID가 0인 위험 계정 발견 ($UID_ZERO_ACCOUNTS)"
    fi
else
    STATUS="FAIL"
    EVIDENCE="취약: 설정 파일($TARGET_FILE)을 찾을 수 없습니다."
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
    "guide": "root 이외의 계정 중 UID가 0인 계정의 UID를 1000 이상의 번호로 변경하세요.",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF