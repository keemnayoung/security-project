#!/bin/bash
# [진단] U-05 UID가 0인 일반 계정 존재

ID="U-05"
CATEGORY="계정관리"
TITLE="UID가 0인 일반 계정 존재"
IMPORTANCE="상"
TARGET_FILE="/etc/passwd"

STATUS="FAIL"
EVIDENCE="N/A"

if [ -f "$TARGET_FILE" ]; then
    # root 계정 외에 UID가 0인 계정 리스트 추출 (세 번째 필드가 0)
    UID_ZERO_ACCOUNTS=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' $TARGET_FILE)
    
    if [ -z "$UID_ZERO_ACCOUNTS" ]; then
        STATUS="PASS"
        EVIDENCE="root 계정 외에 UID가 0인 계정이 존재하지 않습니다."
    else
        STATUS="FAIL"
        EVIDENCE="UID가 0인 위험 계정 발견: $(echo $UID_ZERO_ACCOUNTS | xargs)"
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
    "guide": "root 이외의 계정 중 UID가 0인 계정의 UID를 500(또는 1000) 이상의 번호로 변경하세요.",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF