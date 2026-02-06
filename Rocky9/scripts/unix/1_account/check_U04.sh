#!/bin/bash
# [진단] U-04 비밀번호 파일 보호

ID="U-04"
CATEGORY="계정관리"
TITLE="비밀번호 파일 보호"
IMPORTANCE="상"
TARGET_FILE="/etc/passwd"

STATUS="FAIL"
EVIDENCE="N/A"

if [ -f "$TARGET_FILE" ]; then
    # /etc/passwd 내 두 번째 필드가 x가 아닌 계정이 있는지 확인
    UNSHADOWED_COUNT=$(awk -F: '$2 != "x" {print $1}' $TARGET_FILE | wc -l)
    
    if [ "$UNSHADOWED_COUNT" -eq 0 ]; then
        STATUS="PASS"
        EVIDENCE="모든 계정이 쉐도우 패스워드(x)를 사용하여 암호화 보호 중입니다."
    else
        STATUS="FAIL"
        EVIDENCE="암호화되지 않은 계정 발견: ${UNSHADOWED_COUNT}건 (쉐도우 패스워드 미사용)"
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
    "guide": "pwconv 명령어를 실행하여 쉐도우 패스워드 정책을 적용하세요.",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF