#!/bin/bash
# [점검] U-04 비밀번호 파일 보호

ID="U-04"
CATEGORY="계정관리"
TITLE="비밀번호 파일 보호"
IMPORTANCE="상"
PASSWD_FILE="/etc/passwd"
SHADOW_FILE="/etc/shadow"

STATUS="PASS"
EVIDENCE="N/A"

# 1. /etc/passwd 내 두 번째 필드가 'x'가 아닌 계정 추출
UNSHADOWED_USERS=$(awk -F: '$2 != "x" {print $1}' "$PASSWD_FILE" | xargs | sed 's/ /, /g')

if [ -f "$PASSWD_FILE" ] && [ -f "$SHADOW_FILE" ]; then
    if [ -z "$UNSHADOWED_USERS" ]; then
        STATUS="PASS"
        EVIDENCE="양호: 모든 계정이 쉐도우 패스워드(x)를 사용하여 암호화 보호 중입니다."
    else
        STATUS="FAIL"
        EVIDENCE="취약: 암호화되지 않은 계정 발견 ($UNSHADOWED_USERS)"
    fi
else
    STATUS="FAIL"
    EVIDENCE="취약: 필수 파일($PASSWD_FILE 또는 $SHADOW_FILE)이 누락되었습니다."
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