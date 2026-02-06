#!/bin/bash
# [점검] U-13 안전한 비밀번호 암호화 알고리즘 사용

ID="U-13"
CATEGORY="계정관리"
TITLE="안전한 비밀번호 암호화 알고리즘 사용"
IMPORTANCE="중"
DEFS_FILE="/etc/login.defs"
SHADOW_FILE="/etc/shadow"

STATUS="PASS"
EVIDENCE="N/A"

if [ -f "$DEFS_FILE" ] && [ -f "$SHADOW_FILE" ]; then
    # 1. 파일 해시 추출
    FILE_HASH=$(sha256sum "$DEFS_FILE" | awk '{print $1}')
    
    # 2. /etc/login.defs 설정 확인
    ENCRYPT_METHOD=$(grep -i "^ENCRYPT_METHOD" "$DEFS_FILE" | awk '{print $2}')
    
    # 3. [검증 강화] /etc/shadow에서 실제 사용 중인 알고리즘 식별자 확인 ($6$ = SHA-512)
    # 암호가 설정된 계정 중 SHA-512가 아닌 계정이 있는지 확인
    INVALID_ALGO_ACCOUNTS=$(awk -F: '$2 ~ /^\$/ && $2 !~ /^\$6\$/ {print $1}' "$SHADOW_FILE" | xargs | sed 's/ /, /g')
    
    if [[ "$ENCRYPT_METHOD" =~ "SHA512" ]]; then
        if [ -z "$INVALID_ALGO_ACCOUNTS" ]; then
            STATUS="PASS"
            EVIDENCE="양호: ENCRYPT_METHOD가 SHA512이며, 모든 계정이 안전한 알고리즘을 사용 중입니다."
        else
            STATUS="FAIL"
            EVIDENCE="취약: 설정은 SHA512이나, 기존 일부 계정이 취약한 알고리즘 사용 중 ($INVALID_ALGO_ACCOUNTS)"
        fi
    else
        STATUS="FAIL"
        EVIDENCE="취약: 취약한 암호화 알고리즘 정의됨 (현재 설정: $ENCRYPT_METHOD)"
    fi
else
    STATUS="FAIL"
    EVIDENCE="취약: 필수 설정 파일이 누락되었습니다."
    FILE_HASH="NOT_FOUND"
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
    "guide": "/etc/login.defs 파일에서 ENCRYPT_METHOD를 SHA512로 설정하세요.",
    "file_hash": "$FILE_HASH",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF