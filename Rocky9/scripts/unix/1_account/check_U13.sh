#!/bin/bash
# [진단] U-13 안전한 비밀번호 암호화 알고리즘 사용

# 1. 항목 정보 정의
ID="U-13"
CATEGORY="계정관리"
TITLE="안전한 비밀번호 암호화 알고리즘 사용"
IMPORTANCE="중"
DEFS_FILE="/etc/login.defs"
SHADOW_FILE="/etc/shadow"

# 2. 진단 로직
STATUS="PASS"
EVIDENCE="N/A"

if [ -f "$DEFS_FILE" ] && [ -f "$SHADOW_FILE" ]; then
    # 파일 해시 추출
    FILE_HASH=$(sha256sum "$DEFS_FILE" | awk '{print $1}')
    
    # 1. /etc/login.defs 설정 확인
    ENCRYPT_METHOD=$(grep -i "^ENCRYPT_METHOD" "$DEFS_FILE" | awk '{print $2}')
    
    # 2. /etc/shadow에서 실제 사용 중인 알고리즘 확인 ($6=SHA-512, $5=SHA-256)
    # 일반 사용자(UID 1000 이상) 중 하나를 샘플링하여 확인
    SAMPLE_HASH=$(awk -F: '$2 ~ /^\$/ {print $2}' "$SHADOW_FILE" | head -1)
    
    if [[ "$ENCRYPT_METHOD" =~ "SHA512" || "$ENCRYPT_METHOD" =~ "SHA256" ]]; then
        STATUS="PASS"
        EVIDENCE="양호: 설정 파일에 안전한 알고리즘($ENCRYPT_METHOD)이 정의되어 있습니다."
    else
        STATUS="FAIL"
        EVIDENCE="취약: 취약한 암호화 알고리즘 사용 중 (현재 설정: $ENCRYPT_METHOD)"
    fi
else
    STATUS="FAIL"
    EVIDENCE="오류: 설정 파일을 찾을 수 없습니다."
    FILE_HASH="NOT_FOUND"
fi

# 3. JSON 표준 출력
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
    "target_file": "$DEFS_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF