#!/bin/bash
# [점검] U-10 동일한 UID 금지

ID="U-10"
CATEGORY="계정관리"
TITLE="동일한 UID 금지"
IMPORTANCE="중"
TARGET_FILE="/etc/passwd"

STATUS="PASS"
EVIDENCE="N/A"
DUPLICATE_INFO=""

if [ -f "$TARGET_FILE" ]; then
    # 1. 파일 해시 추출 (무결성 검증용)
    FILE_HASH=$(sha256sum "$TARGET_FILE" | awk '{print $1}')
    
    # 2. 중복된 UID 값 추출
    DUPS=$(cut -d: -f3 "$TARGET_FILE" | sort | n | uniq -d)

    if [ -z "$DUPS" ]; then
        STATUS="PASS"
        EVIDENCE="양호: 중복된 UID를 사용하는 계정이 존재하지 않습니다."
    else
        STATUS="FAIL"
        # 3. 중복 UID별 계정 매칭 상세화
        for uid in $DUPS; do
            ACCOUNTS=$(awk -F: -v u="$uid" '$3 == u {print $1}' "$TARGET_FILE" | xargs | sed 's/ /, /g')
            DUPLICATE_INFO+="UID $uid($ACCOUNTS); "
        done
        EVIDENCE="취약: 동일한 UID 발견 [${DUPLICATE_INFO%; }]"
    fi
else
    STATUS="FAIL"
    EVIDENCE="취약: 설정 파일($TARGET_FILE)을 찾을 수 없습니다."
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
    "guide": "/etc/passwd 파일을 확인하여 중복된 UID를 가진 계정의 UID를 수정하세요.",
    "file_hash": "$FILE_HASH",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF