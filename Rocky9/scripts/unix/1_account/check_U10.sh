#!/bin/bash
# [진단] U-10 동일한 UID 금지

# 1. 항목 정보 정의
ID="U-10"
CATEGORY="계정관리"
TITLE="동일한 UID 금지"
IMPORTANCE="중"
TARGET_FILE="/etc/passwd"

# 2. 진단 로직
STATUS="PASS"
EVIDENCE="N/A"
DUPLICATE_UIDS=""

if [ -f "$TARGET_FILE" ]; then
    # 파일 해시 추출 (무결성 검증용)
    FILE_HASH=$(sha256sum "$TARGET_FILE" | awk '{print $1}')
    
    # UID만 추출하여 중복된 값 찾기
    # 예: "0, 1000, 1000" -> 중복된 "1000" 추출
    DUPS=$(cut -d: -f3 "$TARGET_FILE" | sort | uniq -d)

    if [ -z "$DUPS" ]; then
        STATUS="PASS"
        EVIDENCE="양호: 중복된 UID를 사용하는 계정이 존재하지 않습니다."
    else
        STATUS="FAIL"
        # 중복된 UID와 해당 계정명 매칭 추출
        for uid in $DUPS; do
            ACCOUNTS=$(awk -F: -v u="$uid" '$3 == u {print $1}' "$TARGET_FILE" | xargs | tr ' ' ',')
            DUPLICATE_UIDS+="$uid($ACCOUNTS) "
        done
        EVIDENCE="취약: 동일한 UID 발견 [$DUPLICATE_UIDS]"
    fi
else
    STATUS="FAIL"
    EVIDENCE="오류: $TARGET_FILE 파일을 찾을 수 없습니다."
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
    "guide": "/etc/passwd 파일을 확인하여 중복된 UID를 가진 계정의 UID를 usermod -u 명령으로 변경하세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF