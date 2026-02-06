#!/bin/bash
# [점검] U-07 불필요한 계정 제거

ID="U-07"
CATEGORY="계정관리"
TITLE="불필요한 계정 제거"
IMPORTANCE="하"
TARGET_FILE="/etc/passwd"

# KISA 가이드 및 현업 표준 불필요 계정 목록
DEFAULT_UNUSED_ACCOUNTS=("lp" "uucp" "nuucp")
FOUND_ACCOUNTS=()

STATUS="PASS"
EVIDENCE="양호: 불필요한 계정이 존재하지 않습니다."

if [ -f "$TARGET_FILE" ]; then
    # 1. 파일 무결성을 위한 해시 추출
    FILE_HASH=$(sha256sum "$TARGET_FILE" | awk '{print $1}')
    
    # 2. 불필요 계정 존재 여부 전수 조사
    for acc in "${DEFAULT_UNUSED_ACCOUNTS[@]}"; do
        if grep -q "^${acc}:" "$TARGET_FILE"; then
            FOUND_ACCOUNTS+=("$acc")
        fi
    done

    # 3. 결과 판별
    if [ ${#FOUND_ACCOUNTS[@]} -gt 0 ]; then
        STATUS="FAIL"
        EVIDENCE="취약: 불필요한 기본 계정 존재 (${FOUND_ACCOUNTS[*]})"
    fi
else
    STATUS="FAIL"
    EVIDENCE="취약: $TARGET_FILE 파일을 찾을 수 없습니다."
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
    "guide": "/etc/passwd에서 lp, uucp 등 사용하지 않는 계정을 userdel로 삭제하세요.",
    "file_hash": "$FILE_HASH",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF