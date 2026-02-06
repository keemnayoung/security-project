#!/bin/bash
# [진단] U-07 불필요한 계정 제거

ID="U-07"
CATEGORY="계정관리"
TITLE="불필요한 계정 제거"
IMPORTANCE="하"
TARGET_FILE="/etc/passwd"

# 점검 대상 기본 계정 목록 (가이드 참고)
DEFAULT_UNUSED_ACCOUNTS=("lp" "uucp" "nuucp")
FOUND_ACCOUNTS=()

# 1. 진단 로직
STATUS="PASS"
EVIDENCE="양호: 불필요한 계정이 존재하지 않습니다."

if [ -f "$TARGET_FILE" ]; then
    # 파일 해시 추출
    FILE_HASH=$(sha256sum "$TARGET_FILE" | awk '{print $1}')
    
    # 가이드 명시 기본 계정 존재 확인
    for acc in "${DEFAULT_UNUSED_ACCOUNTS[@]}"; do
        if grep -q "^${acc}:" "$TARGET_FILE"; then
            FOUND_ACCOUNTS+=("$acc")
        fi
    done

    # 결과 판별
    if [ ${#FOUND_ACCOUNTS[@]} -gt 0 ]; then
        STATUS="FAIL"
        EVIDENCE="취약: 불필요한 기본 계정 존재 (${FOUND_ACCOUNTS[*]})"
    fi
else
    STATUS="FAIL"
    EVIDENCE="오류: $TARGET_FILE 파일을 찾을 수 없습니다."
    FILE_HASH="NOT_FOUND"
fi

# 2. JSON 표준 출력
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
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF