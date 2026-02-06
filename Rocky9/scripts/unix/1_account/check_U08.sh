#!/bin/bash
# [점검] U-08 관리자 그룹에 최소한의 계정 포함

ID="U-08"
CATEGORY="계정관리"
TITLE="관리자 그룹에 최소한의 계정 포함"
IMPORTANCE="중"
TARGET_FILE="/etc/group"

STATUS="PASS"
EVIDENCE="N/A"

if [ -f "$TARGET_FILE" ]; then
    # 1. 파일 해시 추출 (무결성 검증용)
    FILE_HASH=$(sha256sum "$TARGET_FILE" | awk '{print $1}')
    
    # 2. root 그룹(GID 0)에 속한 사용자 리스트 추출
    ROOT_GROUP_USERS=$(grep "^root:x:0:" "$TARGET_FILE" | cut -d: -f4)
    
    # root를 제외한 불필요한 계정 필터링
    EXTRA_USERS=$(echo "$ROOT_GROUP_USERS" | tr ',' '\n' | grep -v "^root$" | grep -v "^$" | xargs | tr ' ' ',')

    if [ -z "$EXTRA_USERS" ]; then
        STATUS="PASS"
        EVIDENCE="양호: 관리자 그룹에 root 계정만 존재합니다."
    else
        STATUS="FAIL"
        EVIDENCE="취약: 관리자 그룹에 불필요한 계정 존재 ($EXTRA_USERS)"
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
    "guide": "/etc/group 파일에서 root 그룹에 등록된 불필요한 일반 계정을 제거하세요.",
    "file_hash": "$FILE_HASH",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF