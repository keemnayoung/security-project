#!/bin/bash
# [진단] U-09 계정이 존재하지 않는 GID 금지

# 1. 항목 정보 정의
ID="U-09"
CATEGORY="계정관리"
TITLE="계정이 존재하지 않는 GID 금지"
IMPORTANCE="하"
GROUP_FILE="/etc/group"
PASSWD_FILE="/etc/passwd"

# 2. 진단 로직
STATUS="PASS"
EVIDENCE="N/A"
UNUSED_GROUPS=()

if [ -f "$GROUP_FILE" ] && [ -f "$PASSWD_FILE" ]; then
    # 파일 해시 추출
    FILE_HASH=$(sha256sum "$GROUP_FILE" | awk '{print $1}')
    
    # OS별 일반 사용자 GID 시작점 설정 (Ubuntu: 1000, Rocky: 1000 / 가이드는 보통 500 이상)
    GID_MIN=1000 
    
    # 500(또는 1000) 이상의 GID를 가진 그룹 리스트 추출
    mapfile -t CUSTOM_GROUPS < <(awk -F: -v min="$GID_MIN" '$3 >= min {print $1":"$3}' "$GROUP_FILE")

    for entry in "${CUSTOM_GROUPS[@]}"; do
        GNAME=$(echo "$entry" | cut -d: -f1)
        GID=$(echo "$entry" | cut -d: -f2)

        # 해당 GID를 기본 그룹으로 사용하는 유저가 있는지 확인
        USER_EXISTS=$(awk -F: -v gid="$GID" '$4 == gid {print $1}' "$PASSWD_FILE")
        
        # 그룹 멤버 리스트에 유저가 명시되어 있는지 확인
        MEMBER_EXISTS=$(grep "^$GNAME:" "$GROUP_FILE" | cut -d: -f4)

        if [ -z "$USER_EXISTS" ] && [ -z "$MEMBER_EXISTS" ]; then
            UNUSED_GROUPS+=("$GNAME($GID)")
        fi
    done

    if [ ${#UNUSED_GROUPS[@]} -gt 0 ]; then
        STATUS="FAIL"
        EVIDENCE="취약: 계정이 존재하지 않는 그룹 발견 (${UNUSED_GROUPS[*]})"
    else
        STATUS="PASS"
        EVIDENCE="양호: 모든 그룹에 소속된 계정이 존재합니다."
    fi
else
    STATUS="FAIL"
    EVIDENCE="오류: 설정 파일을 찾을 수 없습니다."
    FILE_HASH="NOT_FOUND"
fi

# 3. JSON 출력
echo ""
cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "/etc/group 파일과 /etc/passwd 파일을 비교하여 사용자가 없는 그룹은 groupdel로 삭제하세요.",
    "target_file": "$GROUP_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF