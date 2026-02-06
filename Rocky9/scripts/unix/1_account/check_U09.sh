#!/bin/bash
# [점검] U-09 계정이 존재하지 않는 GID 금지

ID="U-09"
CATEGORY="계정관리"
TITLE="계정이 존재하지 않는 GID 금지"
IMPORTANCE="하"
GROUP_FILE="/etc/group"
PASSWD_FILE="/etc/passwd"

STATUS="PASS"
EVIDENCE="N/A"
UNUSED_GROUPS=()

if [ -f "$GROUP_FILE" ] && [ -f "$PASSWD_FILE" ]; then
    # 1. 파일 해시 추출
    FILE_HASH=$(sha256sum "$GROUP_FILE" | awk '{print $1}')
    
    # 2. 일반 사용자 GID 시작점 설정 (1000 이상)
    GID_MIN=1000 
    
    # 3. 그룹 전수 조사
    while IFS=: read -r GNAME GPASS GID GMEM; do
        if [[ "$GID" -ge "$GID_MIN" ]]; then
            # 해당 GID를 기본 그룹으로 쓰는 유저 확인
            USER_EXISTS=$(awk -F: -v gid="$GID" '$4 == gid {print $1}' "$PASSWD_FILE")
            
            # 유저도 없고 멤버 리스트도 비어있는 경우
            if [[ -z "$USER_EXISTS" && -z "$GMEM" ]]; then
                UNUSED_GROUPS+=("$GNAME($GID)")
            fi
        fi
    done < "$GROUP_FILE"

    # 4. 결과 판별
    if [ ${#UNUSED_GROUPS[@]} -gt 0 ]; then
        STATUS="FAIL"
        EVIDENCE="취약: 계정이 존재하지 않는 그룹 발견 (${UNUSED_GROUPS[*]})"
    else
        STATUS="PASS"
        EVIDENCE="양호: 모든 일반 그룹에 소속된 계정이 존재합니다."
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
    "file_hash": "$FILE_HASH",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF