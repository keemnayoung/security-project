#!/bin/bash
# [조치] U-09 계정이 존재하지 않는 GID 금지

ID="U-09"
GROUP_FILE="/etc/group"
PASSWD_FILE="/etc/passwd"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"

if [ -f "$GROUP_FILE" ]; then
    # 1. 백업 생성
    BACKUP_FILE="${GROUP_FILE}_bak_$(date +%Y%m%d_%H%M%S)"
    cp -p "$GROUP_FILE" "$BACKUP_FILE"

    # 2. 삭제 대상 식별 (진단 로직과 동일)
    GID_MIN=1000
    REMOVED_GROUPS=()
    
    mapfile -t CUSTOM_GROUPS < <(awk -F: -v min="$GID_MIN" '$3 >= min {print $1":"$3}' "$GROUP_FILE")

    for entry in "${CUSTOM_GROUPS[@]}"; do
        GNAME=$(echo "$entry" | cut -d: -f1)
        GID=$(echo "$entry" | cut -d: -f2)

        USER_EXISTS=$(awk -F: -v gid="$GID" '$4 == gid {print $1}' "$PASSWD_FILE")
        MEMBER_EXISTS=$(grep "^$GNAME:" "$GROUP_FILE" | cut -d: -f4)

        if [ -z "$USER_EXISTS" ] && [ -z "$MEMBER_EXISTS" ]; then
            # 3. 그룹 삭제 실행
            if groupdel "$GNAME" >/dev/null 2>&1; then
                REMOVED_GROUPS+=("$GNAME")
            fi
        fi
    done

    if [ ${#REMOVED_GROUPS[@]} -gt 0 ]; then
        ACTION_RESULT="SUCCESS"
        ACTION_LOG="성공: 불필요한 그룹(${REMOVED_USERS[*]}) 삭제 완료. 백업: $BACKUP_FILE"
    else
        ACTION_RESULT="SUCCESS"
        ACTION_LOG="양호: 삭제할 대상 그룹이 없습니다."
    fi
else
    ACTION_LOG="오류: 대상 파일($GROUP_FILE)이 없습니다."
fi

# 4. JSON 출력
echo ""
cat << EOF
{
    "check_id": "$ID",
    "action_type": "auto",
    "action_result": "$ACTION_RESULT",
    "action_log": "$ACTION_LOG",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF