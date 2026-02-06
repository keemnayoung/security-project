#!/bin/bash
# [조치] U-09 계정이 존재하지 않는 GID 금지

ID="U-09"
GROUP_FILE="/etc/group"
PASSWD_FILE="/etc/passwd"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
ACTION_RESULT="FAIL"
CURRENT_STATUS="FAIL"
ACTION_LOG="N/A"

if [ -f "$GROUP_FILE" ]; then
    # 1. 백업 생성
    cp -p "$GROUP_FILE" "${GROUP_FILE}_bak_$TIMESTAMP"

    # 2. 삭제 대상 식별 및 처리
    GID_MIN=1000
    REMOVED_GROUPS=()
    
    while IFS=: read -r GNAME GPASS GID GMEM; do
        if [[ "$GID" -ge "$GID_MIN" ]]; then
            USER_EXISTS=$(awk -F: -v gid="$GID" '$4 == gid {print $1}' "$PASSWD_FILE")
            if [[ -z "$USER_EXISTS" && -z "$GMEM" ]]; then
                if groupdel "$GNAME" >/dev/null 2>&1; then
                    REMOVED_GROUPS+=("$GNAME")
                fi
            fi
        fi
    done < "$GROUP_FILE"

    # 3. 검증
    STILL_EXISTS=0
    while IFS=: read -r GNAME GPASS GID GMEM; do
        if [[ "$GID" -ge "$GID_MIN" ]]; then
            USER_EXISTS=$(awk -F: -v gid="$GID" '$4 == gid {print $1}' "$PASSWD_FILE")
            [[ -z "$USER_EXISTS" && -z "$GMEM" ]] && ((STILL_EXISTS++))
        fi
    done < "$GROUP_FILE"

    if [ "$STILL_EXISTS" -eq 0 ]; then
        ACTION_RESULT="SUCCESS"
        CURRENT_STATUS="PASS"
        if [ ${#REMOVED_GROUPS[@]} -gt 0 ]; then
            ACTION_LOG="성공: 불필요한 그룹(${REMOVED_GROUPS[*]}) 삭제 완료."
        else
            ACTION_LOG="양호: 삭제할 대상 그룹이 없습니다."
        fi
    else
        ACTION_RESULT="PARTIAL_SUCCESS"
        ACTION_LOG="주의: 일부 그룹 삭제에 실패했습니다."
    fi
else
    ACTION_LOG="오류: 대상 파일($GROUP_FILE)이 없습니다."
fi

echo ""
cat << EOF
{
    "check_id": "$ID",
    "status": "$CURRENT_STATUS",
    "action_result": "$ACTION_RESULT",
    "action_log": "$ACTION_LOG",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF