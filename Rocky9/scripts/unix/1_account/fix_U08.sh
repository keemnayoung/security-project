#!/bin/bash
# [조치] U-08 관리자 그룹에 최소한의 계정 포함

ID="U-08"
TARGET_FILE="/etc/group"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
ACTION_RESULT="FAIL"
CURRENT_STATUS="FAIL"
ACTION_LOG="N/A"

# 1. 대상 확인 및 백업
if [ -f "$TARGET_FILE" ]; then
    cp -p "$TARGET_FILE" "${TARGET_FILE}_bak_$TIMESTAMP"
    
    # root 그룹 내 root 제외 계정 추출
    EXTRA_USERS=$(grep "^root:x:0:" "$TARGET_FILE" | cut -d: -f4 | tr ',' '\n' | grep -v "^root$" | grep -v "^$" | xargs)

    if [ -z "$EXTRA_USERS" ]; then
        ACTION_RESULT="SUCCESS"
        CURRENT_STATUS="PASS"
        ACTION_LOG="양호: 이미 root 그룹에 불필요한 계정이 없습니다."
    else
        # 2. 계정 제거 수행
        REMOVED_USERS=()
        for user in $EXTRA_USERS; do
            if gpasswd -d "$user" root >/dev/null 2>&1; then
                REMOVED_USERS+=("$user")
            fi
        done

        # 3. [핵심 검증] 조치 후 상태 재확인
        REMAIN_USERS=$(grep "^root:x:0:" "$TARGET_FILE" | cut -d: -f4 | tr ',' '\n' | grep -v "^root$" | grep -v "^$" | wc -l)
        
        if [ "$REMAIN_USERS" -eq 0 ]; then
            ACTION_RESULT="SUCCESS"
            CURRENT_STATUS="PASS"
            ACTION_LOG="성공: root 그룹에서 계정(${REMOVED_USERS[*]}) 제거 완료."
        else
            ACTION_RESULT="PARTIAL_SUCCESS"
            ACTION_LOG="주의: 일부 계정이 제거되지 않았습니다. 수동 확인이 필요합니다."
        fi
    fi
else
    ACTION_LOG="오류: 대상 파일($TARGET_FILE)이 없습니다."
fi

# 4. 표준 JSON 출력
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