#!/bin/bash
# [조치] U-07 불필요한 계정 제거

ID="U-07"
TARGET_FILE="/etc/passwd"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
ACTION_RESULT="FAIL"
CURRENT_STATUS="FAIL"
ACTION_LOG="N/A"

# 삭제 대상 정의
UNUSED_ACCOUNTS=("lp" "uucp" "nuucp")

if [ -f "$TARGET_FILE" ]; then
    # 1. 안전한 복구를 위한 백업 생성
    cp -p "$TARGET_FILE" "/etc/passwd_bak_$TIMESTAMP"
    [ -f "/etc/shadow" ] && cp -p "/etc/shadow" "/etc/shadow_bak_$TIMESTAMP"

    # 2. 계정 삭제 수행
    REMOVED_LIST=()
    for acc in "${UNUSED_ACCOUNTS[@]}"; do
        if id "$acc" >/dev/null 2>&1; then
            # 홈 디렉토리는 남겨두고 계정만 삭제 (현업 안정성 기준)
            if userdel "$acc" >/dev/null 2>&1; then
                REMOVED_LIST+=("$acc")
            fi
        fi
    done

    # 3. [핵심 검증] 조치 후 실제 계정이 남아있는지 재검사
    STILL_EXISTS=0
    for acc in "${UNUSED_ACCOUNTS[@]}"; do
        if grep -q "^${acc}:" "$TARGET_FILE"; then
            STILL_EXISTS=$((STILL_EXISTS + 1))
        fi
    done

    # 4. 결과 판정
    if [ "$STILL_EXISTS" -eq 0 ]; then
        ACTION_RESULT="SUCCESS"
        CURRENT_STATUS="PASS"
        if [ ${#REMOVED_LIST[@]} -gt 0 ]; then
            ACTION_LOG="성공: 불필요한 계정(${REMOVED_LIST[*]}) 삭제 완료 및 검증 성공."
        else
            ACTION_LOG="양호: 삭제 대상 계정이 이미 존재하지 않습니다."
        fi
    else
        ACTION_RESULT="PARTIAL_SUCCESS"
        ACTION_LOG="주의: 일부 계정이 삭제되지 않았습니다. 수동 확인이 필요합니다."
    fi
else
    ACTION_LOG="오류: 대상 파일($TARGET_FILE)이 없습니다."
fi

# 5. 표준 JSON 출력
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