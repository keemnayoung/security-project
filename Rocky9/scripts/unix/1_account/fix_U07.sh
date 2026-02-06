#!/bin/bash
# [조치] U-01 root 계정 원격 접속 제한

ID="U-07"
TARGET_FILE="/etc/passwd"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"

# 삭제할 기본 불필요 계정 정의
UNUSED_ACCOUNTS=("lp" "uucp" "nuucp")

if [ -f "$TARGET_FILE" ]; then
    # 1. 백업 생성 (가장 중요)
    BACKUP_FILE="/etc/passwd_bak_$(date +%Y%m%d_%H%M%S)"
    cp -p "$TARGET_FILE" "$BACKUP_FILE"
    cp -p "/etc/shadow" "/etc/shadow_bak_$(date +%Y%m%d_%H%M%S)"

    # 2. 계정 삭제 수행
    REMOVED_LIST=()
    for acc in "${UNUSED_ACCOUNTS[@]}"; do
        if id "$acc" >/dev/null 2>&1; then
            # 계정 삭제 (홈디렉토리는 업무 영향도 파악 후 수동 삭제 권고하므로 계정만 삭제)
            if userdel "$acc" >/dev/null 2>&1; then
                REMOVED_LIST+=("$acc")
            fi
        fi
    done

    # 3. 조치 결과 확인
    if [ ${#REMOVED_LIST[@]} -gt 0 ]; then
        ACTION_RESULT="SUCCESS"
        ACTION_LOG="성공: 불필요한 계정(${REMOVED_LIST[*]}) 삭제 완료. 백업본: $BACKUP_FILE"
    else
        ACTION_RESULT="SUCCESS"
        ACTION_LOG="양호: 이미 삭제되었거나 대상 계정이 없습니다."
    fi
else
    ACTION_LOG="오류: 대상 파일($TARGET_FILE)이 없습니다."
fi

# 4. JSON 표준 출력
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