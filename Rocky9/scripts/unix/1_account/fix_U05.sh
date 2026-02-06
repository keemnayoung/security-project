#!/bin/bash
# [조치] U-05 UID가 0인 일반 계정 존재

ID="U-05"
TARGET_FILE="/etc/passwd"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
ACTION_RESULT="FAIL"
CURRENT_STATUS="FAIL"
ACTION_LOG="N/A"

# 1. 대상 계정 확인
EXTRA_ROOT=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' "$TARGET_FILE")

if [ -z "$EXTRA_ROOT" ]; then
    ACTION_RESULT="SUCCESS"
    CURRENT_STATUS="PASS"
    ACTION_LOG="조치 대상 계정이 없습니다."
else
    # 2. 백업 생성
    cp -p "$TARGET_FILE" "${TARGET_FILE}_bak_$TIMESTAMP"

    # 3. 조치 로직 수행 (UID 변경)
    LOG_MSG=""
    
    # 2000번부터 사용 중이지 않은 UID 찾기 함수
    get_unused_uid() {
        local uid=2000
        while getent passwd "$uid" >/dev/null; do
            ((uid++))
        done
        echo "$uid"
    }

    for user in $EXTRA_ROOT; do
        NEW_UID=$(get_unused_uid)
        if usermod -u "$NEW_UID" "$user" >/dev/null 2>&1; then
            LOG_MSG+="${user}(UID 0 -> $NEW_UID) 변경 완료; "
        else
            LOG_MSG+="${user} 변경 실패; "
        fi
    done

    # 4. [핵심 검증] 조치 후 실제 파일에서 UID 0인 일반 계정이 남았는지 확인
    REMAIN_COUNT=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' "$TARGET_FILE" | wc -l)
    
    if [ "$REMAIN_COUNT" -eq 0 ]; then
        ACTION_RESULT="SUCCESS"
        CURRENT_STATUS="PASS"
        ACTION_LOG="성공: 모든 위험 계정의 UID가 변경되었습니다. (${LOG_MSG%; })"
    else
        ACTION_RESULT="PARTIAL_SUCCESS"
        CURRENT_STATUS="FAIL"
        ACTION_LOG="일부 계정의 UID 변경에 실패했습니다. (${LOG_MSG%; })"
    fi
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