#!/bin/bash
# [조치] U-10 동일한 UID 금지

ID="U-10"
TARGET_FILE="/etc/passwd"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
ACTION_RESULT="FAIL"
CURRENT_STATUS="FAIL"
ACTION_LOG="N/A"

if [ -f "$TARGET_FILE" ]; then
    # 1. 백업 생성 (조치 전 필수)
    cp -p "$TARGET_FILE" "${TARGET_FILE}_bak_$TIMESTAMP"

    # 2. 중복 상황 파악
    DUPS=$(cut -d: -f3 "$TARGET_FILE" | sort | n | uniq -d)
    
    if [ -z "$DUPS" ]; then
        ACTION_RESULT="SUCCESS"
        CURRENT_STATUS="PASS"
        ACTION_LOG="양호: 중복된 UID가 없어 조치가 필요하지 않습니다."
    else
        REPORT=""
        for uid in $DUPS; do
            ACCOUNTS=$(awk -F: -v u="$uid" '$3 == u {print $1}' "$TARGET_FILE" | xargs | sed 's/ /, /g')
            REPORT+="UID $uid($ACCOUNTS) "
        done

        # 3. 조치 가이드 제공 (영향도 고려하여 수동 조치 권고)
        ACTION_RESULT="MANUAL_REQUIRED"
        ACTION_LOG="수동 조치 필요: 중복 UID 발견($REPORT). usermod -u 명령으로 UID 수정이 필요합니다."
    fi
else
    ACTION_LOG="오류: 대상 파일($TARGET_FILE)이 없습니다."
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