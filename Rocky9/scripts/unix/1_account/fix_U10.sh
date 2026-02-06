#!/bin/bash
# [수동 조치] U-10 동일한 UID 금지

ID="U-10"
TARGET_FILE="/etc/passwd"
ACTION_RESULT="CANCELLED"
ACTION_LOG="사용자에 의해 조치가 취소되었습니다."

# 1. 중복 UID 식별 및 리포팅
if [ -f "$TARGET_FILE" ]; then
    DUPS=$(cut -d: -f3 "$TARGET_FILE" | sort | uniq -d)
    
    if [ -z "$DUPS" ]; then
        ACTION_RESULT="SUCCESS"
        ACTION_LOG="양호: 중복된 UID가 없어 조치가 필요하지 않습니다."
        echo ""
        cat << EOF
{
    "check_id": "$ID",
    "action_result": "$ACTION_RESULT",
    "action_log": "$ACTION_LOG",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
        exit 0
    fi
else
    ACTION_RESULT="ERROR"
    ACTION_LOG="대상 파일($TARGET_FILE)이 없습니다."
    exit 1
fi

# 중복된 계정 정보 추출
REPORT=""
for uid in $DUPS; do
    ACCOUNTS=$(awk -F: -v u="$uid" '$3 == u {print $1}' "$TARGET_FILE" | xargs | tr ' ' ',')
    REPORT+="UID $uid($ACCOUNTS) "
done

echo "----------------------------------------------------------------------"
echo "[주의] 시스템 내 중복된 UID가 발견되었습니다."
echo "발견 리스트: $REPORT"
echo "UID 변경 시 해당 계정이 소유한 파일들에 대한 접근 권한 문제가 발생할 수 있습니다."
echo "----------------------------------------------------------------------"
read -p "관리자가 직접 확인 후 UID를 수정하시겠습니까? (y/n): " CONFIRM

if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
    echo ""
    cat << EOF
{
    "check_id": "$ID",
    "action_result": "$ACTION_RESULT",
    "action_log": "$ACTION_LOG",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
    exit 0
fi

# 2. 백업 생성 (수동 조치 전 필수)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${TARGET_FILE}_bak_$TIMESTAMP"
cp -p "$TARGET_FILE" "$BACKUP_FILE"

# 3. 조치 가이드 및 상태 반환
# UID 변경은 영향도가 너무 크므로 usermod 명령 가이드를 제공하며 수동 확인을 유도함
ACTION_RESULT="MANUAL_REQUIRED"
ACTION_LOG="수동 조치 대기: 중복 UID 발견($REPORT). usermod -u 명령으로 UID 수정이 필요합니다. 백업: $BACKUP_FILE"

# 4. JSON 표준 출력
echo ""
cat << EOF
{
    "check_id": "$ID",
    "action_type": "manual",
    "action_result": "$ACTION_RESULT",
    "action_log": "$ACTION_LOG",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF