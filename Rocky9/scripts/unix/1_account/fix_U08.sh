#!/bin/bash
# [수동 조치] U-08 관리자 그룹에 최소한의 계정 포함

ID="U-08"
TARGET_FILE="/etc/group"
ACTION_RESULT="CANCELLED"
ACTION_LOG="사용자에 의해 조치가 취소되었습니다."

# 1. 관리자 위험 고지 및 대상 리포팅
if [ -f "$TARGET_FILE" ]; then
    ROOT_GROUP_USERS=$(grep "^root:x:0:" "$TARGET_FILE" | cut -d: -f4)
    EXTRA_USERS=$(echo "$ROOT_GROUP_USERS" | tr ',' '\n' | grep -v "^root$" | grep -v "^$" | xargs)

    if [ -z "$EXTRA_USERS" ]; then
        ACTION_RESULT="SUCCESS"
        ACTION_LOG="양호: root 그룹에 불필요한 계정이 없습니다."
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
    # 오류 출력 후 종료
fi

echo "----------------------------------------------------------------------"
echo "[주의] root 그룹(GID 0)에 등록된 일반 계정을 제거합니다."
echo "대상 계정: $EXTRA_USERS"
echo "계정 제거 후 해당 사용자는 sudo 권한이나 root 그룹 권한을 잃을 수 있습니다."
echo "----------------------------------------------------------------------"
read -p "정말 해당 계정들을 root 그룹에서 제거하시겠습니까? (y/n): " CONFIRM

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

# 2. 백업 생성
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${TARGET_FILE}_bak_$TIMESTAMP"
cp -p "$TARGET_FILE" "$BACKUP_FILE"

# 3. 조치 로직 수행
REMOVED_USERS=()
FAIL_USERS=()

for user in ${EXTRA_USERS//,/ }; do
    # gpasswd 명령어로 그룹에서 사용자 제거
    if gpasswd -d "$user" root >/dev/null 2>&1; then
        REMOVED_USERS+=("$user")
    else
        FAIL_USERS+=("$user")
    fi
done

# 4. 결과 판정 및 로깅
if [ ${#REMOVED_USERS[@]} -gt 0 ] && [ ${#FAIL_USERS[@]} -eq 0 ]; then
    ACTION_RESULT="SUCCESS"
    ACTION_LOG="성공: root 그룹에서 계정(${REMOVED_USERS[*]}) 삭제 완료. 백업: $BACKUP_FILE"
elif [ ${#REMOVED_USERS[@]} -gt 0 ] && [ ${#FAIL_USERS[@]} -gt 0 ]; then
    ACTION_RESULT="PARTIAL_SUCCESS"
    ACTION_LOG="부분 성공: 삭제(${REMOVED_USERS[*]}), 실패(${FAIL_USERS[*]}). 백업 확인 필요."
else
    ACTION_RESULT="FAIL"
    ACTION_LOG="실패: 모든 계정 제거에 실패했습니다."
fi

# 5. 표준 JSON 출력
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