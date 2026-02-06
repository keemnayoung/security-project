#!/bin/bash
# [수동 조치] U-05 root 이외의 UID가 0인 계정 존재

ID="U-05"
TARGET_FILE="/etc/passwd"
ACTION_RESULT="CANCELLED"
ACTION_LOG="사용자에 의해 조치가 취소되었습니다."

# 1. 관리자 위험 고지 및 대상 리포팅
EXTRA_ROOT=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' $TARGET_FILE)

if [ -z "$EXTRA_ROOT" ]; then
    ACTION_RESULT="SUCCESS"
    ACTION_LOG="조치할 대상 계정이 없습니다."
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

echo "----------------------------------------------------------------------"
echo "[치명적 위험] root 권한(UID 0)을 가진 일반 계정이 발견되었습니다."
echo "대상 계정: $EXTRA_ROOT"
echo "조치 시 해당 계정의 UID를 2000번 대역의 미사용 번호로 변경합니다."
echo "주의: UID 변경 시 해당 계정이 소유한 파일의 권한 문제가 발생할 수 있습니다."
echo "----------------------------------------------------------------------"
read -p "정말 조치를 진행하시겠습니까? (y/n): " CONFIRM

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
cp -p "$TARGET_FILE" "${TARGET_FILE}_bak_$TIMESTAMP"

# 3. 조치 로직 수행
SUCCESS_COUNT=0
FAIL_COUNT=0
LOG_MSG=""

# 2000번부터 시작하여 사용 중이지 않은 UID 찾기 함수
get_unused_uid() {
    local uid=2000
    while getent passwd $uid >/dev/null; do
        ((uid++))
    done
    echo $uid
}

for user in $EXTRA_ROOT; do
    NEW_UID=$(get_unused_uid)
    if usermod -u $NEW_UID $user >/dev/null 2>&1; then
        ((SUCCESS_COUNT++))
        LOG_MSG+="${user}(UID 0 -> $NEW_UID) 변경 완료; "
    else
        ((FAIL_COUNT++))
        LOG_MSG+="${user} 변경 실패; "
    fi
done

# 4. 결과 판정
if [ $FAIL_COUNT -eq 0 ]; then
    ACTION_RESULT="SUCCESS"
else
    ACTION_RESULT="PARTIAL_SUCCESS"
fi
ACTION_LOG="${LOG_MSG%; }"

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