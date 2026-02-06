#!/bin/bash
# [조치] U-06 su 명령 사용 제한

ID="U-06"
TARGET_FILE="/etc/pam.d/su"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
ACTION_RESULT="FAIL"
CURRENT_STATUS="FAIL"
ACTION_LOG="N/A"

# 1. 백업 생성
if [ -f "$TARGET_FILE" ]; then
    cp -p "$TARGET_FILE" "${TARGET_FILE}_bak_$TIMESTAMP"
else
    ACTION_RESULT="ERROR"
    ACTION_LOG="대상 파일($TARGET_FILE)이 존재하지 않습니다."
    # 결과 출력 후 종료
    exit 1
fi

# 2. 실제 조치 프로세스
{
    # pam_wheel.so 설정 활성화 (주석 제거 및 use_uid 옵션 강제)
    if grep -qi "pam_wheel.so" "$TARGET_FILE"; then
        # 1) 주석 제거 (라인 시작의 # 제거)
        sed -i '/pam_wheel.so/s/^#//' "$TARGET_FILE"
        # 2) 필수 옵션인 use_uid가 없다면 추가
        if ! grep -q "pam_wheel.so.*use_uid" "$TARGET_FILE"; then
            sed -i 's/pam_wheel.so/pam_wheel.so use_uid/' "$TARGET_FILE"
        fi
    else
        # 설정이 아예 없으면 최상단 부근(auth 설정 구역)에 추가
        sed -i '1i auth            required        pam_wheel.so use_uid' "$TARGET_FILE"
    fi

    # 3. [검증] 조치 후 상태 재확인
    FINAL_CHECK=$(grep -v '^#' "$TARGET_FILE" | grep "pam_wheel.so" | grep "auth" | grep "required")
    if [ -n "$FINAL_CHECK" ]; then
        ACTION_RESULT="SUCCESS"
        CURRENT_STATUS="PASS"
        ACTION_LOG="성공: pam_wheel.so 설정 활성화 및 wheel 그룹 제한 적용 완료."
    else
        ACTION_LOG="실패: 설정 수정 후에도 활성화 상태를 확인할 수 없습니다."
    fi
} || {
    [ -f "${TARGET_FILE}_bak_$TIMESTAMP" ] && mv "${TARGET_FILE}_bak_$TIMESTAMP" "$TARGET_FILE"
    ACTION_RESULT="FAIL_AND_ROLLBACK"
    ACTION_LOG="조치 중 오류가 발생하여 파일을 원복했습니다."
}

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