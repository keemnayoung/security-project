#!/bin/bash
# [수동 조치] U-06 su 명령 사용 제한

ID="U-06"
TARGET_FILE="/etc/pam.d/su"
ACTION_RESULT="CANCELLED"
ACTION_LOG="사용자에 의해 조치가 취소되었습니다."

# 1. 관리자 위험 고지 및 승인 절차
echo "----------------------------------------------------------------------"
echo "[주의] su 명령어 사용을 'wheel' 그룹으로 제한합니다."
echo "조치 후, wheel 그룹에 속하지 않은 계정은 su - root 명령을 사용할 수 없습니다."
echo "반드시 조치 전 관리자 계정이 wheel 그룹에 포함되어 있는지 확인하세요."
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

# 2. 실제 조치 프로세스 시작
if [ -f "$TARGET_FILE" ]; then
    # 백업 생성
    BACKUP_FILE="${TARGET_FILE}_bak_$(date +%Y%m%d_%H%M%S)"
    cp -p "$TARGET_FILE" "$BACKUP_FILE"

    # 3. pam_wheel.so 설정 활성화 또는 추가
    # 주석처리된 auth required pam_wheel.so use_uid 라인을 찾아 주석 해제
    if grep -q "pam_wheel.so" "$TARGET_FILE"; then
        # 이미 존재하면 주석 해제
        sed -i '/pam_wheel.so/s/^#//' "$TARGET_FILE"
        # 만약 use_uid 옵션이 없다면 추가 (더 엄격한 보안 적용)
        if ! grep -q "pam_wheel.so use_uid" "$TARGET_FILE"; then
            sed -i 's/pam_wheel.so/pam_wheel.so use_uid/' "$TARGET_FILE"
        fi
        ACTION_RESULT="SUCCESS"
        ACTION_LOG="성공: pam_wheel.so 설정 활성화 완료. (백업: $BACKUP_FILE)"
    else
        # 설정이 아예 없으면 추가
        echo "auth            required        pam_wheel.so use_uid" >> "$TARGET_FILE"
        ACTION_RESULT="SUCCESS"
        ACTION_LOG="성공: pam_wheel.so 설정을 파일 끝에 추가 완료."
    fi
else
    ACTION_RESULT="ERROR"
    ACTION_LOG="대상 파일($TARGET_FILE)이 없습니다."
fi

# 4. 표준 JSON 출력
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