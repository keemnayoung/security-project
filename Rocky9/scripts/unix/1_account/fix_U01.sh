#!/bin/bash
# [수동 조치] U-01 root 계정 원격 접속 제한

ID="U-01"
TARGET_FILE="/etc/ssh/sshd_config"
ACTION_RESULT="CANCELLED"
ACTION_LOG="사용자가 조치를 취소했습니다."

# 1. 관리자 위험 고지 및 승인 절차
echo "----------------------------------------------------------------------"
echo "[경고] SSH root 원격 접속을 차단합니다."
echo "조치 후 반드시 별도의 터미널 세션에서 접속 가능 여부를 확인해야 합니다."
echo "잘못된 설정은 관리자의 원격 접속 불능 상태를 초래할 수 있습니다."
echo "----------------------------------------------------------------------"
read -p "정말 조치를 진행하시겠습니까? (y/n): " CONFIRM

if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
    # 조치 취소 시 JSON 출력 후 종료
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
    # 백업 생성 (파일명에 타임스탬프 포함)
    BACKUP_FILE="${TARGET_FILE}_bak_$(date +%Y%m%d_%H%M%S)"
    cp -p "$TARGET_FILE" "$BACKUP_FILE"
    
    # 설정 변경: 기존 설정 삭제 후 최상단 삽입
    sed -i '/PermitRootLogin/d' "$TARGET_FILE"
    sed -i '1i PermitRootLogin no' "$TARGET_FILE"
    
    # 3. 서비스 재시작 및 자동 복구 로직 (Rollback)
    if systemctl restart sshd >/dev/null 2>&1 || systemctl restart ssh >/dev/null 2>&1; then
        ACTION_RESULT="SUCCESS"
        ACTION_LOG="Root 로그인 차단 완료 및 SSH 서비스 재시작 성공. (백업: $BACKUP_FILE)"
    else
        # 서비스 재시작 실패 시 백업본으로 즉시 복구
        mv "$BACKUP_FILE" "$TARGET_FILE"
        systemctl restart sshd >/dev/null 2>&1 || systemctl restart ssh >/dev/null 2>&1
        ACTION_RESULT="FAIL_AND_ROLLBACK"
        ACTION_LOG="서비스 재시작 실패로 인해 설정을 원복(Rollback)했습니다. 파일 구문을 확인하세요."
    fi
else
    ACTION_RESULT="ERROR"
    ACTION_LOG="조치 대상 파일($TARGET_FILE)이 없습니다."
fi

# 4. 표준 JSON 출력 (대시보드 연동용)
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