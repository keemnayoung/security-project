#!/bin/bash
# [수동 조치] U-03 계정 잠금 임계값 설정

ID="U-03"
CONF_FILE="/etc/security/faillock.conf"
ACTION_RESULT="CANCELLED"
ACTION_LOG="사용자에 의해 조치가 취소되었습니다."

# 1. 관리자 위험 고지 및 승인 절차 (수동 조치의 핵심)
echo "----------------------------------------------------------------------"
echo "[경고] 계정 잠금 임계값 설정을 적용합니다."
echo "조치 후, 설정된 횟수 이상 로그인 실패 시 해당 계정이 잠깁니다."
echo "공격자가 관리자 계정을 고의로 잠글 수 있는 위험(DoS)을 인지하셨습니까?"
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

# 2. 백업 및 환경 준비
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
if [ -f "$CONF_FILE" ]; then
    cp -p "$CONF_FILE" "${CONF_FILE}_bak_$TIMESTAMP"
else
    # 파일이 없는 경우 생성 (터치)
    touch "$CONF_FILE"
fi

# 3. 조치 로직 수행
{
    # Rocky/RHEL 계열에서 authselect 사용 가능 시 활성화
    if command -v authselect >/dev/null 2>&1; then
        authselect enable-feature with-faillock >/dev/null 2>&1
        authselect apply-changes >/dev/null 2>&1
    fi

    # faillock.conf 설정 적용 (deny=10, unlock_time=120)
    # 기존 설정이 주석(#) 처리되어 있어도 치환하거나 없으면 추가함
    for param in "deny" "unlock_time"; do
        val=$([ "$param" == "deny" ] && echo "10" || echo "120")
        if grep -q "^#\? \?${param}" "$CONF_FILE"; then
            sed -i "s/^#\? \?${param}.*/${param} = ${val}/" "$CONF_FILE"
        else
            echo "${param} = ${val}" >> "$CONF_FILE"
        fi
    done

    ACTION_RESULT="SUCCESS"
    ACTION_LOG="계정 잠금 임계값(10회) 및 잠금 시간(120초) 설정 완료 (백업: ${CONF_FILE}_bak_$TIMESTAMP)"
} || {
    # 실패 시 롤백 (백업 파일이 존재할 경우)
    [ -f "${CONF_FILE}_bak_$TIMESTAMP" ] && mv "${CONF_FILE}_bak_$TIMESTAMP" "$CONF_FILE"
    ACTION_RESULT="FAIL_AND_ROLLBACK"
    ACTION_LOG="설정 적용 중 오류가 발생하여 원복했습니다."
}

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