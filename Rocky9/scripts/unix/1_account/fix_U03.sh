#!/bin/bash
# [조치] U-03 계정 잠금 임계값 설정

ID="U-03"
CONF_FILE="/etc/security/faillock.conf"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
ACTION_RESULT="FAIL"
CURRENT_STATUS="FAIL"
ACTION_LOG="N/A"

# 1. 백업 및 환경 준비
if [ -f "$CONF_FILE" ]; then
    cp -p "$CONF_FILE" "${CONF_FILE}_bak_$TIMESTAMP"
else
    mkdir -p /etc/security
    touch "$CONF_FILE"
fi

# 2. 조치 로직 수행
{
    # Rocky/RHEL 9 계열 대응 (authselect 사용 시)
    if command -v authselect >/dev/null 2>&1; then
        authselect enable-feature with-faillock >/dev/null 2>&1
        authselect apply-changes >/dev/null 2>&1
    fi

    # faillock.conf 설정 (deny=10, unlock_time=120)
    for param in "deny" "unlock_time"; do
        # [수정 완료] 구문 오류 제거
        if [ "$param" == "deny" ]; then 
            val="10" 
        else 
            val="120" 
        fi 

        if grep -qi "^#\?${param}" "$CONF_FILE"; then
            sed -i "s/^#\?${param}.*/${param} = ${val}/i" "$CONF_FILE"
        else
            echo "${param} = ${val}" >> "$CONF_FILE"
        fi
    done

    # [검증] 실제 파일에 값이 제대로 반영되었는지 확인
    CHECK_VAL=$(grep -iv '^#' "$CONF_FILE" | grep -w "deny" | sed 's/ //g' | cut -d'=' -f2 | tail -1)
    
    if [ "$CHECK_VAL" == "10" ]; then
        ACTION_RESULT="SUCCESS"
        CURRENT_STATUS="PASS"
        ACTION_LOG="조치 완료: 임계값(10회) 및 잠금시간(120초) 설정됨."
    else
        ACTION_LOG="조치 실패: 설정값이 반영되지 않았습니다."
    fi
} || {
    [ -f "${CONF_FILE}_bak_$TIMESTAMP" ] && mv "${CONF_FILE}_bak_$TIMESTAMP" "$CONF_FILE"
    ACTION_RESULT="FAIL_AND_ROLLBACK"
    ACTION_LOG="설정 도중 오류가 발생하여 원복했습니다."
}

# 3. 표준 JSON 출력
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