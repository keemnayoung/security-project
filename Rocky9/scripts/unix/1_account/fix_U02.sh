#!/bin/bash
# [수동 조치] U-02 패스워드 복잡성 설정

ID="U-02"
PW_CONF="/etc/security/pwquality.conf"
LOGIN_DEFS="/etc/login.defs"
ACTION_RESULT="CANCELLED"
ACTION_LOG="사용자에 의해 조치가 취소되었습니다."

# 1. 관리자 위험 고지 및 승인 절차
echo "----------------------------------------------------------------------"
echo "[주의] 패스워드 복잡성 규정(길이 8자, 3종류 혼합, 유효기간 90일)을 적용합니다."
echo "이 조치는 향후 모든 사용자의 패스워드 변경 시 강제 적용됩니다."
echo "기존에 연동된 자동화 스크립트나 서비스 계정의 로그인 장애 여부를 확인하세요."
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

# 2. 백업 생성 (안전한 복구를 위해 필수)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
[ -f "$PW_CONF" ] && cp -p "$PW_CONF" "${PW_CONF}_bak_$TIMESTAMP"
[ -f "$LOGIN_DEFS" ] && cp -p "$LOGIN_DEFS" "${LOGIN_DEFS}_bak_$TIMESTAMP"

# 3. 조치 로직 (함수화하여 안정성 확보)
set_pwquality() {
    local param=$1
    local val=$2
    if grep -q "^#\?${param}" $PW_CONF; then
        sed -i "s/^#\?${param}.*/${param} = ${val}/" $PW_CONF
    else
        echo "${param} = ${val}" >> $PW_CONF
    fi
}

# 실제 수정 프로세스
{
    # pwquality 설정 (Ubuntu/Rocky 공통)
    if [ -f "$PW_CONF" ]; then
        set_pwquality "minlen" 8
        set_pwquality "minclass" 3
    fi

    # 유효기간 설정 (login.defs)
    if [ -f "$LOGIN_DEFS" ]; then
        sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' $LOGIN_DEFS
    fi
    
    ACTION_RESULT="SUCCESS"
    ACTION_LOG="KISA 기준(길이 8, 종류 3, 기간 90일) 설정 완료. (백업본 생성됨)"
} || {
    # 실패 시 복구 로직
    [ -f "${PW_CONF}_bak_$TIMESTAMP" ] && mv "${PW_CONF}_bak_$TIMESTAMP" "$PW_CONF"
    [ -f "${LOGIN_DEFS}_bak_$TIMESTAMP" ] && mv "${LOGIN_DEFS}_bak_$TIMESTAMP" "$LOGIN_DEFS"
    ACTION_RESULT="FAIL_AND_ROLLBACK"
    ACTION_LOG="설정 도중 오류가 발생하여 파일을 원복했습니다."
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