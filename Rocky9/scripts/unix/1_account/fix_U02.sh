#!/bin/bash
# [조치] U-02 패스워드 복잡성 설정

ID="U-02"
PW_CONF="/etc/security/pwquality.conf"
LOGIN_DEFS="/etc/login.defs"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# 1. 파일 백업 (조치 과정에서 원본 파일이 손상될 경우를 대비하여 복구용 복사본을 만드는 과정)
[ -f "$PW_CONF" ] && cp -p "$PW_CONF" "${PW_CONF}_bak_$TIMESTAMP"
[ -f "$LOGIN_DEFS" ] && cp -p "$LOGIN_DEFS" "${LOGIN_DEFS}_bak_$TIMESTAMP"

# 2. 파라미터 설정 함수 (수정 또는 추가)
set_param() {
    local file=$1
    local param=$2
    local val=$3
    local sep=$4 # 구분자 (pwquality는 =, login.defs는 공백)

    if grep -q "^#\?${param}" "$file"; then
        sed -i "s/^#\?${param}.*/${param}${sep}${val}/" "$file"
    else
        echo "${param}${sep}${val}" >> "$file"
    fi
}

# 3. 실제 조치 수행
if [ -f "$PW_CONF" ]; then
    set_param "$PW_CONF" "minlen" "8" " = "
    set_param "$PW_CONF" "minclass" "3" " = "
fi

if [ -f "$LOGIN_DEFS" ]; then
    set_param "$LOGIN_DEFS" "PASS_MAX_DAYS" "90" "   "
fi

# 4. 검증 및 결과 보고
# 실제 파일에 값이 제대로 박혔는지 런타임 체크
CHECK_LEN=$(grep -iv '^#' "$PW_CONF" | grep "minlen" | sed 's/ //g' | cut -d'=' -f2 | tail -1)
CHECK_DAYS=$(grep "^PASS_MAX_DAYS" "$LOGIN_DEFS" | awk '{print $2}' | tail -1)

if [ "$CHECK_LEN" == "8" ] && [ "$CHECK_DAYS" == "90" ]; then
    ACTION_RESULT="SUCCESS"
    CURRENT_STATUS="PASS"
    ACTION_LOG="조치 완료: 패스워드 규정 준수 설정됨. (minlen:8, MaxDays:90)"
else
    ACTION_RESULT="FAIL"
    CURRENT_STATUS="FAIL"
    ACTION_LOG="조치 실패: 설정값이 기준과 일치하지 않습니다. 수동 확인 필요."
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