#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 김나영
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID : U-02
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 패스워드 복잡성 설정
# @Description : 패스워드 복잡성 및 유효기간 설정을 KISA 권고 수준으로 강화
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-02"
CATEGORY="계정관리"
TITLE="패스워드 복잡성 및 유효기간 설정"
IMPORTANCE="상"
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
    STATUS="PASS"
    ACTION_LOG="비밀번호의 최소 길이를 8자로 강화하고 유효기간을 90일로 설정하여, 유추하기 어려운 암호 사용 및 정기적인 변경을 유도하도록 정책을 변경하였습니다."
else
    ACTION_RESULT="FAIL"
    STATUS="FAIL"
    ACTION_LOG="보안 설정을 시도하였으나 일부 파라미터가 시스템 기준값과 일치하지 않습니다. 설정 파일의 문법 오류나 권한 문제를 점검하기 위해 관리자의 수동 확인이 필요합니다."
fi

echo ""
cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "KISA 가이드라인에 따른 보안 설정이 완료되었습니다.",
    "action_result": "$ACTION_RESULT",
    "action_log": "$ACTION_LOG",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF