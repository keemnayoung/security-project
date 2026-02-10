#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 김나영
# @Last Updated: 2026-02-09
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-02
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 패스워드 복잡성 설정
# @Description : 패스워드 복잡성 및 유효기간 설정 여부 점검
# @Criteria_Good : 패스워드 최소 길이, 복잡성, 유효기간 정책이 기준에 적합한 경우
# @Criteria_Bad : 패스워드 정책이 설정되어 있지 않거나 기준 미달인 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-02"
CATEGORY="계정관리"
TITLE="패스워드 복잡성 및 유효기간 설정"
IMPORTANCE="상"
PW_CONF="/etc/security/pwquality.conf"
LOGIN_DEFS="/etc/login.defs"
IMPACT_LEVEL="MEDIUM" 
ACTION_IMPACT="비밀번호 정책 변경(복잡성/유효기간) 시 Web, WAS, DB 연동 구간에서 계정 인증 문제가 발생할 수 있습니다. 특히 자동 로그인 스크립트나 연동 계정의 비밀번호 만료 시 서비스 중단 위험이 있으므로, 연동 구간에 미칠 수 있는 영향을 충분히 고려하여 적용해야 합니다."

STATUS="PASS"
EVIDENCE_LIST=()

# 1. pwquality.conf 체크 함수 (공백 및 주석 처리 강화)
check_pwq() {
    local param=$1
    local expected=$2
    # 주석 제외, 정확한 파라미터 매칭 후 값 추출
    local val=$(grep -iv '^#' "$PW_CONF" | grep -w "${param}" | sed 's/ //g' | cut -d'=' -f2 | tail -n 1)
    
    if [ -z "$val" ] || [ "$val" -lt "$expected" ]; then
        STATUS="FAIL"
        EVIDENCE_LIST+=("${param} 미흡(현재:${val:-기본값}, 기준:${expected})")
    fi
}

if [ -f "$PW_CONF" ]; then
    check_pwq "minlen" 8
    check_pwq "minclass" 3
else
    STATUS="FAIL"; EVIDENCE_LIST+=("pwquality.conf 파일 없음")
fi

# 2. login.defs 유효기간 체크 (주석 제외하고 정확히 매칭)
MAX_DAYS=$(grep "^PASS_MAX_DAYS" "$LOGIN_DEFS" | awk '{print $2}' | tail -n 1)
if [ -z "$MAX_DAYS" ] || [ "$MAX_DAYS" -gt 90 ]; then
    STATUS="FAIL"
    EVIDENCE_LIST+=("비밀번호 최대 유효기간이 ${MAX_DAYS:-미지정}일로 설정되어 있어 정기적인 변경 권고 기간(90일)을 초과했습니다.")
fi

# 최종 결과 정리
if [ "$STATUS" == "PASS" ]; then
    EVIDENCE="비밀번호 복잡성 설정과 유효기간 정책이 보안 가이드라인의 권고 기준을 모두 충족하고 있습니다."
else
    EVIDENCE=$(printf "; %s" "${EVIDENCE_LIST[@]}")
    EVIDENCE=${EVIDENCE#; }
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
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "guide": "pwquality.conf(minlen=8, minclass=3) 및 login.defs(PASS_MAX_DAYS=90) 설정을 적용하세요.",
    "target_file": "$PW_CONF, $LOGIN_DEFS",
    "file_hash": "${FILE_HASH:-N/A}",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF