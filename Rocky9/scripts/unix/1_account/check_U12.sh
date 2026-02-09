#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 김나영
# @Last Updated: 2026-02-09
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-12
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 하
# @Title : 세션 종료 시간 설정
# @Description : 사용자 셸에 대한 환경 설정 파일에서 세션 종료 시간 설정 여부 점검
# @Criteria_Good : 세션 종료 시간이 600초(10분) 이하로 설정되어 있는 경우
# @Criteria_Bad : 세션 종료 시간이 설정되지 않았거나 600초를 초과하는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================
ID="U-12"
CATEGORY="계정관리"
TITLE="세션 종료 시간 설정"
IMPORTANCE="하"
TARGET_FILE="/etc/profile"
IMPACT_LEVEL="MEDIUM"
ACTION_IMPACT="유휴 세션 종료(TMOUT)를 설정할 경우, 일정 시간 활동이 없으면 접속이 강제로 끊어지게 됩니다. 특히 실시간 모니터링이나 대시보드 관제 용도로 사용하는 계정은 업무 수행에 차질이 발생할 수 있으므로, 해당 용도의 계정이나 IP에 대해서는 별도의 예외 처리가 필요합니다."

STATUS="FAIL"
EVIDENCE="N/A"

if [ -f "$TARGET_FILE" ]; then
    # 1. 파일 무결성 해시 추출
    FILE_HASH=$(sha256sum "$TARGET_FILE" | awk '{print $1}')
    
    # 2. [검증 강화] TMOUT 설정값 추출 (주석 제외 및 숫자만 정밀 추출)
    TMOUT_VAL=$(grep -i "TMOUT=" "$TARGET_FILE" | grep -v "^#" | cut -d= -f2 | sed 's/[^0-9]//g' | head -1)

    # 3. 결과 판별: 가이드 기준(600초 이하) 준수 여부 확인
    if [[ "$TMOUT_VAL" =~ ^[0-9]+$ ]] && [ "$TMOUT_VAL" -le 600 ] && [ "$TMOUT_VAL" -gt 0 ]; then
        STATUS="PASS"
        EVIDENCE="세션 종료 시간이 ${TMOUT_VAL}초로 적절히 설정되어 있습니다."
    else
        STATUS="FAIL"
        if [ -z "$TMOUT_VAL" ]; then
            EVIDENCE="TMOUT 설정이 존재하지 않거나 비활성화되어 있습니다."
        else
            EVIDENCE="현재 설정값(${TMOUT_VAL}초)이 가이드 기준(600초 이하)을 초과합니다."
        fi
    fi
else
    STATUS="FAIL"
    EVIDENCE="설정 파일($TARGET_FILE) 누락"
    FILE_HASH="NOT_FOUND"
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
    "guide": "/etc/profile 파일에 TMOUT=600 및 export TMOUT를 설정하세요.",
    "file_hash": "$FILE_HASH",
    "target_file": "$TARGET_FILE",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF