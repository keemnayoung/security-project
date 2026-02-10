#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 김나영
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID : U-03
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 계정 잠금 임계값 설정
# @Description : 계정 탈취 공격 방지를 위해 로그인 실패 시 잠금 임계값 조치
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-03"
CATEGORY="계정관리"
TITLE="계정 잠금 임계값 설정"
IMPORTANCE="상"
CONF_FILE="/etc/security/faillock.conf"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
ACTION_RESULT="FAIL"
STATUS="FAIL"
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
        STATUS="PASS"
        ACTION_LOG="계정 잠금 임계값 10회 및 잠금 시간 120초 적용을 통해 시스템 접근 제어 강화를 위한 조치를 완료하였습니다."
    else
        ACTION_LOG="설정 변경을 시도하였으나 시스템에 즉시 반영되지 않았습니다. 정확한 적용을 위해 설정 파일의 문법이나 서비스 상태를 수동으로 확인해야 합니다."
    fi
} || {
    [ -f "${CONF_FILE}_bak_$TIMESTAMP" ] && mv "${CONF_FILE}_bak_$TIMESTAMP" "$CONF_FILE"
    ACTION_RESULT="FAIL_AND_ROLLBACK"
    ACTION_LOG="구성 파일 수정 중 예기치 않은 오류가 발생하여 시스템의 안정성을 유지하기 위해 기존 설정 상태로 복구하였습니다."
}

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