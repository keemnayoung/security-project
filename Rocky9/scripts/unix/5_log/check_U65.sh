#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.2
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-65
# @Category    : 로그 관리
# @Platform    : Rocky Linux
# @Importance  : 중
# @Title       : NTP 및 시각 동기화 설정
# @Description : NTP 및 시각 동기화 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 1. 항목 정보 정의
ID="U-65"
CATEGORY="로그 관리"
TITLE="NTP 및 시각 동기화 설정"
IMPORTANCE="중"
STATUS="FAIL"
EVIDENCE=""
GUIDE="해당 항목은 자동 조치 시 시스템 장애 위험이 커서 자동 조치 기능을 제공하지 않습니다. 관리자가 직접 NTP 또는 Chrony 설정과 동기화 주기를 설정해주세요."
ACTION_RESULT="PARTIAL_SUCCESS"
IMPACT_LEVEL="LOW" 
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없으나, 잘못된 NTP 서버 설정이나 네트워크 지연 시 서비스 시작 지연이나 시간 의존 애플리케이션 오류가 발생할 수 있습니다."
TARGET_FILE="/etc/ntp.conf, /etc/chrony.conf"
FILE_HASH="N/A"
CHECK_DATE=$(date '+%Y-%m-%d %H:%M:%S')

# 2. 진단 로직

# [NTP] 점검
NTP_OK=false

# Step 1. NTP 서비스 활성화 여부
if systemctl list-units --type=service | grep -q ntp; then
    EVIDENCE+="ntp 서비스 활성화됨, "

    # Step 2. 동기화된 NTP 서버 확인
    if command -v ntpq >/dev/null 2>&1; then
        NTP_SYNC=$(ntpq -pn 2>/dev/null | awk '$1 ~ /^[\*\+]/')
        if [ -n "$NTP_SYNC" ]; then
            CNT=$(echo "$NTP_SYNC" | wc -l)
            EVIDENCE+="ntp 동기화 서버 존재(${CNT}개), "
            
            # Step 3. ntp.conf 서버 설정 확인
            if [ -f /etc/ntp.conf ] && grep -qE '^[[:space:]]*server[[:space:]]+' /etc/ntp.conf; then
                EVIDENCE+="ntp.conf 서버 설정이 존재하여 이 항목에 대한 보안 위협이 없습니다. 다만, 올바른 설정이 다시 한번 확인해주시길 바랍니다."
                NTP_OK=true
            else
                EVIDENCE+="ntp.conf 서버 설정이 없습니다. "
            fi
        else
            EVIDENCE+="ntp 동기화 서버가 없습니다. "
        fi
    else
        EVIDENCE+="ntpq 명령어가 없습니다.  "
    fi
else
    EVIDENCE+="ntp 서비스가 비활성화되어 있습니다."
fi


# [Chrony] 점검
CHRONY_OK=false

# Step 1. Chrony 서비스 활성화 여부
if systemctl list-units --type=service | grep -q chrony; then
    EVIDENCE+="chrony 서비스 활성화됨, "

    # Step 2. 동기화된 Chrony 서버 확인
    if command -v chronyc >/dev/null 2>&1; then
        CHRONY_SYNC=$(chronyc sources 2>/dev/null | grep -E '^\^')
        if [ -n "$CHRONY_SYNC" ]; then
            EVIDENCE+="chrony 동기화 서버 확인됨, "

            # Step 3. chrony.conf 서버 설정 확인
            if [ -f /etc/chrony.conf ] && grep -qE '^[[:space:]]*server[[:space:]]+' /etc/chrony.conf; then
                EVIDENCE+="chrony.conf 서버 설정이 존재하여 이 항목에 대한 보안 위협이 없습니다. 다만, 올바른 설정이 다시 한번 확인해주시길 바랍니다. "
                CHRONY_OK=true
            else
                EVIDENCE+="chrony.conf 서버 설정이 없습니다. "
            fi
        else
            EVIDENCE+="chrony 동기화 서버가 없습니다. "
        fi
    else
        EVIDENCE+="chronyc 명령어가 없습니다."
    fi
else
    EVIDENCE+="chrony 서비스가 비활성화 되어 있습니다. "
fi


# 최종 판단
if [ "$NTP_OK" = true ] || [ "$CHRONY_OK" = true ]; then
    STATUS="PASS"
    ACTION_RESULT="SUCCESS"
    GUIDE="KISA 보안 가이드라인을 준수하고 있습니다."
fi


# 3. 마스터 템플릿 표준 출력
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
    "guide": "$GUIDE",
    "action_result": "$ACTION_RESULT",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$CHECK_DATE"
}
EOF