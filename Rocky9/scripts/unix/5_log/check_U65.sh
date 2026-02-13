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

# 기본 변수
ID="U-65"
STATUS="FAIL"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/ntp.conf /etc/chrony.conf"
CHECK_COMMAND='systemctl list-units --type=service | egrep "ntp|chrony"; command -v ntpq >/dev/null && ntpq -pn; [ -f /etc/ntp.conf ] && grep -nE "^[[:space:]]*server[[:space:]]+" /etc/ntp.conf; command -v chronyc >/dev/null && chronyc sources; [ -f /etc/chrony.conf ] && grep -nE "^[[:space:]]*server[[:space:]]+" /etc/chrony.conf'

REASON_LINE=""
DETAIL_CONTENT=""

NTP_OK=false
CHRONY_OK=false

NTP_DETAIL=""
CHRONY_DETAIL=""

# NTP 점검 분기
if systemctl list-units --type=service 2>/dev/null | grep -q ntp; then
    NTP_DETAIL+="ntp_service=active"$'\n'

    if command -v ntpq >/dev/null 2>&1; then
        NTP_SYNC=$(ntpq -pn 2>/dev/null | awk '$1 ~ /^[\*\+]/')
        if [ -n "$NTP_SYNC" ]; then
            CNT=$(echo "$NTP_SYNC" | wc -l | tr -d ' ')
            NTP_DETAIL+="ntp_sync_servers=${CNT}"$'\n'
        else
            NTP_DETAIL+="ntp_sync_servers=0"$'\n'
        fi

        if [ -f /etc/ntp.conf ] && grep -qE '^[[:space:]]*server[[:space:]]+' /etc/ntp.conf; then
            NTP_DETAIL+="ntp_conf_server=present"
            NTP_OK=true
        else
            NTP_DETAIL+="ntp_conf_server=missing"
        fi
    else
        NTP_DETAIL+="ntpq_cmd=missing"
    fi
else
    NTP_DETAIL+="ntp_service=inactive"
fi

# Chrony 점검 분기
if systemctl list-units --type=service 2>/dev/null | grep -q chrony; then
    CHRONY_DETAIL+="chrony_service=active"$'\n'

    if command -v chronyc >/dev/null 2>&1; then
        CHRONY_SYNC=$(chronyc sources 2>/dev/null | grep -E '^\^')
        if [ -n "$CHRONY_SYNC" ]; then
            CHRONY_DETAIL+="chrony_sync_sources=present"$'\n'
        else
            CHRONY_DETAIL+="chrony_sync_sources=missing"$'\n'
        fi

        if [ -f /etc/chrony.conf ] && grep -qE '^[[:space:]]*server[[:space:]]+' /etc/chrony.conf; then
            CHRONY_DETAIL+="chrony_conf_server=present"
            CHRONY_OK=true
        else
            CHRONY_DETAIL+="chrony_conf_server=missing"
        fi
    else
        CHRONY_DETAIL+="chronyc_cmd=missing"
    fi
else
    CHRONY_DETAIL+="chrony_service=inactive"
fi

# 최종 판단
if [ "$NTP_OK" = true ] || [ "$CHRONY_OK" = true ]; then
    STATUS="PASS"
    REASON_LINE="NTP 또는 Chrony 서비스가 활성화되어 있고 동기화 서버 설정(server)이 존재하여 시스템 시간이 기준 시간과 동기화될 수 있으므로 이 항목에 대한 보안 위협이 없습니다."
else
    STATUS="FAIL"
    REASON_LINE="NTP 및 Chrony 동기화 설정이 활성화되어 있지 않거나 동기화 서버 설정(server)이 확인되지 않아 로그 시간 불일치 및 감사 추적 신뢰성이 저하될 수 있으므로 취약합니다. NTP 또는 Chrony를 활성화하고 동기화 서버 및 주기 설정을 구성해야 합니다."
fi

# detail 구성 (줄바꿈 유지)
DETAIL_CONTENT="NTP:"$'\n'"$NTP_DETAIL"$'\n'"CHRONY:"$'\n'"$CHRONY_DETAIL"

# raw_evidence 구성 (첫 줄: 평가 이유 / 다음 줄부터: 현재 설정값)
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

# JSON escape 처리 (따옴표, 줄바꿈)
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/"/\\"/g' \
  | sed ':a;N;$!ba;s/\n/\\n/g')

# scan_history 저장용 JSON 출력
echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF