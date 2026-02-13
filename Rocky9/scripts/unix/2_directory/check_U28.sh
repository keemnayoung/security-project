#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-28
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : 접속 IP 및 포트 제한
# @Description : 허용할 호스트에 대한 접속 IP주소 제한 및 포트 제한 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-28"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE=""
CHECK_COMMAND='[ -f /etc/hosts.allow ] && [ -f /etc/hosts.deny ] && (grep -n "^ALL:ALL" /etc/hosts.deny; grep -nEv "^\s*$|^\s*#" /etc/hosts.allow | head); command -v iptables >/dev/null && iptables -L INPUT -n; command -v firewall-cmd >/dev/null && firewall-cmd --state && firewall-cmd --list-rich-rules; command -v ufw >/dev/null && ufw status && ufw status numbered'

DETAIL_CONTENT=""
REASON_LINE=""
FOUND_VULN="N"
VULN_LINES=""

# TCP Wrapper 점검 (조건 만족 시 양호로 간주)
if [ -f /etc/hosts.allow ] && [ -f /etc/hosts.deny ]; then
    TARGET_FILE+="/etc/hosts.allow /etc/hosts.deny "
    if grep -q "^ALL:ALL" /etc/hosts.deny && grep -Ev '^\s*$|^\s*#' /etc/hosts.allow >/dev/null 2>&1; then
        :
    else
        FOUND_VULN="Y"
        VULN_LINES+="tcp_wrapper_missing_policy"$'\n'
    fi
else
    VULN_LINES+="tcp_wrapper_not_found"$'\n'
    FOUND_VULN="Y"
fi

# iptables 점검 (INPUT 체인에서 dpt 기반 ACCEPT 룰 존재 시 양호로 간주)
if command -v iptables >/dev/null 2>&1; then
    TARGET_FILE+="iptables "
    IPTABLES_RULES=$(iptables -L INPUT -n 2>/dev/null | grep ACCEPT | grep -E 'dpt:' 2>/dev/null)
    if [ -n "$IPTABLES_RULES" ]; then
        :
    else
        FOUND_VULN="Y"
        VULN_LINES+="iptables_missing_policy"$'\n'
    fi
else
    FOUND_VULN="Y"
    VULN_LINES+="iptables_not_found"$'\n'
fi

# firewalld 점검 (active + rich-rule 존재 시 양호로 간주)
if command -v firewall-cmd >/dev/null 2>&1; then
    TARGET_FILE+="firewalld "
    if firewall-cmd --state >/dev/null 2>&1; then
        FIREWALLD_RULES=$(firewall-cmd --list-rich-rules 2>/dev/null)
        if [ -n "$FIREWALLD_RULES" ]; then
            :
        else
            FOUND_VULN="Y"
            VULN_LINES+="firewalld_missing_policy"$'\n'
        fi
    else
        FOUND_VULN="Y"
        VULN_LINES+="firewalld_inactive"$'\n'
    fi
else
    FOUND_VULN="Y"
    VULN_LINES+="firewalld_not_found"$'\n'
fi

# UFW 점검 (active + ALLOW 룰에 IP 포함 시 양호로 간주)
if command -v ufw >/dev/null 2>&1; then
    TARGET_FILE+="ufw "
    if ufw status 2>/dev/null | grep -q "Status: active"; then
        UFW_RULES=$(ufw status numbered 2>/dev/null | grep -E 'ALLOW.*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' 2>/dev/null)
        if [ -n "$UFW_RULES" ]; then
            :
        else
            FOUND_VULN="Y"
            VULN_LINES+="ufw_missing_policy"$'\n'
        fi
    else
        FOUND_VULN="Y"
        VULN_LINES+="ufw_inactive"$'\n'
    fi
else
    FOUND_VULN="Y"
    VULN_LINES+="ufw_not_found"$'\n'
fi

# 결과에 따른 PASS/FAIL 및 reason/detail 구성
if [ "$FOUND_VULN" = "Y" ]; then
    STATUS="FAIL"
    REASON_LINE="TCP Wrapper, iptables, firewalld, UFW 중 하나 이상에서 접속 IP 및 포트 제한 정책이 확인되지 않아 비인가 접근이 허용될 위험이 있으므로 취약합니다. 사용 중인 방화벽 또는 TCP Wrapper에서 허용 IP와 포트만 접근 가능하도록 정책을 설정해야 합니다."
    DETAIL_CONTENT="$(printf "%s" "$VULN_LINES" | sed 's/[[:space:]]*$//')"
else
    STATUS="PASS"
    REASON_LINE="TCP Wrapper 또는 방화벽(iptables/firewalld/UFW)에 접속 IP 및 포트 제한 정책이 설정되어 허용된 대상만 접근 가능하므로 이 항목에 대한 보안 위협이 없습니다."
    DETAIL_CONTENT="all_controls_ok"
fi

TARGET_FILE="$(echo "$TARGET_FILE" | tr -s ' ' | sed 's/[[:space:]]*$//')"

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