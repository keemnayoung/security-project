#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.1
# @Author: 권순형
# @Last Updated: 2026-02-15
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

FOUND_GOOD="N"
OK_LINES=""
WARN_LINES=""

# 1) TCP Wrapper 점검 (hosts.deny: ALL:ALL + hosts.allow: 허용 규칙 존재)
if [ -f /etc/hosts.allow ] && [ -f /etc/hosts.deny ]; then
    TARGET_FILE+="/etc/hosts.allow /etc/hosts.deny "
    if grep -q "^ALL:ALL" /etc/hosts.deny && grep -Ev '^\s*$|^\s*#' /etc/hosts.allow >/dev/null 2>&1; then
        FOUND_GOOD="Y"
        OK_LINES+="tcp_wrapper_policy_ok"$'\n'
    else
        WARN_LINES+="tcp_wrapper_policy_missing_or_incomplete"$'\n'
    fi
else
    # 가이드: 두 파일이 없으면 전체 허용이므로 취약 근거가 될 수 있음
    WARN_LINES+="tcp_wrapper_files_not_found"$'\n'
fi

# 2) iptables 점검
# - "포트(dpt:)" + "소스 IP 제한(0.0.0.0/0, ::/0 제외)"이 함께 있는 ACCEPT 룰이 있으면 양호로 간주
if command -v iptables >/dev/null 2>&1; then
    TARGET_FILE+="iptables "
    IPTABLES_OK=$(iptables -L INPUT -n 2>/dev/null \
      | awk '
        /ACCEPT/ && /dpt:/ {
          # 일반적으로: target prot opt source destination ...
          # source가 0.0.0.0/0 또는 ::/0 이면 IP 제한이 없는 것으로 판단
          src=$4;
          if (src != "0.0.0.0/0" && src != "::/0") { print $0 }
        }')

    if [ -n "$IPTABLES_OK" ]; then
        FOUND_GOOD="Y"
        OK_LINES+="iptables_ip_and_port_policy_ok"$'\n'
    else
        WARN_LINES+="iptables_ip_and_port_policy_missing"$'\n'
    fi
else
    # 특정 방화벽만 사용하는 환경일 수 있으므로 '없음' 자체로 취약 확정하지 않음
    WARN_LINES+="iptables_not_installed_or_not_used"$'\n'
fi

# 3) firewalld 점검
# - active 이면서 rich-rule에 source address + port 조건이 같이 있으면 양호로 간주
if command -v firewall-cmd >/dev/null 2>&1; then
    TARGET_FILE+="firewalld "
    if firewall-cmd --state >/dev/null 2>&1; then
        FIREWALLD_RULES=$(firewall-cmd --list-rich-rules 2>/dev/null)
        FIREWALLD_OK=$(echo "$FIREWALLD_RULES" | grep -E 'source address=' | grep -E 'port port=')

        if [ -n "$FIREWALLD_OK" ]; then
            FOUND_GOOD="Y"
            OK_LINES+="firewalld_richrule_ip_and_port_ok"$'\n'
        else
            WARN_LINES+="firewalld_richrule_ip_and_port_missing"$'\n'
        fi
    else
        WARN_LINES+="firewalld_inactive"$'\n'
    fi
else
    WARN_LINES+="firewalld_not_installed_or_not_used"$'\n'
fi

# 4) UFW 점검 (Ubuntu 계열)
# - active 이면서 "포트/프로토콜 + ALLOW + IP" 형태 룰이 있으면 양호로 간주
if command -v ufw >/dev/null 2>&1; then
    TARGET_FILE+="ufw "
    if ufw status 2>/dev/null | grep -q "Status: active"; then
        UFW_OK=$(ufw status numbered 2>/dev/null \
          | grep -E '([0-9]{1,5})/(tcp|udp)' \
          | grep -E 'ALLOW' \
          | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}')

        if [ -n "$UFW_OK" ]; then
            FOUND_GOOD="Y"
            OK_LINES+="ufw_ip_and_port_policy_ok"$'\n'
        else
            WARN_LINES+="ufw_ip_and_port_policy_missing"$'\n'
        fi
    else
        WARN_LINES+="ufw_inactive"$'\n'
    fi
else
    WARN_LINES+="ufw_not_installed_or_not_used"$'\n'
fi

# 최종 판단 (핵심 수정: "하나라도 설정되면 양호", 전부 미확인이면 취약)
if [ "$FOUND_GOOD" = "Y" ]; then
    STATUS="PASS"
    REASON_LINE="TCP Wrapper 또는 방화벽(iptables/firewalld/UFW)에서 접속 허용 대상에 대한 IP 및 포트 제한 정책이 확인되어 양호합니다."
    DETAIL_CONTENT="$(printf "%s" "$OK_LINES" | sed 's/[[:space:]]*$//')"
else
    STATUS="FAIL"
    REASON_LINE="TCP Wrapper 및 방화벽(iptables/firewalld/UFW)에서 접속 허용 대상에 대한 IP 및 포트 제한 정책이 확인되지 않아 취약합니다. 사용 중인 방화벽 또는 TCP Wrapper에서 허용 IP와 포트만 접근 가능하도록 정책을 설정해야 합니다."
    DETAIL_CONTENT="$(printf "%s" "$WARN_LINES" | sed 's/[[:space:]]*$//')"
fi

TARGET_FILE="$(echo "$TARGET_FILE" | tr -s ' ' | sed 's/[[:space:]]*$//')"
[ -z "$TARGET_FILE" ] && TARGET_FILE="N/A"

# raw_evidence 구성
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
