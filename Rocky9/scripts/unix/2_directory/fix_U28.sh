#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 권순형
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-28
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Debian
# @Importance  : 상
# @Title       : 접속 IP 및 포트 제한
# @Description : 접속을 허용할 특정 호스트에 대한 IP주소 및 포트 제한 설정
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

######################
# 검토 필요 (수동 설정)
#####################

# 1. 기본 변수 정의
CHECK_ID="U-28"
TARGET_FILE="Firewall / TCP Wrapper"
ACTION_RESULT="MANUAL_REQUIRED"
ACTION_LOG=""
BEFORE_SETTING=""
AFTER_SETTING=""
ACTION_DATE=$(date +"%Y-%m-%d %H:%M:%S")


# 2. 조치 로직
# TCP Wrapper 상태 수집
if [ -f /etc/hosts.allow ] || [ -f /etc/hosts.deny ]; then
    BEFORE_SETTING+="[TCP Wrapper]\n"
    BEFORE_SETTING+="--- /etc/hosts.allow ---\n"
    BEFORE_SETTING+="$(cat /etc/hosts.allow 2>/dev/null)\n"
    BEFORE_SETTING+="--- /etc/hosts.deny ---\n"
    BEFORE_SETTING+="$(cat /etc/hosts.deny 2>/dev/null)\n\n"
fi

# iptables 상태 수집
if command -v iptables >/dev/null 2>&1; then
    BEFORE_SETTING+="[iptables]\n"
    BEFORE_SETTING+="$(iptables -L INPUT -n 2>/dev/null)\n\n"
fi

# firewalld 상태 수집
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    BEFORE_SETTING+="[firewalld]\n"
    BEFORE_SETTING+="$(firewall-cmd --list-all 2>/dev/null)\n\n"
fi

# UFW 상태 수집
if command -v ufw >/dev/null 2>&1; then
    BEFORE_SETTING+="[UFW]\n"
    BEFORE_SETTING+="$(ufw status numbered 2>/dev/null)\n\n"
fi

ACTION_LOG="IP 및 포트 제한 정책은 서비스별 영향도가 높아 자동 조치를 수행하지 않음.
관리자는 OS 방화벽 또는 TCP Wrapper를 사용하여 허용 IP 및 포트를 명시적으로 설정해야 함."

AFTER_SETTING="자동 조치 미수행 (수동 설정 필요)"


# 3. 조치 결과 JSON 출력
echo ""
cat <<EOF
{
  "check_id": "$CHECK_ID",
  "action_result": "$ACTION_RESULT",
  "before_setting": "$(echo -e "$BEFORE_SETTING" | sed 's/"/\\"/g')",
  "after_setting": "$(echo -e "$AFTER_SETTING" | sed 's/"/\\"/g')",
  "action_log": "$(echo -e "$ACTION_LOG" | sed 's/"/\\"/g')",
  "action_date": "$ACTION_DATE"
}
EOF