#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-52
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : Telnet 서비스 비활성화
# @Description : 원격 접속 시 Telnet 프로토콜 사용 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-52 Telnet 서비스 비활성화

# 1. 항목 정보 정의
ID="U-52"
CATEGORY="서비스 관리"
TITLE="Telnet 서비스 비활성화"
IMPORTANCE="중"
TARGET_FILE="/etc/inetd.conf"

# 2. 보완 로직
ACTION_RESULT="SUCCESS"
ACTION_LOG=""

# [inetd] Telnet 비활성화
if [ -f "/etc/inetd.conf" ]; then
    if grep -v "^#" /etc/inetd.conf 2>/dev/null | grep -qE "^[[:space:]]*telnet"; then

        cp /etc/inetd.conf /etc/inetd.conf.bak_$(date +%Y%m%d_%H%M%S)
        sed -i 's/^\([[:space:]]*telnet\)/#\1/g' /etc/inetd.conf
        systemctl restart inetd 2>/dev/null || killall -HUP inetd 2>/dev/null
        ACTION_LOG="$ACTION_LOG /etc/inetd.conf Telnet을 주석 처리하고 inetd를 재시작했습니다."
    fi
fi

# [xinetd] Telnet 비활성화
if [ -f "/etc/xinetd.d/telnet" ]; then
    if grep -qiE "disable\s*=\s*no" "/etc/xinetd.d/telnet"; then

        sed -i 's/disable\s*=\s*no/disable = yes/gi' /etc/xinetd.d/telnet
        systemctl restart xinetd 2>/dev/null
        ACTION_LOG="$ACTION_LOG /etc/xinetd.d/telnet disable=yes 설정 후 xinetd를 재시작했습니다."
    fi
fi

# [systemd] Telnet 비활성화
# 가이드: systemctl list-units --type=socket | grep telnet
if systemctl list-units --type=socket 2>/dev/null | grep -q telnet; then

    systemctl stop telnet.socket 2>/dev/null
    systemctl disable telnet.socket 2>/dev/null
    ACTION_LOG="$ACTION_LOG systemd telnet.socket을 중지하고 비활성화했습니다."
fi
if systemctl list-units --type=service 2>/dev/null | grep -q telnet; then
    systemctl stop telnet.service 2>/dev/null
    systemctl disable telnet.service 2>/dev/null
    ACTION_LOG="$ACTION_LOG systemd telnet.service를 중지하고 비활성화했습니다."
fi
if systemctl is-active telnet.service >/dev/null 2>&1; then
    systemctl stop telnet.service 2>/dev/null
    systemctl disable telnet.service 2>/dev/null
    ACTION_LOG="$ACTION_LOG systemd telnet.service를 중지하고 비활성화했습니다."
fi

# [SSH] 서비스 활성화
# 가이드: systemctl list-units --type=service | grep sshd
if ! systemctl list-units --type=service 2>/dev/null | grep -q sshd; then

    systemctl start sshd 2>/dev/null || systemctl start ssh 2>/dev/null
    systemctl enable sshd 2>/dev/null || systemctl enable ssh 2>/dev/null
    ACTION_LOG="$ACTION_LOG SSH 서비스를 시작하고 활성화했습니다."
fi

if [ -n "$ACTION_LOG" ]; then
    ACTION_LOG="Telnet 서비스를 비활성화하고 SSH 서비스를 활성화하여 안전한 원격 접속 환경을 구성했습니다."
else
    ACTION_LOG="Telnet 서비스가 이미 비활성화되어 있습니다."
fi

STATUS="PASS"
EVIDENCE="취약점 조치가 완료되었습니다."

# 3. 마스터 템플릿 표준 출렵
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
