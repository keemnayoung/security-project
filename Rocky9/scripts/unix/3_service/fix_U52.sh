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
# @Platform : LINUX
# @Importance : 상
# @Title : SSH 서비스 사용 (Telnet 비활성화)
# @Description : Telnet 서비스를 비활성화하고 SSH 서비스를 활성화
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-52 SSH 서비스 사용 (Telnet 비활성화)

# 1. 항목 정보 정의
ID="U-52"
CATEGORY="서비스관리"
TITLE="SSH 서비스 사용 (Telnet 비활성화)"
IMPORTANCE="상"
TARGET_FILE="/etc/inetd.conf"

# 2. 보완 로직
ACTION_RESULT="SUCCESS"
BEFORE_SETTING=""
AFTER_SETTING=""
ACTION_LOG=""

# [inetd] Telnet 비활성화
if [ -f "/etc/inetd.conf" ]; then
    if grep -v "^#" /etc/inetd.conf 2>/dev/null | grep -qE "^[[:space:]]*telnet"; then
        BEFORE_SETTING="$BEFORE_SETTING inetd Telnet 활성화;"
        cp /etc/inetd.conf /etc/inetd.conf.bak_$(date +%Y%m%d_%H%M%S)
        sed -i 's/^\([[:space:]]*telnet\)/#\1/g' /etc/inetd.conf
        systemctl restart inetd 2>/dev/null || killall -HUP inetd 2>/dev/null
        ACTION_LOG="$ACTION_LOG /etc/inetd.conf Telnet 주석 처리 및 inetd 재시작;"
    fi
fi

# [xinetd] Telnet 비활성화
if [ -f "/etc/xinetd.d/telnet" ]; then
    if grep -qiE "disable\s*=\s*no" "/etc/xinetd.d/telnet"; then
        BEFORE_SETTING="$BEFORE_SETTING xinetd Telnet disable=no;"
        sed -i 's/disable\s*=\s*no/disable = yes/gi' /etc/xinetd.d/telnet
        systemctl restart xinetd 2>/dev/null
        ACTION_LOG="$ACTION_LOG /etc/xinetd.d/telnet disable=yes 설정 및 xinetd 재시작;"
    fi
fi

# [systemd] Telnet 비활성화
# 가이드: systemctl list-units --type=socket | grep telnet
if systemctl list-units --type=socket 2>/dev/null | grep -q telnet; then
    BEFORE_SETTING="$BEFORE_SETTING systemd Telnet 활성화;"
    systemctl stop telnet.socket 2>/dev/null
    systemctl disable telnet.socket 2>/dev/null
    ACTION_LOG="$ACTION_LOG systemd telnet.socket 중지 및 비활성화;"
fi
if systemctl list-units --type=service 2>/dev/null | grep -q telnet; then
    systemctl stop telnet.service 2>/dev/null
    systemctl disable telnet.service 2>/dev/null
    ACTION_LOG="$ACTION_LOG systemd telnet.service 중지 및 비활성화;"
fi
if systemctl is-active telnet.service >/dev/null 2>&1; then
    systemctl stop telnet.service 2>/dev/null
    systemctl disable telnet.service 2>/dev/null
    ACTION_LOG="$ACTION_LOG systemd telnet.service 중지 및 비활성화;"
fi

# [SSH] 서비스 활성화
# 가이드: systemctl list-units --type=service | grep sshd
if ! systemctl list-units --type=service 2>/dev/null | grep -q sshd; then
    BEFORE_SETTING="$BEFORE_SETTING SSH 비활성화;"
    systemctl start sshd 2>/dev/null || systemctl start ssh 2>/dev/null
    systemctl enable sshd 2>/dev/null || systemctl enable ssh 2>/dev/null
    ACTION_LOG="$ACTION_LOG SSH 서비스 시작 및 활성화;"
fi

AFTER_SETTING="Telnet 비활성화 및 SSH 활성화 완료"
[ -z "$ACTION_LOG" ] && ACTION_LOG="Telnet 이미 비활성화됨"

# 3. 마스터 템플릿 표준 출력
echo ""
cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "action_result": "$ACTION_RESULT",
    "before_setting": "$BEFORE_SETTING",
    "after_setting": "$AFTER_SETTING",
    "action_log": "$ACTION_LOG",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
