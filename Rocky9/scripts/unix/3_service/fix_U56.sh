#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.1.0
# @Author: 이가영
# @Last Updated: 2026-02-11
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-56
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 하
# @Title : FTP 서비스 접근 제어 설정
# @Description : FTP 서비스 접근 제어 설정 보완
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-56 FTP 서비스 접근 제어 설정

# 1. 항목 정보 정의
ID="U-56"
CATEGORY="서비스 관리"
TITLE="FTP 서비스 접근 제어 설정"
IMPORTANCE="하"
TARGET_FILE="/etc/vsftpd.conf"

# 2. 보완 로직
ACTION_RESULT="SUCCESS"
ACTION_LOG=""
STATUS="PASS"
EVIDENCE=""
FTP_IN_USE=0
NEEDS_MANUAL=0

ensure_owner_perm() {
    local file="$1"
    local owner="$2"
    local perm="$3"

    [ -f "$file" ] || return
    chown "$owner" "$file" 2>/dev/null
    chmod "$perm" "$file" 2>/dev/null
}

has_non_comment_match() {
    local file="$1"
    local pattern="$2"
    grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$file" 2>/dev/null | grep -qE "$pattern"
}

# hosts.allow / hosts.deny 기본 보완
ensure_hosts_control() {
    local daemon_regex="$1"
    local daemon_label="$2"

    [ -f "/etc/hosts.allow" ] || touch "/etc/hosts.allow"
    [ -f "/etc/hosts.deny" ] || touch "/etc/hosts.deny"

    ensure_owner_perm "/etc/hosts.allow" root 644
    ensure_owner_perm "/etc/hosts.deny" root 644

    if ! has_non_comment_match "/etc/hosts.allow" "^(${daemon_regex})[[:space:]]*:"; then
        echo "${daemon_label}: 127.0.0.1" >> /etc/hosts.allow
        ACTION_LOG="$ACTION_LOG /etc/hosts.allow에 ${daemon_label}:127.0.0.1 예시를 추가했습니다."
        NEEDS_MANUAL=1
    fi

    if ! has_non_comment_match "/etc/hosts.deny" '^ALL[[:space:]]*:[[:space:]]*ALL'; then
        echo "ALL: ALL" >> /etc/hosts.deny
        ACTION_LOG="$ACTION_LOG /etc/hosts.deny에 ALL:ALL 기본 차단 정책을 추가했습니다."
    fi
}

# vsFTP 보완
VSFTPD_CONF=""
if [ -f "/etc/vsftpd.conf" ]; then
    VSFTPD_CONF="/etc/vsftpd.conf"
elif [ -f "/etc/vsftpd/vsftpd.conf" ]; then
    VSFTPD_CONF="/etc/vsftpd/vsftpd.conf"
fi

if command -v vsftpd >/dev/null 2>&1 || [ -n "$VSFTPD_CONF" ] || systemctl list-units --type=service 2>/dev/null | grep -q vsftpd; then
    FTP_IN_USE=1

    if [ -n "$VSFTPD_CONF" ]; then
        TARGET_FILE="$VSFTPD_CONF"
        if grep -Eq '^[[:space:]]*tcp_wrappers[[:space:]]*=' "$VSFTPD_CONF"; then
            sed -Ei 's/^[[:space:]]*tcp_wrappers[[:space:]]*=.*/tcp_wrappers=YES/' "$VSFTPD_CONF"
        else
            echo "tcp_wrappers=YES" >> "$VSFTPD_CONF"
        fi
        ACTION_LOG="$ACTION_LOG vsftpd tcp_wrappers=YES를 적용했습니다."

        ensure_hosts_control "vsftpd|in\\.ftpd" "vsftpd"

        if has_non_comment_match "$VSFTPD_CONF" '^userlist_enable[[:space:]]*=[[:space:]]*YES'; then
            USERLIST_FILE="/etc/vsftpd.user_list"
            [ ! -f "$USERLIST_FILE" ] && USERLIST_FILE="/etc/vsftpd/user_list"
            [ -f "$USERLIST_FILE" ] && ensure_owner_perm "$USERLIST_FILE" root 640
        else
            FTPUSERS_FILE="/etc/vsftpd.ftpusers"
            [ ! -f "$FTPUSERS_FILE" ] && FTPUSERS_FILE="/etc/vsftpd/ftpusers"
            [ ! -f "$FTPUSERS_FILE" ] && FTPUSERS_FILE="/etc/ftpusers"
            [ -f "$FTPUSERS_FILE" ] && ensure_owner_perm "$FTPUSERS_FILE" root 640
        fi

        systemctl restart vsftpd 2>/dev/null
    else
        ACTION_LOG="$ACTION_LOG vsftpd 설정 파일을 찾지 못해 수동 확인이 필요합니다."
        NEEDS_MANUAL=1
    fi
fi

# ProFTP 보완
PROFTPD_CONF=""
if [ -f "/etc/proftpd/proftpd.conf" ]; then
    PROFTPD_CONF="/etc/proftpd/proftpd.conf"
elif [ -f "/etc/proftpd.conf" ]; then
    PROFTPD_CONF="/etc/proftpd.conf"
fi

if command -v proftpd >/dev/null 2>&1 || [ -n "$PROFTPD_CONF" ] || systemctl list-units --type=service 2>/dev/null | grep -q proftpd; then
    FTP_IN_USE=1

    if [ -n "$PROFTPD_CONF" ]; then
        ensure_owner_perm "$PROFTPD_CONF" root 640
        TARGET_FILE="$PROFTPD_CONF"

        USE_FTPUSERS=$(grep -Ei '^[[:space:]]*UseFtpUsers' "$PROFTPD_CONF" 2>/dev/null | tail -n1 | awk '{print tolower($2)}')
        if [ "$USE_FTPUSERS" = "off" ]; then
            LIMIT_LOGIN=$(sed -n '/<Limit LOGIN>/,/<\/Limit>/p' "$PROFTPD_CONF" 2>/dev/null)
            if [ -z "$LIMIT_LOGIN" ] || ! echo "$LIMIT_LOGIN" | grep -qiE 'Allow[[:space:]]+from|Deny[[:space:]]+from|AllowUser|DenyUser'; then
                cat >> "$PROFTPD_CONF" <<'LIMIT_EOF'

<Limit LOGIN>
    Order Deny,Allow
    Allow from 127.0.0.1
    Deny from all
</Limit>
LIMIT_EOF
                ACTION_LOG="$ACTION_LOG proftpd <Limit LOGIN> 기본 템플릿을 추가했습니다."
                NEEDS_MANUAL=1
            fi
        else
            FTPUSERS_FILE="/etc/ftpusers"
            [ ! -f "$FTPUSERS_FILE" ] && FTPUSERS_FILE="/etc/ftpd/ftpusers"
            [ -f "$FTPUSERS_FILE" ] && ensure_owner_perm "$FTPUSERS_FILE" root 640
        fi

        systemctl restart proftpd 2>/dev/null
    else
        ACTION_LOG="$ACTION_LOG proftpd 설정 파일을 찾지 못해 수동 확인이 필요합니다."
        NEEDS_MANUAL=1
    fi
fi

# inetd/xinetd FTP 사용 시 접근 제어 기본 보완
if [ -f "/etc/inetd.conf" ] && has_non_comment_match "/etc/inetd.conf" '^[[:space:]]*ftp([[:space:]]|$)'; then
    FTP_IN_USE=1
    ensure_hosts_control "in\\.ftpd|ftpd" "in.ftpd"
    NEEDS_MANUAL=1
fi

if [ -f "/etc/xinetd.d/ftp" ] && has_non_comment_match "/etc/xinetd.d/ftp" '^[[:space:]]*disable[[:space:]]*=[[:space:]]*no'; then
    FTP_IN_USE=1
    ensure_hosts_control "in\\.ftpd|ftpd|vsftpd" "in.ftpd"
    NEEDS_MANUAL=1
fi

# 최종 상태 결정
if [ "$FTP_IN_USE" -eq 0 ]; then
    ACTION_RESULT="SUCCESS"
    STATUS="PASS"
    EVIDENCE="FTP 서비스가 비활성화되어 조치 대상이 없습니다."
    ACTION_LOG="FTP 서비스 미사용 상태입니다."
elif [ "$NEEDS_MANUAL" -eq 1 ]; then
    ACTION_RESULT="MANUAL"
    STATUS="MANUAL"
    EVIDENCE="FTP 접근 제어 설정에 수동 검토가 필요합니다."
    ACTION_LOG="$ACTION_LOG 허용할 운영 IP/호스트를 반영하도록 수동 검토가 필요합니다."
else
    ACTION_RESULT="SUCCESS"
    STATUS="PASS"
    EVIDENCE="FTP 접근 제어 설정이 적용되었습니다."
    [ -z "$ACTION_LOG" ] && ACTION_LOG="FTP 접근 제어 설정이 이미 적절합니다."
fi

# 3. 마스터 템플릿 표준 출력
echo ""
cat << EOF_JSON
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "FTP 서비스를 사용하는 경우 허용할 IP/호스트를 명시한 접근 제어 정책(ftpusers/user_list/Limit LOGIN/hosts.allow/hosts.deny)을 적용해야 합니다.",
    "action_result": "$ACTION_RESULT",
    "action_log": "$ACTION_LOG",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF_JSON
