#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.2.0
# @Author: 이가영
# @Last Updated: 2026-02-14
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

set -u

ID="U-56"
CATEGORY="서비스 관리"
TITLE="FTP 서비스 접근 제어 설정"
IMPORTANCE="하"
TARGET_FILE="N/A"

ACTION_RESULT="SUCCESS"
ACTION_LOG=""
STATUS="PASS"
EVIDENCE="취약점 조치가 완료되었습니다."
GUIDE="FTP 서비스를 사용하는 경우 허용할 IP/호스트를 명시한 접근 제어 정책(tcp_wrappers/hosts.allow/hosts.deny 또는 proftpd <Limit LOGIN>)을 적용해야 합니다."

FTP_IN_USE=0
NEEDS_MANUAL=0
LOCAL_ONLY_TEMPLATE=0

append_log() {
    local msg="$1"
    [ -z "$msg" ] && return 0
    if [ -n "$ACTION_LOG" ]; then
        ACTION_LOG="$ACTION_LOG; $msg"
    else
        ACTION_LOG="$msg"
    fi
}

json_escape() {
    echo "$1" | tr '\n\r\t' '   ' | sed 's/\\/\\\\/g; s/"/\\"/g'
}

has_non_comment_match() {
    local file="$1"
    local pattern="$2"
    grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$file" 2>/dev/null | grep -qE "$pattern"
}

ensure_owner_perm() {
    local file="$1"
    local owner="$2"
    local perm="$3"
    [ -f "$file" ] || return 0
    chown "$owner" "$file" 2>/dev/null || true
    chmod "$perm" "$file" 2>/dev/null || true
}

is_named_running() {
    systemctl list-units --type=service 2>/dev/null | grep -qE '\b(vsftpd|proftpd|named)(\.service)?\b' && return 0
    return 0
}

ensure_hosts_control() {
    local daemon_regex="$1"
    local daemon_label="$2"

    [ -f "/etc/hosts.allow" ] || touch "/etc/hosts.allow"
    [ -f "/etc/hosts.deny" ] || touch "/etc/hosts.deny"

    ensure_owner_perm "/etc/hosts.allow" root 644
    ensure_owner_perm "/etc/hosts.deny" root 644

    if ! has_non_comment_match "/etc/hosts.allow" "^(${daemon_regex})[[:space:]]*:"; then
        echo "${daemon_label}: 127.0.0.1" >> /etc/hosts.allow
        append_log "/etc/hosts.allow에 ${daemon_label}:127.0.0.1 예시를 추가했습니다."
        NEEDS_MANUAL=1
        LOCAL_ONLY_TEMPLATE=1
    fi

    if ! has_non_comment_match "/etc/hosts.deny" '^ALL[[:space:]]*:[[:space:]]*ALL'; then
        echo "ALL: ALL" >> /etc/hosts.deny
        append_log "/etc/hosts.deny에 ALL:ALL 기본 차단 정책을 추가했습니다."
    fi
}

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    STATUS="FAIL"
    ACTION_RESULT="FAIL"
    EVIDENCE="root 권한으로 실행해야 조치가 가능합니다."
    ACTION_LOG="권한 부족으로 조치를 수행하지 못했습니다."
else
    # vsftpd
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
            append_log "vsftpd 설정에 tcp_wrappers=YES를 적용했습니다."

            ensure_hosts_control "vsftpd|in\\.ftpd" "vsftpd"

            systemctl restart vsftpd 2>/dev/null || true
        else
            NEEDS_MANUAL=1
            append_log "vsftpd 설정 파일을 찾지 못해 수동 확인이 필요합니다."
        fi
    fi

    # proftpd
    PROFTPD_CONF=""
    if [ -f "/etc/proftpd/proftpd.conf" ]; then
        PROFTPD_CONF="/etc/proftpd/proftpd.conf"
    elif [ -f "/etc/proftpd.conf" ]; then
        PROFTPD_CONF="/etc/proftpd.conf"
    fi

    if command -v proftpd >/dev/null 2>&1 || [ -n "$PROFTPD_CONF" ] || systemctl list-units --type=service 2>/dev/null | grep -q proftpd; then
        FTP_IN_USE=1
        if [ -n "$PROFTPD_CONF" ]; then
            TARGET_FILE="$PROFTPD_CONF"
            ensure_owner_perm "$PROFTPD_CONF" root 640

            USE_FTPUSERS="$(grep -Ei '^[[:space:]]*UseFtpUsers' "$PROFTPD_CONF" 2>/dev/null | tail -n1 | awk '{print tolower($2)}')"
            [ -z "$USE_FTPUSERS" ] && USE_FTPUSERS="on"

            if [ "$USE_FTPUSERS" = "off" ]; then
                LIMIT_LOGIN="$(sed -n '/<Limit LOGIN>/,/<\\/Limit>/p' "$PROFTPD_CONF" 2>/dev/null)"
                if [ -z "$LIMIT_LOGIN" ] || ! echo "$LIMIT_LOGIN" | grep -qiE 'Allow[[:space:]]+from|Deny[[:space:]]+from|AllowUser|DenyUser'; then
                    cat >> "$PROFTPD_CONF" <<'LIMIT_EOF'

<Limit LOGIN>
    Order Deny,Allow
    Allow from 127.0.0.1
    Deny from all
</Limit>
LIMIT_EOF
                    append_log "proftpd 설정에 <Limit LOGIN> 기본 템플릿을 추가했습니다."
                    NEEDS_MANUAL=1
                    LOCAL_ONLY_TEMPLATE=1
                fi
            fi

            systemctl restart proftpd 2>/dev/null || true
        else
            NEEDS_MANUAL=1
            append_log "proftpd 설정 파일을 찾지 못해 수동 확인이 필요합니다."
        fi
    fi

    # inetd/xinetd 기반 FTP
    if [ -f "/etc/inetd.conf" ] && has_non_comment_match "/etc/inetd.conf" '^[[:space:]]*ftp([[:space:]]|$)'; then
        FTP_IN_USE=1
        TARGET_FILE="/etc/inetd.conf"
        ensure_hosts_control "in\\.ftpd|ftpd" "in.ftpd"
        NEEDS_MANUAL=1
    fi

    if [ -f "/etc/xinetd.d/ftp" ] && has_non_comment_match "/etc/xinetd.d/ftp" '^[[:space:]]*disable[[:space:]]*=[[:space:]]*no'; then
        FTP_IN_USE=1
        TARGET_FILE="/etc/xinetd.d/ftp"
        ensure_hosts_control "in\\.ftpd|ftpd|vsftpd" "in.ftpd"
        NEEDS_MANUAL=1
    fi

    if [ "$FTP_IN_USE" -eq 0 ]; then
        STATUS="PASS"
        ACTION_RESULT="SUCCESS"
        EVIDENCE="FTP 서비스가 비활성화되어 조치 대상이 없습니다."
        ACTION_LOG="FTP 서비스 미사용 상태입니다."
        GUIDE="FTP 미사용 환경은 서비스를 비활성화 상태로 유지해야 합니다."
    elif [ "$NEEDS_MANUAL" -eq 1 ]; then
        STATUS="MANUAL"
        ACTION_RESULT="MANUAL_REQUIRED"
        EVIDENCE="FTP 접근 제어 설정에 수동 검토가 필요합니다."
        append_log "운영에서 허용할 IP/호스트를 반영하도록 수동 검토가 필요합니다."
    else
        STATUS="PASS"
        ACTION_RESULT="SUCCESS"
        EVIDENCE="FTP 접근 제어 설정이 적용되었습니다."
        [ -z "$ACTION_LOG" ] && ACTION_LOG="FTP 접근 제어 설정이 이미 적절합니다."
    fi

    if [ "$LOCAL_ONLY_TEMPLATE" -eq 1 ]; then
        append_log "로컬(127.0.0.1) 예시를 추가했으므로 운영 허용 IP/호스트가 있으면 실제 값으로 조정해야 합니다."
        GUIDE="$GUIDE 기본값은 로컬(127.0.0.1) 예시이며, 운영 허용 IP/호스트가 있으면 실제 값으로 조정해야 합니다."
    fi
fi

IMPACT_LEVEL="HIGH"
ACTION_IMPACT="FTP 접근 제어를 강화하면 허용 목록 외 IP/호스트의 접속이 차단될 수 있으므로 운영에 필요한 접속 주체를 사전에 식별한 뒤 정책을 반영해야 합니다."

EVIDENCE="$(json_escape "$EVIDENCE")"
GUIDE="$(json_escape "$GUIDE")"
ACTION_LOG="$(json_escape "$ACTION_LOG")"

echo ""
cat << EOF_JSON
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "$GUIDE",
    "action_result": "$ACTION_RESULT",
    "action_log": "$ACTION_LOG",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF_JSON

