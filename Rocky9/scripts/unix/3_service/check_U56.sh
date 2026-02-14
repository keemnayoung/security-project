#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.2.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-56
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 하
# @Title : FTP 서비스 접근 제어 설정
# @Description : FTP 서비스 접근 제어(hosts.allow/hosts.deny 등) 설정 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-56"
CATEGORY="서비스 관리"
TITLE="FTP 서비스 접근 제어 설정"
IMPORTANCE="하"
TARGET_FILE="N/A"

STATUS="PASS"
EVIDENCE=""
FILE_HASH="NOT_FOUND"
GUIDE=""

VULNERABLE=0
FTP_IN_USE=0

append_evidence() {
    local msg="$1"
    [ -z "$msg" ] && return 0
    if [ -n "$EVIDENCE" ]; then
        EVIDENCE="$EVIDENCE; $msg"
    else
        EVIDENCE="$msg"
    fi
}

set_target_file_once() {
    local f="$1"
    if [ -f "$f" ] && [ "$TARGET_FILE" = "N/A" ]; then
        TARGET_FILE="$f"
        FILE_HASH=$(sha256sum "$f" 2>/dev/null | awk '{print $1}')
    fi
}

has_non_comment_match() {
    local file="$1"
    local pattern="$2"
    grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$file" 2>/dev/null | grep -qE "$pattern"
}

check_owner_perm() {
    local file="$1"
    local max_perm="$2"
    local label="$3"

    if [ ! -f "$file" ]; then
        VULNERABLE=1
        append_evidence "${label} 파일이 존재하지 않습니다(${file})."
        return
    fi

    local owner perms
    owner="$(stat -c '%U' "$file" 2>/dev/null || true)"
    perms="$(stat -c '%a' "$file" 2>/dev/null || true)"

    if [ "$owner" != "root" ]; then
        VULNERABLE=1
        append_evidence "${label} 파일 소유자가 root가 아닙니다(현재: ${owner})."
    fi

    if [ -n "$perms" ] && [ "$perms" -gt "$max_perm" ]; then
        VULNERABLE=1
        append_evidence "${label} 파일 권한이 과대합니다(현재: ${perms}, 기준: ${max_perm} 이하)."
    fi
}

check_hosts_control() {
    local daemon_regex="$1"
    local label="$2"
    local allow_ok=0
    local deny_ok=0

    if [ -f "/etc/hosts.allow" ] && has_non_comment_match "/etc/hosts.allow" "^(${daemon_regex})[[:space:]]*:"; then
        allow_ok=1
    fi

    if [ -f "/etc/hosts.deny" ] && has_non_comment_match "/etc/hosts.deny" "^(ALL[[:space:]]*:[[:space:]]*ALL|(${daemon_regex})[[:space:]]*:[[:space:]]*ALL)"; then
        deny_ok=1
    fi

    if [ "$allow_ok" -eq 0 ] || [ "$deny_ok" -eq 0 ]; then
        VULNERABLE=1
        append_evidence "${label} 접근 제어(hosts.allow/hosts.deny) 설정이 미흡합니다."
    fi
}

is_named_unit_active() {
    systemctl list-units --type=service 2>/dev/null | grep -q "$1"
}

# ----------------------------------------------------------------------------
# vsftpd
# ----------------------------------------------------------------------------
VSFTPD_CONF=""
if [ -f "/etc/vsftpd.conf" ]; then
    VSFTPD_CONF="/etc/vsftpd.conf"
elif [ -f "/etc/vsftpd/vsftpd.conf" ]; then
    VSFTPD_CONF="/etc/vsftpd/vsftpd.conf"
fi

if command -v vsftpd >/dev/null 2>&1 || [ -n "$VSFTPD_CONF" ] || systemctl list-units --type=service 2>/dev/null | grep -q vsftpd; then
    FTP_IN_USE=1

    if [ -n "$VSFTPD_CONF" ]; then
        set_target_file_once "$VSFTPD_CONF"

        if ! has_non_comment_match "$VSFTPD_CONF" '^tcp_wrappers[[:space:]]*=[[:space:]]*YES'; then
            VULNERABLE=1
            append_evidence "vsftpd 설정에서 tcp_wrappers=YES가 설정되어 있지 않습니다."
        fi

        check_hosts_control "vsftpd|in\\.ftpd" "vsftpd"

        if has_non_comment_match "$VSFTPD_CONF" '^userlist_enable[[:space:]]*=[[:space:]]*YES'; then
            USERLIST_FILE="/etc/vsftpd.user_list"
            [ ! -f "$USERLIST_FILE" ] && USERLIST_FILE="/etc/vsftpd/user_list"
            check_owner_perm "$USERLIST_FILE" 640 "vsftpd user_list"
        else
            FTPUSERS_FILE="/etc/vsftpd.ftpusers"
            [ ! -f "$FTPUSERS_FILE" ] && FTPUSERS_FILE="/etc/vsftpd/ftpusers"
            [ ! -f "$FTPUSERS_FILE" ] && FTPUSERS_FILE="/etc/ftpusers"
            check_owner_perm "$FTPUSERS_FILE" 640 "vsftpd ftpusers"
        fi
    else
        VULNERABLE=1
        append_evidence "vsftpd 설정 파일을 찾지 못했습니다."
    fi
fi

# ----------------------------------------------------------------------------
# proftpd
# ----------------------------------------------------------------------------
PROFTPD_CONF=""
if [ -f "/etc/proftpd/proftpd.conf" ]; then
    PROFTPD_CONF="/etc/proftpd/proftpd.conf"
elif [ -f "/etc/proftpd.conf" ]; then
    PROFTPD_CONF="/etc/proftpd.conf"
fi

if command -v proftpd >/dev/null 2>&1 || [ -n "$PROFTPD_CONF" ] || systemctl list-units --type=service 2>/dev/null | grep -q proftpd; then
    FTP_IN_USE=1

    if [ -n "$PROFTPD_CONF" ]; then
        set_target_file_once "$PROFTPD_CONF"
        check_owner_perm "$PROFTPD_CONF" 640 "proftpd.conf"

        USE_FTPUSERS="$(grep -Ei '^[[:space:]]*UseFtpUsers' "$PROFTPD_CONF" 2>/dev/null | tail -n1 | awk '{print tolower($2)}')"
        if [ -z "$USE_FTPUSERS" ]; then
            USE_FTPUSERS="on"
        fi

        if [ "$USE_FTPUSERS" = "off" ]; then
            LIMIT_LOGIN="$(sed -n '/<Limit LOGIN>/,/<\\/Limit>/p' "$PROFTPD_CONF" 2>/dev/null)"
            if [ -z "$LIMIT_LOGIN" ] || ! echo "$LIMIT_LOGIN" | grep -qiE 'Allow[[:space:]]+from|Deny[[:space:]]+from|AllowUser|DenyUser'; then
                VULNERABLE=1
                append_evidence "proftpd <Limit LOGIN> 접근 제어 설정이 미흡합니다."
            fi
        else
            FTPUSERS_FILE="/etc/ftpusers"
            [ ! -f "$FTPUSERS_FILE" ] && FTPUSERS_FILE="/etc/ftpd/ftpusers"
            check_owner_perm "$FTPUSERS_FILE" 640 "proftpd ftpusers"
        fi
    else
        VULNERABLE=1
        append_evidence "proftpd 설정 파일을 찾지 못했습니다."
    fi
fi

# ----------------------------------------------------------------------------
# inetd/xinetd 기반 FTP
# ----------------------------------------------------------------------------
if [ -f "/etc/inetd.conf" ] && has_non_comment_match "/etc/inetd.conf" '^[[:space:]]*ftp([[:space:]]|$)'; then
    FTP_IN_USE=1
    set_target_file_once "/etc/inetd.conf"
    check_hosts_control "in\\.ftpd|ftpd" "inetd 기반 FTP"
fi

if [ -f "/etc/xinetd.d/ftp" ] && has_non_comment_match "/etc/xinetd.d/ftp" '^[[:space:]]*disable[[:space:]]*=[[:space:]]*no'; then
    FTP_IN_USE=1
    set_target_file_once "/etc/xinetd.d/ftp"
    check_hosts_control "in\\.ftpd|ftpd|vsftpd" "xinetd 기반 FTP"
fi

# ----------------------------------------------------------------------------
# 최종 판정
# ----------------------------------------------------------------------------
if [ "$FTP_IN_USE" -eq 0 ]; then
    STATUS="PASS"
    EVIDENCE="FTP 서비스가 비활성화되어 점검 대상이 없습니다."
    GUIDE="FTP 미사용 환경은 서비스를 비활성화 상태로 유지해야 합니다."
elif [ "$VULNERABLE" -eq 1 ]; then
    STATUS="FAIL"
    EVIDENCE="FTP 서비스 접근 제어 설정이 미흡하여 비인가 접속 위험이 있습니다. $EVIDENCE"
    GUIDE="FTP 서비스를 사용하는 경우 tcp_wrappers/hosts.allow/hosts.deny 또는 proftpd <Limit LOGIN>을 통해 허용할 IP/호스트만 접속 가능하도록 설정해야 합니다."
else
    STATUS="PASS"
    EVIDENCE="FTP 서비스 접근 제어가 설정되어 있습니다."
    GUIDE="현재 접근 제어 정책을 유지하고 허용 IP/호스트 변경 시 동일 기준으로 반영해야 합니다."
fi

EVIDENCE=$(echo "$EVIDENCE" | tr '\n\r\t' '   ' | sed 's/\\/\\\\/g; s/"/\\"/g')
GUIDE=$(echo "$GUIDE" | tr '\n\r\t' '   ' | sed 's/\\/\\\\/g; s/"/\\"/g')

IMPACT_LEVEL="HIGH"
ACTION_IMPACT="FTP 접근 제어를 강화하면 허용 목록 외 IP/호스트의 접속이 차단될 수 있으므로 운영에 필요한 접속 주체를 사전에 식별한 뒤 정책을 반영해야 합니다."

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
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF_JSON

