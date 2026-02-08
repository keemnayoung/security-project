#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-07
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-62
# @Category : 서비스 관리
# @Platform : Rocky Linux 9
# @Importance : 하
# @Title : 로그온 경고 메시지 설정
# @Description : 서비스별 로그온 시 경고 메시지 설정
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-62 로그온 경고 메시지 설정

# 1. 항목 정보 정의
ID="U-62"
CATEGORY="서비스관리"
TITLE="로그온 경고 메시지 설정"
IMPORTANCE="하"
TARGET_FILE="/etc/motd"

# 2. 보완 로직
ACTION_RESULT="SUCCESS"
BEFORE_SETTING=""
AFTER_SETTING=""
ACTION_LOG=""

# 경고 메시지 템플릿
WARNING_MSG="***************************************************************
* WARNING: Unauthorized access to this system is prohibited. *
* All activities are monitored and logged.                    *
***************************************************************"

# [서버] /etc/motd, /etc/issue 설정
for file in "/etc/motd" "/etc/issue" "/etc/issue.net"; do
    if [ -f "$file" ]; then
        CONTENT=$(cat "$file" 2>/dev/null | tr -d '[:space:]')
        if [ -z "$CONTENT" ]; then
            BEFORE_SETTING="$BEFORE_SETTING $file 비어있음;"
            echo "$WARNING_MSG" > "$file"
            ACTION_LOG="$ACTION_LOG $file 경고 메시지 추가;"
        fi
    else
        echo "$WARNING_MSG" > "$file"
        ACTION_LOG="$ACTION_LOG $file 생성 및 경고 메시지 추가;"
    fi
done

# [SSH] Banner 설정
# 가이드: systemctl list-units --type=service | grep sshd
if systemctl list-units --type=service 2>/dev/null | grep -q sshd; then
    SSH_CONF="/etc/ssh/sshd_config"
    if [ -f "$SSH_CONF" ]; then
        if ! grep -v "^#" "$SSH_CONF" | grep -q "^Banner"; then
            BEFORE_SETTING="$BEFORE_SETTING SSH Banner 없음;"
            echo "Banner /etc/issue.net" >> "$SSH_CONF"
            systemctl restart sshd 2>/dev/null
            ACTION_LOG="$ACTION_LOG SSH Banner /etc/issue.net 설정 및 재시작;"
        fi
    fi
fi

# [Sendmail] SmtpGreetingMessage 설정
# 가이드: systemctl list-units --type=service | grep sendmail
if systemctl list-units --type=service 2>/dev/null | grep -q sendmail; then
    CONF="/etc/mail/sendmail.cf"
    if [ -f "$CONF" ]; then
        if ! grep -v "^#" "$CONF" | grep -q "SmtpGreetingMessage"; then
            echo "O SmtpGreetingMessage=Mail Server Ready" >> "$CONF"
            systemctl restart sendmail 2>/dev/null
            ACTION_LOG="$ACTION_LOG Sendmail SmtpGreetingMessage 설정;"
        fi
    fi
fi

# [Postfix] smtpd_banner 설정
# 가이드: systemctl list-units --type=service | grep postfix
if systemctl list-units --type=service 2>/dev/null | grep -q postfix; then
    CONF="/etc/postfix/main.cf"
    if [ -f "$CONF" ]; then
        if ! grep -v "^#" "$CONF" | grep -q "smtpd_banner"; then
            echo 'smtpd_banner = $myhostname ESMTP' >> "$CONF"
            systemctl restart postfix 2>/dev/null
            ACTION_LOG="$ACTION_LOG Postfix smtpd_banner 설정;"
        fi
    fi
fi

# [vsFTP] ftpd_banner 설정
# 가이드: systemctl list-units --type=service | grep vsftpd
if systemctl list-units --type=service 2>/dev/null | grep -q vsftpd; then
    CONF="/etc/vsftpd/vsftpd.conf"
    [ ! -f "$CONF" ] && CONF="/etc/vsftpd.conf"
    if [ -f "$CONF" ]; then
        if ! grep -v "^#" "$CONF" | grep -q "ftpd_banner"; then
            echo "ftpd_banner=Welcome to FTP service." >> "$CONF"
            systemctl restart vsftpd 2>/dev/null
            ACTION_LOG="$ACTION_LOG vsFTPd ftpd_banner 설정;"
        fi
    fi
fi

# [ProFTP] DisplayLogin 설정
# 가이드: systemctl list-units --type=service | grep proftpd
if systemctl list-units --type=service 2>/dev/null | grep -q proftpd; then
    CONF="/etc/proftpd/proftpd.conf"
    [ ! -f "$CONF" ] && CONF="/etc/proftpd.conf"
    if [ -f "$CONF" ]; then
        if ! grep -v "^#" "$CONF" | grep -qi "DisplayLogin"; then
            # welcome.msg 파일 생성
            echo "$WARNING_MSG" > "/etc/proftpd/welcome.msg"
            echo "DisplayLogin /etc/proftpd/welcome.msg" >> "$CONF"
            systemctl restart proftpd 2>/dev/null
            ACTION_LOG="$ACTION_LOG ProFTP DisplayLogin 설정;"
        fi
    fi
fi

# [Exim] smtp_banner 설정
# 가이드: systemctl list-units --type=service | grep exim
if systemctl list-units --type=service 2>/dev/null | grep -q exim; then
    CONF="/etc/exim/exim.conf"
    [ ! -f "$CONF" ] && CONF="/etc/exim4/exim4.conf"
    if [ -f "$CONF" ]; then
        if ! grep -v "^#" "$CONF" | grep -q "smtp_banner"; then
            echo 'smtp_banner = $primary_hostname ESMTP' >> "$CONF"
            systemctl restart exim 2>/dev/null || systemctl restart exim4 2>/dev/null
            ACTION_LOG="$ACTION_LOG Exim smtp_banner 설정;"
        fi
    fi
fi

# [DNS] version 설정
# 가이드: systemctl list-units --type=service | grep named
if systemctl list-units --type=service 2>/dev/null | grep -q named; then
    CONF="/etc/named.conf"
    if [ -f "$CONF" ]; then
        if ! grep -v "^#" "$CONF" | grep -q "version"; then
            # options 블록 안에 추가
            if grep -q "^options" "$CONF"; then
                sed -i '/^options\s*{/a \\tversion "none";' "$CONF"
                systemctl restart named 2>/dev/null
                ACTION_LOG="$ACTION_LOG DNS version 설정;"
            fi
        fi
    fi
fi

AFTER_SETTING="로그온 경고 메시지 설정 완료"
[ -z "$ACTION_LOG" ] && ACTION_LOG="이미 설정되어 있음"

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
