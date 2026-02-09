#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-07
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-62
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 하
# @Title : 로그인 시 경고 메시지 설정
# @Description : 서버 및 서비스에 로그온 시 불필요한 정보 차단 설정 및 불법적인 사용에 대한 경고 메시지 출력 여부 점검
# @Criteria_Good : 서버 및 Telnet, FTP, SMTP, DNS 서비스에 로그온 시 경고 메시지가 설정된 경우
# @Criteria_Bad : 서버 및 Telnet, FTP, SMTP, DNS 서비스에 로그온 시 경고 메시지가 설정되어 있지 않은 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-62 로그인 시 경고 메시지 설정

# 1. 항목 정보 정의
ID="U-62"
CATEGORY="서비스 관리"
TITLE="로그인 시 경고 메시지 설정"
IMPORTANCE="하"
TARGET_FILE="/etc/motd"

# 2. 진단 로직 (무결성 해시 포함)
STATUS="PASS"
EVIDENCE=""
FILE_HASH="NOT_FOUND"

VULNERABLE=0

# [서버] /etc/motd, /etc/issue 확인
for file in "/etc/motd" "/etc/issue"; do
    if [ -f "$file" ]; then
        CONTENT=$(cat "$file" 2>/dev/null | tr -d '[:space:]')
        if [ -z "$CONTENT" ]; then
            VULNERABLE=1
            EVIDENCE="$EVIDENCE $file 경고 메시지 없음;"
        else
            EVIDENCE="$EVIDENCE $file 경고 메시지 존재;"
        fi
    fi
done

# [Telnet] /etc/issue.net 확인
# 가이드: /etc/issue.net 파일 내에 로그온 경고 메시지 수정
if [ -f "/etc/issue.net" ]; then
    CONTENT=$(cat "/etc/issue.net" 2>/dev/null | tr -d '[:space:]')
    if [ -z "$CONTENT" ]; then
        VULNERABLE=1
        EVIDENCE="$EVIDENCE /etc/issue.net 경고 메시지 없음;"
    else
        EVIDENCE="$EVIDENCE /etc/issue.net 경고 메시지 존재;"
    fi
fi

# [SSH] /etc/ssh/sshd_config Banner 설정 확인
# 가이드: systemctl list-units --type=service | grep sshd
if systemctl list-units --type=service 2>/dev/null | grep -q sshd; then
    SSH_CONF="/etc/ssh/sshd_config"
    if [ -f "$SSH_CONF" ]; then
        BANNER=$(grep -v "^#" "$SSH_CONF" | grep -i "^Banner")
        if [ -z "$BANNER" ]; then
            VULNERABLE=1
            EVIDENCE="$EVIDENCE SSH Banner 설정 없음;"
        else
            EVIDENCE="$EVIDENCE SSH $BANNER;"
        fi
    fi
fi

# [Sendmail] SmtpGreetingMessage 확인
# 가이드: systemctl list-units --type=service | grep sendmail
if systemctl list-units --type=service 2>/dev/null | grep -q sendmail; then
    CONF="/etc/mail/sendmail.cf"
    if [ -f "$CONF" ]; then
        GREETING=$(grep -v "^#" "$CONF" | grep "SmtpGreetingMessage")
        if [ -z "$GREETING" ]; then
            VULNERABLE=1
            EVIDENCE="$EVIDENCE Sendmail SmtpGreetingMessage 없음;"
        fi
    fi
fi

# [Postfix] smtpd_banner 확인
# 가이드: systemctl list-units --type=service | grep postfix
if systemctl list-units --type=service 2>/dev/null | grep -q postfix; then
    CONF="/etc/postfix/main.cf"
    if [ -f "$CONF" ]; then
        BANNER=$(grep -v "^#" "$CONF" | grep "smtpd_banner")
        if [ -z "$BANNER" ]; then
            VULNERABLE=1
            EVIDENCE="$EVIDENCE Postfix smtpd_banner 없음;"
        fi
    fi
fi

# [vsFTP] ftpd_banner 확인
# 가이드: systemctl list-units --type=service | grep vsftpd
if systemctl list-units --type=service 2>/dev/null | grep -q vsftpd; then
    CONF="/etc/vsftpd/vsftpd.conf"
    [ ! -f "$CONF" ] && CONF="/etc/vsftpd.conf"
    if [ -f "$CONF" ]; then
        BANNER=$(grep -v "^#" "$CONF" | grep "ftpd_banner")
        if [ -z "$BANNER" ]; then
            VULNERABLE=1
            EVIDENCE="$EVIDENCE vsFTPd ftpd_banner 없음;"
        fi
    fi
fi

# [ProFTP] DisplayLogin 확인
# 가이드: systemctl list-units --type=service | grep proftpd
if systemctl list-units --type=service 2>/dev/null | grep -q proftpd; then
    CONF="/etc/proftpd/proftpd.conf"
    [ ! -f "$CONF" ] && CONF="/etc/proftpd.conf"
    if [ -f "$CONF" ]; then
        DISPLAY=$(grep -v "^#" "$CONF" | grep -i "DisplayLogin")
        if [ -z "$DISPLAY" ]; then
            VULNERABLE=1
            EVIDENCE="$EVIDENCE ProFTP DisplayLogin 없음;"
        else
            EVIDENCE="$EVIDENCE ProFTP $DISPLAY;"
        fi
    fi
fi

# [Exim] smtp_banner 확인
# 가이드: systemctl list-units --type=service | grep exim
if systemctl list-units --type=service 2>/dev/null | grep -q exim; then
    CONF="/etc/exim/exim.conf"
    [ ! -f "$CONF" ] && CONF="/etc/exim4/exim4.conf"
    if [ -f "$CONF" ]; then
        BANNER=$(grep -v "^#" "$CONF" | grep "smtp_banner")
        if [ -z "$BANNER" ]; then
            VULNERABLE=1
            EVIDENCE="$EVIDENCE Exim smtp_banner 없음;"
        fi
    fi
fi

# [DNS] version 확인
# 가이드: systemctl list-units --type=service | grep named
if systemctl list-units --type=service 2>/dev/null | grep -q named; then
    CONF="/etc/named.conf"
    if [ -f "$CONF" ]; then
        VERSION=$(grep -v "^#" "$CONF" | grep "version")
        if [ -z "$VERSION" ]; then
            VULNERABLE=1
            EVIDENCE="$EVIDENCE DNS version 설정 없음;"
        fi
    fi
fi

if [ $VULNERABLE -eq 1 ]; then
    STATUS="FAIL"
    EVIDENCE="로그온 경고 메시지 미설정: $EVIDENCE"
else
    STATUS="PASS"
    EVIDENCE="로그온 경고 메시지 설정됨"
fi


IMPACT_LEVEL="LOW"
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없으나, SNMP 로그가 활성화되면 로그 저장량이 증가하여 저장 공간 및 로그 관리 정책에 영향을 줄 수 있으므로 적용 전 로그 보관 주기와 저장 경로, 용량 관리 기준을 확인한 뒤 로그 설정을 반영해야 합니다"

# 3. 마스터 템플릿 표준 출력
echo ""
cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "/etc/issue, /etc/motd에 경고 메시지 설정, sshd_config에 Banner /etc/issue.net 설정 후 서비스 재시작하세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
