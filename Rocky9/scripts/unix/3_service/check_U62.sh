#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.0
# @Author: 이가영
# @Last Updated: 2026-02-16
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


# 기본 변수
ID="U-62"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

REASON_LINE=""
DETAIL_LINES=""
TARGET_FILE="/etc/issue, /etc/motd, /etc/issue.net, /etc/ssh/sshd_config, (서비스별 설정파일)"
CHECK_COMMAND='
ls -l /etc/issue /etc/issue.net /etc/motd 2>/dev/null;
wc -c /etc/issue /etc/issue.net /etc/motd 2>/dev/null;
grep -nEi "^[[:space:]]*Banner[[:space:]]+" /etc/ssh/sshd_config 2>/dev/null;
systemctl is-active sshd 2>/dev/null;
systemctl is-active vsftpd proftpd postfix sendmail exim named 2>/dev/null;
grep -nEi "^[[:space:]]*ftpd_banner[[:space:]]*=" /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null;
grep -nEi "^[[:space:]]*DisplayLogin[[:space:]]+" /etc/proftpd.conf /etc/proftpd/proftpd.conf 2>/dev/null;
grep -nEi "^[[:space:]]*smtpd_banner[[:space:]]*=" /etc/postfix/main.cf 2>/dev/null;
grep -nEi "^[[:space:]]*SmtpGreetingMessage" /etc/mail/sendmail.cf 2>/dev/null;
grep -nEi "^[[:space:]]*smtp_banner[[:space:]]*=" /etc/exim/exim.conf /etc/exim4/exim4.conf 2>/dev/null;
grep -nEi "^[[:space:]]*version[[:space:]]+" /etc/named.conf /etc/bind/named.conf.options 2>/dev/null;
( [ -f /etc/xinetd.d/telnet ] && grep -nEv "^[[:space:]]*#|^[[:space:]]*$" /etc/xinetd.d/telnet | head -n 80 ) 2>/dev/null;
( [ -f /etc/inetd.conf ] && grep -nEv "^[[:space:]]*#|^[[:space:]]*$" /etc/inetd.conf | grep -nEi "^[[:space:]]*telnet([[:space:]]|$)" ) 2>/dev/null
'

append_detail(){ [ -n "${1:-}" ] && DETAIL_LINES="${DETAIL_LINES}${DETAIL_LINES:+\\n}$1"; }

has_content() { # 공백/주석 제외 실내용 존재 여부
  [ -f "$1" ] || return 1
  grep -Ev '^[[:space:]]*$|^[[:space:]]*#' "$1" 2>/dev/null | tr -d '[:space:]' | grep -q .
}

svc_active(){ systemctl is-active --quiet "$1" 2>/dev/null; }

grep_uc_last(){ # uncommented last match
  local f="$1" r="$2"
  [ -f "$f" ] || return 1
  grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$f" 2>/dev/null | grep -Ei "$r" | tail -n 1
}

VULN=0

# 1) 서버(로컬) 로그인 경고(/etc/issue 또는 /etc/motd 중 1개 이상)
LOCAL_OK=0
if has_content /etc/issue; then append_detail "[server] /etc/issue=HAS_WARNING_MESSAGE"; LOCAL_OK=1
else append_detail "[server] /etc/issue=EMPTY_OR_NOT_FOUND"; fi

if has_content /etc/motd; then append_detail "[server] /etc/motd=HAS_WARNING_MESSAGE"; LOCAL_OK=1
else append_detail "[server] /etc/motd=EMPTY_OR_NOT_FOUND"; fi

[ "$LOCAL_OK" -eq 1 ] || { VULN=1; append_detail "[result] local_warning=NOT_SET"; }

# 2) SSH 사용 시 Banner 설정 확인
if svc_active sshd; then
  BLINE="$(grep_uc_last /etc/ssh/sshd_config '^[[:space:]]*Banner[[:space:]]+')"
  if [ -z "${BLINE:-}" ]; then VULN=1; append_detail "[ssh] sshd_active=Y, Banner=NOT_SET"
  elif echo "$BLINE" | grep -qiE '^[[:space:]]*Banner[[:space:]]+none([[:space:]]|$)'; then VULN=1; append_detail "[ssh] sshd_active=Y, Banner=none(NOT_SET)"
  else append_detail "[ssh] sshd_active=Y, $BLINE"; fi
else
  append_detail "[ssh] sshd_active=N"
fi

# 3) Telnet 사용 시(/etc/xinetd.d/telnet 또는 /etc/inetd.conf) /etc/issue.net 필요
TELNET_USED=0
if [ -f /etc/xinetd.d/telnet ]; then
  if grep -Ev '^[[:space:]]*#|^[[:space:]]*$' /etc/xinetd.d/telnet 2>/dev/null | grep -qiE '^[[:space:]]*disable[[:space:]]*=[[:space:]]*no'; then TELNET_USED=1; fi
fi
if [ -f /etc/inetd.conf ] && grep -Ev '^[[:space:]]*#|^[[:space:]]*$' /etc/inetd.conf 2>/dev/null | grep -qiE '^[[:space:]]*telnet([[:space:]]|$)'; then TELNET_USED=1; fi

if [ "$TELNET_USED" -eq 1 ]; then
  if has_content /etc/issue.net; then append_detail "[telnet] used=Y, /etc/issue.net=HAS_WARNING_MESSAGE"
  else VULN=1; append_detail "[telnet] used=Y, /etc/issue.net=EMPTY_OR_NOT_FOUND"; fi
else
  append_detail "[telnet] used=N"
fi

# 4) FTP 사용 시 배너(vsftpd/proftpd)
if svc_active vsftpd; then
  VCONF=""
  [ -f /etc/vsftpd.conf ] && VCONF="/etc/vsftpd.conf"
  [ -z "$VCONF" ] && [ -f /etc/vsftpd/vsftpd.conf ] && VCONF="/etc/vsftpd/vsftpd.conf"
  VLINE="$( [ -n "$VCONF" ] && grep_uc_last "$VCONF" '^[[:space:]]*ftpd_banner[[:space:]]*=' )"
  if [ -n "${VLINE:-}" ]; then append_detail "[ftp] vsftpd_active=Y, $VCONF: $VLINE"
  else VULN=1; append_detail "[ftp] vsftpd_active=Y, ftpd_banner=NOT_SET($VCONF)"; fi
else
  append_detail "[ftp] vsftpd_active=N"
fi

if svc_active proftpd; then
  PCONF=""
  [ -f /etc/proftpd.conf ] && PCONF="/etc/proftpd.conf"
  [ -z "$PCONF" ] && [ -f /etc/proftpd/proftpd.conf ] && PCONF="/etc/proftpd/proftpd.conf"
  DLINE="$( [ -n "$PCONF" ] && grep_uc_last "$PCONF" '^[[:space:]]*DisplayLogin[[:space:]]+' )"
  if [ -n "${DLINE:-}" ]; then
    MSGF="$(echo "$DLINE" | awk '{print $2}' | tr -d '"')"
    if [ -n "${MSGF:-}" ] && has_content "$MSGF"; then
      append_detail "[ftp] proftpd_active=Y, $PCONF: $DLINE (message_has_content=Y)"
    else
      VULN=1; append_detail "[ftp] proftpd_active=Y, DisplayLogin_file_empty_or_not_found: ${MSGF:-unknown}"
    fi
  else
    VULN=1; append_detail "[ftp] proftpd_active=Y, DisplayLogin=NOT_SET($PCONF)"
  fi
else
  append_detail "[ftp] proftpd_active=N"
fi

# 5) SMTP 사용 시 배너(Postfix/Sendmail/Exim)
if svc_active postfix; then
  PLINE="$(grep_uc_last /etc/postfix/main.cf '^[[:space:]]*smtpd_banner[[:space:]]*=')"
  if [ -n "${PLINE:-}" ]; then append_detail "[smtp] postfix_active=Y, /etc/postfix/main.cf: $PLINE"
  else VULN=1; append_detail "[smtp] postfix_active=Y, smtpd_banner=NOT_SET(/etc/postfix/main.cf)"; fi
else
  append_detail "[smtp] postfix_active=N"
fi

if svc_active sendmail; then
  SLINE="$(grep_uc_last /etc/mail/sendmail.cf '^[[:space:]]*O[[:space:]]+SmtpGreetingMessage|^[[:space:]]*SmtpGreetingMessage')"
  if [ -n "${SLINE:-}" ]; then append_detail "[smtp] sendmail_active=Y, /etc/mail/sendmail.cf: $SLINE"
  else VULN=1; append_detail "[smtp] sendmail_active=Y, SmtpGreetingMessage=NOT_SET(/etc/mail/sendmail.cf)"; fi
else
  append_detail "[smtp] sendmail_active=N"
fi

if svc_active exim; then
  ECONF=""
  [ -f /etc/exim/exim.conf ] && ECONF="/etc/exim/exim.conf"
  [ -z "$ECONF" ] && [ -f /etc/exim4/exim4.conf ] && ECONF="/etc/exim4/exim4.conf"
  ELINE="$( [ -n "$ECONF" ] && grep_uc_last "$ECONF" '^[[:space:]]*smtp_banner[[:space:]]*=')"
  if [ -n "${ELINE:-}" ]; then append_detail "[smtp] exim_active=Y, $ECONF: $ELINE"
  else VULN=1; append_detail "[smtp] exim_active=Y, smtp_banner=NOT_SET($ECONF)"; fi
else
  append_detail "[smtp] exim_active=N"
fi

# 6) DNS(named) 사용 시 version 설정
if svc_active named; then
  NCONF=""
  [ -f /etc/named.conf ] && NCONF="/etc/named.conf"
  [ -z "$NCONF" ] && [ -f /etc/bind/named.conf.options ] && NCONF="/etc/bind/named.conf.options"
  NLINE="$( [ -n "$NCONF" ] && grep_uc_last "$NCONF" '^[[:space:]]*version[[:space:]]+' )"
  if [ -n "${NLINE:-}" ]; then append_detail "[dns] named_active=Y, $NCONF: $NLINE"
  else VULN=1; append_detail "[dns] named_active=Y, version=NOT_SET($NCONF)"; fi
else
  append_detail "[dns] named_active=N"
fi

# 최종 판정/문구(요구사항 반영)
GUIDE_SIMPLE="조치: /etc/issue,/etc/motd(서버), /etc/issue.net(Telnet) 경고 문구를 작성하고, SSH는 /etc/ssh/sshd_config에 'Banner <파일경로>' 설정 후 sshd 재시작. FTP(vsftpd: ftpd_banner, proftpd: DisplayLogin), SMTP(postfix: smtpd_banner, sendmail: SmtpGreetingMessage, exim: smtp_banner), DNS(named.conf: version)도 서비스 사용 시 배너/버전 문구를 설정 후 해당 서비스 재시작."

if [ "$VULN" -eq 0 ]; then
  STATUS="PASS"
  REASON_LINE="서버(/etc/issue 또는 /etc/motd) 및 서비스(SSH/Telnet/FTP/SMTP/DNS) 사용 시 해당 설정파일에서 배너/경고 문구가 설정되어 있어 이 항목에 대한 보안 위협이 없습니다."
else
  STATUS="FAIL"
  REASON_LINE="서버 또는 일부 서비스(SSH/Telnet/FTP/SMTP/DNS)에서 배너/경고 문구가 설정되지 않았거나 비어 있어 취약합니다. ${GUIDE_SIMPLE}"
fi

[ -n "$DETAIL_LINES" ] || DETAIL_LINES="none"

RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_LINES",
  "target_file": "$TARGET_FILE"
}
EOF
)

# escape(백슬래시/따옴표/줄바꿈)
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" | sed 's/\\/\\\\/g; s/"/\\"/g; :a;N;$!ba;s/\n/\\n/g')

echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF