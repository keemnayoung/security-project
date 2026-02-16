#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.0
# @Author: 이가영
# @Last Updated: 2026-02-16
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-62
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 하
# @Title : 로그인 시 경고 메시지 설정
# @Description : 서버 및 서비스에 로그온 시 불필요한 정보 차단 설정 및 불법적인 사용에 대한 경고 메시지 출력 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-62 로그인 시 경고 메시지 설정

# 기본 변수
ID="U-62"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

TARGET_FILE="/etc/motd /etc/issue /etc/issue.net /etc/ssh/sshd_config (active 서비스 설정파일)"
CHECK_COMMAND='
(ls -l /etc/motd /etc/issue /etc/issue.net 2>/dev/null || true);
(sed -n "1,10p" /etc/motd 2>/dev/null || echo "motd_not_found");
(sed -n "1,10p" /etc/issue 2>/dev/null || echo "issue_not_found");
(sed -n "1,10p" /etc/issue.net 2>/dev/null || echo "issue_net_not_found");
(grep -inE "^[[:space:]]*Banner[[:space:]]+" /etc/ssh/sshd_config 2>/dev/null || echo "sshd_banner_not_set");
(command -v systemctl >/dev/null 2>&1 && systemctl is-active sshd vsftpd proftpd postfix sendmail sm-mta exim exim4 named 2>/dev/null || true);
(grep -inE "^[[:space:]]*O[[:space:]]+SmtpGreetingMessage" /etc/mail/sendmail.cf 2>/dev/null || echo "sendmail_greeting_not_set");
(grep -inE "^[[:space:]]*smtpd_banner[[:space:]]*=" /etc/postfix/main.cf 2>/dev/null || echo "postfix_banner_not_set");
(grep -inE "^[[:space:]]*ftpd_banner[[:space:]]*=" /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null || echo "vsftpd_banner_not_set");
(grep -inE "^[[:space:]]*DisplayLogin[[:space:]]+" /etc/proftpd/proftpd.conf /etc/proftpd.conf 2>/dev/null || echo "proftpd_displaylogin_not_set");
(grep -inE "^[[:space:]]*smtp_banner[[:space:]]*=" /etc/exim/exim.conf /etc/exim4/exim4.conf 2>/dev/null || echo "exim_banner_not_set");
(grep -inE "^[[:space:]]*version[[:space:]]+\".*\";" /etc/named.conf 2>/dev/null || echo "named_version_not_set")
'

REASON_LINE=""
DETAIL_CONTENT=""
ACTION_ERR_LOG=""

append_detail(){ [ -n "${1:-}" ] && DETAIL_CONTENT="${DETAIL_CONTENT}${DETAIL_CONTENT:+\n}$1"; }
append_err(){ [ -n "${1:-}" ] && ACTION_ERR_LOG="${ACTION_ERR_LOG}${ACTION_ERR_LOG:+\n}$1"; }

json_escape(){ echo "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; :a;N;$!ba;s/\n/\\n/g'; }

svc_active(){ command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "$1" 2>/dev/null; }

# 경고 메시지(고정)
WARNING_MSG='***************************************************************
* WARNING: Unauthorized access to this system is prohibited.  *
* All activities are monitored and logged.                    *
***************************************************************'

ensure_file(){ # f
  local f="$1"
  if [ -f "$f" ]; then
    local c; c="$(tr -d '[:space:]' < "$f" 2>/dev/null || true)"
    [ -n "$c" ] || { printf "%s\n" "$WARNING_MSG" > "$f" 2>/dev/null || return 1; }
  else
    printf "%s\n" "$WARNING_MSG" > "$f" 2>/dev/null || return 1
  fi
  chown root:root "$f" 2>/dev/null || true
  chmod 644 "$f" 2>/dev/null || true
  return 0
}

set_kv_file(){ # file key regex_line new_line
  local f="$1" key_re="$2" new_line="$3"
  [ -f "$f" ] || return 1
  if grep -Eq "$key_re" "$f" 2>/dev/null; then
    sed -i -E "s/$key_re.*/$new_line/" "$f" 2>/dev/null || return 1
  else
    printf "\n%s\n" "$new_line" >> "$f" 2>/dev/null || return 1
  fi
  return 0
}

fail_now(){
  IS_SUCCESS=0
  [ -n "${1:-}" ] && append_detail "$1"
}

# root 권한 확인
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  IS_SUCCESS=0
  REASON_LINE="root 권한이 아니어서 로그인 경고 메시지 설정 조치를 수행할 수 없어 조치가 완료되지 않았습니다."
  DETAIL_CONTENT="sudo로 실행해야 합니다."
else
  IS_SUCCESS=1

  # 1) 서버 로컬/원격(파일) 배너: 없거나 비어있으면 작성
  for f in /etc/motd /etc/issue /etc/issue.net; do
    if ensure_file "$f"; then
      append_detail "${f}(after)=warning_message_present"
    else
      fail_now "${f}에 경고 메시지를 설정하지 못했습니다."
      append_err "write_failed:$f"
    fi
  done

  # 2) SSH Banner: sshd가 active일 때만 적용 + 재시작 실패 시 실패
  SSHD_CONF="/etc/ssh/sshd_config"
  if svc_active sshd; then
    if [ -f "$SSHD_CONF" ]; then
      # 기존 Banner 라인 정리 후 단일 설정으로 정규화
      sed -i -E '/^[[:space:]]*Banner[[:space:]]+/Id' "$SSHD_CONF" 2>/dev/null || true
      printf "\nBanner /etc/issue.net\n" >> "$SSHD_CONF" 2>/dev/null || { fail_now "sshd_config에 Banner를 설정하지 못했습니다."; append_err "sshd_config_write_failed"; }
      if command -v systemctl >/dev/null 2>&1 && systemctl restart sshd >/dev/null 2>&1; then
        append_detail "sshd_banner(after)=Banner /etc/issue.net"
        append_detail "sshd_restart(after)=success"
      else
        fail_now "sshd 서비스를 재시작하지 못했습니다."
        append_detail "sshd_restart(after)=failed"
        append_err "sshd_restart_failed"
      fi
    else
      fail_now "sshd가 활성 상태이나 /etc/ssh/sshd_config 파일이 없어 조치가 완료되지 않았습니다."
      append_err "sshd_config_not_found"
    fi
  else
    append_detail "sshd_active=NO(skip)"
  fi

  # 3) 선택 서비스(실제로 active일 때만) 배너/정보 최소화 설정
  # postfix
  if svc_active postfix && [ -f /etc/postfix/main.cf ]; then
    set_kv_file /etc/postfix/main.cf '^[[:space:]]*smtpd_banner[[:space:]]*=' 'smtpd_banner = ESMTP' \
      || { fail_now "postfix smtpd_banner 설정에 실패했습니다."; append_err "postfix_banner_set_failed"; }
    command -v systemctl >/dev/null 2>&1 && systemctl restart postfix >/dev/null 2>&1 || true
    P="$(grep -E '^[[:space:]]*smtpd_banner[[:space:]]*=' /etc/postfix/main.cf 2>/dev/null | tail -n 1)"
    [ -n "$P" ] && append_detail "postfix_smtpd_banner(after)=${P}"
  else
    append_detail "postfix_active=NO(skip)"
  fi

  # vsftpd
  if svc_active vsftpd; then
    VCONF=""; [ -f /etc/vsftpd.conf ] && VCONF=/etc/vsftpd.conf; [ -z "$VCONF" ] && [ -f /etc/vsftpd/vsftpd.conf ] && VCONF=/etc/vsftpd/vsftpd.conf
    if [ -n "$VCONF" ]; then
      set_kv_file "$VCONF" '^[[:space:]]*ftpd_banner[[:space:]]*=' 'ftpd_banner=Welcome' \
        || { fail_now "vsftpd ftpd_banner 설정에 실패했습니다."; append_err "vsftpd_banner_set_failed"; }
      command -v systemctl >/dev/null 2>&1 && systemctl restart vsftpd >/dev/null 2>&1 || true
      V="$(grep -E '^[[:space:]]*ftpd_banner[[:space:]]*=' "$VCONF" 2>/dev/null | tail -n 1)"
      [ -n "$V" ] && append_detail "vsftpd_banner(after)=${VCONF}: ${V}"
    else
      append_detail "vsftpd_conf=NOT_FOUND(skip)"
    fi
  else
    append_detail "vsftpd_active=NO(skip)"
  fi

  # proftpd
  if svc_active proftpd; then
    PCONF=""; [ -f /etc/proftpd/proftpd.conf ] && PCONF=/etc/proftpd/proftpd.conf; [ -z "$PCONF" ] && [ -f /etc/proftpd.conf ] && PCONF=/etc/proftpd.conf
    if [ -n "$PCONF" ]; then
      mkdir -p /etc/proftpd 2>/dev/null || true
      printf "%s\n" "$WARNING_MSG" > /etc/proftpd/welcome.msg 2>/dev/null || { fail_now "proftpd welcome.msg 생성에 실패했습니다."; append_err "proftpd_msg_write_failed"; }
      grep -qiE '^[[:space:]]*DisplayLogin[[:space:]]+' "$PCONF" 2>/dev/null \
        || printf "\nDisplayLogin /etc/proftpd/welcome.msg\n" >> "$PCONF" 2>/dev/null || true
      command -v systemctl >/dev/null 2>&1 && systemctl restart proftpd >/dev/null 2>&1 || true
      D="$(grep -iE '^[[:space:]]*DisplayLogin[[:space:]]+' "$PCONF" 2>/dev/null | tail -n 1)"
      [ -n "$D" ] && append_detail "proftpd_displaylogin(after)=${PCONF}: ${D}"
    else
      append_detail "proftpd_conf=NOT_FOUND(skip)"
    fi
  else
    append_detail "proftpd_active=NO(skip)"
  fi

  # sendmail
  if (svc_active sendmail || svc_active sm-mta) && [ -f /etc/mail/sendmail.cf ]; then
    grep -Ev '^[[:space:]]*#' /etc/mail/sendmail.cf 2>/dev/null | grep -q 'SmtpGreetingMessage' \
      || printf "\nO SmtpGreetingMessage=Mail Server Ready\n" >> /etc/mail/sendmail.cf 2>/dev/null || true
    command -v systemctl >/dev/null 2>&1 && (systemctl restart sendmail >/dev/null 2>&1 || systemctl restart sm-mta >/dev/null 2>&1 || true)
    G="$(grep -E '^[[:space:]]*O[[:space:]]+SmtpGreetingMessage=' /etc/mail/sendmail.cf 2>/dev/null | tail -n 1)"
    [ -n "$G" ] && append_detail "sendmail_greeting(after)=${G}"
  else
    append_detail "sendmail_active=NO(skip)"
  fi

  # exim
  if (svc_active exim || svc_active exim4); then
    ECONF=""; [ -f /etc/exim/exim.conf ] && ECONF=/etc/exim/exim.conf; [ -z "$ECONF" ] && [ -f /etc/exim4/exim4.conf ] && ECONF=/etc/exim4/exim4.conf
    if [ -n "$ECONF" ]; then
      set_kv_file "$ECONF" '^[[:space:]]*smtp_banner[[:space:]]*=' 'smtp_banner = ESMTP' \
        || { fail_now "exim smtp_banner 설정에 실패했습니다."; append_err "exim_banner_set_failed"; }
      command -v systemctl >/dev/null 2>&1 && (systemctl restart exim >/dev/null 2>&1 || systemctl restart exim4 >/dev/null 2>&1 || true)
      E="$(grep -E '^[[:space:]]*smtp_banner[[:space:]]*=' "$ECONF" 2>/dev/null | tail -n 1)"
      [ -n "$E" ] && append_detail "exim_smtp_banner(after)=${ECONF}: ${E}"
    else
      append_detail "exim_conf=NOT_FOUND(skip)"
    fi
  else
    append_detail "exim_active=NO(skip)"
  fi

  # named
  if svc_active named && [ -f /etc/named.conf ]; then
    if ! grep -Ev '^[[:space:]]*#|^[[:space:]]*$' /etc/named.conf 2>/dev/null | grep -qE '^[[:space:]]*version[[:space:]]+"[^"]*";'; then
      grep -qE '^[[:space:]]*options[[:space:]]*\{' /etc/named.conf 2>/dev/null \
        && sed -i -E '/^[[:space:]]*options[[:space:]]*\{/{n; s/^/    version "not currently available";\n/; }' /etc/named.conf 2>/dev/null || true
      command -v systemctl >/dev/null 2>&1 && systemctl restart named >/dev/null 2>&1 || true
    fi
    N="$(grep -E '^[[:space:]]*version[[:space:]]+"[^"]*";' /etc/named.conf 2>/dev/null | tail -n 1)"
    [ -n "$N" ] && append_detail "named_version(after)=${N}" || append_detail "named_version(after)=NOT_SET_OR_OPTIONS_BLOCK_MISSING"
  else
    append_detail "named_active=NO(skip)"
  fi

  if [ "$IS_SUCCESS" -eq 1 ]; then
    REASON_LINE="로그인 경고 메시지(서버/SSH 등)가 설정되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
  else
    REASON_LINE="로그인 경고 메시지 설정을 시도했으나 일부 조치가 실패하여 조치가 완료되지 않았습니다."
  fi
fi

[ -n "$DETAIL_CONTENT" ] || DETAIL_CONTENT="none"

RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE
$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

RAW_EVIDENCE_ESCAPED="$(json_escape "$RAW_EVIDENCE")"

echo ""
cat << EOF
{
    "item_code": "$ID",
    "action_date": "$ACTION_DATE",
    "is_success": $IS_SUCCESS,
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
}
EOF