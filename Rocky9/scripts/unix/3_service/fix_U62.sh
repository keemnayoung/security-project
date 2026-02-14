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

CHECK_COMMAND='(ls -l /etc/motd /etc/issue /etc/issue.net 2>/dev/null || true); (sed -n "1,10p" /etc/motd 2>/dev/null || echo "motd_not_found"); (sed -n "1,10p" /etc/issue 2>/dev/null || echo "issue_not_found"); (sed -n "1,10p" /etc/issue.net 2>/dev/null || echo "issue_net_not_found"); (grep -inE "^[[:space:]]*Banner[[:space:]]+" /etc/ssh/sshd_config 2>/dev/null || echo "sshd_banner_not_set"); (command -v systemctl >/dev/null 2>&1 && systemctl is-active sshd 2>/dev/null || true); (grep -inE "^[[:space:]]*O[[:space:]]+SmtpGreetingMessage" /etc/mail/sendmail.cf 2>/dev/null || echo "sendmail_greeting_not_set"); (grep -inE "^[[:space:]]*smtpd_banner[[:space:]]*=" /etc/postfix/main.cf 2>/dev/null || echo "postfix_banner_not_set"); (grep -inE "^[[:space:]]*ftpd_banner[[:space:]]*=" /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null || echo "vsftpd_banner_not_set"); (grep -inE "^[[:space:]]*DisplayLogin[[:space:]]+" /etc/proftpd/proftpd.conf /etc/proftpd.conf 2>/dev/null || echo "proftpd_displaylogin_not_set"); (grep -inE "^[[:space:]]*smtp_banner[[:space:]]*=" /etc/exim/exim.conf /etc/exim4/exim4.conf 2>/dev/null || echo "exim_banner_not_set"); (grep -inE "^[[:space:]]*version[[:space:]]+\".*\";" /etc/named.conf 2>/dev/null || echo "named_version_not_set")'

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE="/etc/motd /etc/issue /etc/issue.net /etc/ssh/sshd_config"

# 경고 메시지(고정)
WARNING_MSG="$(cat <<'EOF'
***************************************************************
* WARNING: Unauthorized access to this system is prohibited.  *
* All activities are monitored and logged.                    *
***************************************************************
EOF
)"

append_detail() {
  if [ -n "$DETAIL_CONTENT" ]; then
    DETAIL_CONTENT="${DETAIL_CONTENT}\n$1"
  else
    DETAIL_CONTENT="$1"
  fi
}

fail() {
  IS_SUCCESS=0
  [ -n "$1" ] && append_detail "$1"
}

ensure_file_owner_perm() {
  local f="$1"
  local owner="${2:-root:root}"
  local perm="${3:-644}"
  [ -e "$f" ] || return 0
  chown "$owner" "$f" 2>/dev/null || true
  chmod "$perm" "$f" 2>/dev/null || true
}

write_if_missing_or_empty() {
  local f="$1"
  if [ -f "$f" ]; then
    local stripped
    stripped="$(tr -d '[:space:]' < "$f" 2>/dev/null || true)"
    if [ -z "$stripped" ]; then
      printf "%s\n" "$WARNING_MSG" > "$f" 2>/dev/null || return 1
    fi
  else
    # 파일이 없으면 생성 후 작성
    printf "%s\n" "$WARNING_MSG" > "$f" 2>/dev/null || return 1
  fi
  ensure_file_owner_perm "$f" "root:root" "644"
  return 0
}

# root 권한 확인
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  IS_SUCCESS=0
  REASON_LINE="root 권한이 아니어서 로그인 경고 메시지 설정 조치를 수행할 수 없어 조치가 완료되지 않았습니다."
  DETAIL_CONTENT="sudo로 실행해야 합니다."
else
  IS_SUCCESS=1

  # 1) /etc/motd, /etc/issue, /etc/issue.net (없거나 비어있으면만 작성)
  for f in /etc/motd /etc/issue /etc/issue.net; do
    if write_if_missing_or_empty "$f"; then
      append_detail "${f}(after)=warning_message_present"
    else
      fail "${f}에 경고 메시지를 설정하지 못했습니다."
    fi
  done

  # 2) SSH Banner 설정(/etc/issue.net)
  SSHD_CONF="/etc/ssh/sshd_config"
  if [ -f "$SSHD_CONF" ]; then
    # 기존 Banner(비주석) 라인 제거 후 단일 라인으로 정규화
    if grep -Ev '^[[:space:]]*#' "$SSHD_CONF" 2>/dev/null | grep -qiE '^[[:space:]]*Banner[[:space:]]+'; then
      sed -i -E '/^[[:space:]]*Banner[[:space:]]+/Id' "$SSHD_CONF" 2>/dev/null || fail "sshd_config의 기존 Banner 설정을 정리하지 못했습니다."
    fi

    # Banner 라인 추가
    if ! grep -Ev '^[[:space:]]*#' "$SSHD_CONF" 2>/dev/null | grep -qiE '^[[:space:]]*Banner[[:space:]]+/etc/issue\.net([[:space:]]|$)'; then
      printf "\nBanner /etc/issue.net\n" >> "$SSHD_CONF" 2>/dev/null || fail "sshd_config에 Banner /etc/issue.net을 추가하지 못했습니다."
    fi

    # 재시작(실패 시 실패 처리)
    if command -v systemctl >/dev/null 2>&1; then
      if systemctl restart sshd >/dev/null 2>&1; then
        append_detail "sshd_banner(after)=Banner /etc/issue.net"
        append_detail "sshd_restart(after)=success"
      else
        fail "sshd 서비스를 재시작하지 못했습니다."
        append_detail "sshd_restart(after)=failed"
      fi
    else
      append_detail "sshd_banner(after)=Banner /etc/issue.net"
      append_detail "sshd_restart(after)=systemctl_not_found"
    fi
  else
    append_detail "sshd_config(after)=not_found"
  fi

  # 3) (선택) 메일/FTP/DNS 배너(해당 서비스 설정 파일이 있을 때만, 없으면 건너뜀)
  # - 정보 노출 최소화를 위해 '버전/호스트명'이 드러나지 않도록 보수적으로 설정

  # Sendmail: SmtpGreetingMessage (있을 때만 추가)
  if command -v sendmail >/dev/null 2>&1 && [ -f /etc/mail/sendmail.cf ]; then
    if ! grep -Ev '^[[:space:]]*#' /etc/mail/sendmail.cf 2>/dev/null | grep -q 'SmtpGreetingMessage'; then
      cp -a /etc/mail/sendmail.cf "/etc/mail/sendmail.cf.bak_$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true
      echo 'O SmtpGreetingMessage=Mail Server Ready' >> /etc/mail/sendmail.cf 2>/dev/null || fail "sendmail.cf에 SmtpGreetingMessage를 추가하지 못했습니다."
      if command -v systemctl >/dev/null 2>&1; then
        systemctl restart sendmail >/dev/null 2>&1 || fail "sendmail 서비스를 재시작하지 못했습니다."
      fi
    fi
    GREET_LINE="$(grep -E '^[[:space:]]*O[[:space:]]+SmtpGreetingMessage=' /etc/mail/sendmail.cf 2>/dev/null | tail -n 1)"
    [ -n "$GREET_LINE" ] && append_detail "sendmail_greeting(after)=$(echo "$GREET_LINE" | tr '\n' ' ')"
  fi

  # Postfix: smtpd_banner (있을 때만 추가/정규화)
  if command -v postfix >/dev/null 2>&1 && [ -f /etc/postfix/main.cf ]; then
    if grep -Eq '^[[:space:]]*smtpd_banner[[:space:]]*=' /etc/postfix/main.cf 2>/dev/null; then
      sed -i -E 's/^[[:space:]]*smtpd_banner[[:space:]]*=.*/smtpd_banner = ESMTP/' /etc/postfix/main.cf 2>/dev/null || true
    else
      echo 'smtpd_banner = ESMTP' >> /etc/postfix/main.cf 2>/dev/null || fail "postfix main.cf에 smtpd_banner를 추가하지 못했습니다."
    fi
    if command -v systemctl >/dev/null 2>&1; then
      systemctl restart postfix >/dev/null 2>&1 || true
    fi
    POSTFIX_BANNER="$(grep -E '^[[:space:]]*smtpd_banner[[:space:]]*=' /etc/postfix/main.cf 2>/dev/null | tail -n 1)"
    [ -n "$POSTFIX_BANNER" ] && append_detail "postfix_smtpd_banner(after)=$(echo "$POSTFIX_BANNER" | tr '\n' ' ')"
  fi

  # vsftpd: ftpd_banner (있을 때만 추가)
  VSFTPD_CONF=""
  [ -f /etc/vsftpd.conf ] && VSFTPD_CONF="/etc/vsftpd.conf"
  [ -z "$VSFTPD_CONF" ] && [ -f /etc/vsftpd/vsftpd.conf ] && VSFTPD_CONF="/etc/vsftpd/vsftpd.conf"
  if command -v vsftpd >/dev/null 2>&1 && [ -n "$VSFTPD_CONF" ]; then
    if ! grep -Ev '^[[:space:]]*#' "$VSFTPD_CONF" 2>/dev/null | grep -qE '^[[:space:]]*ftpd_banner[[:space:]]*='; then
      echo 'ftpd_banner=Welcome' >> "$VSFTPD_CONF" 2>/dev/null || fail "vsftpd 설정에 ftpd_banner를 추가하지 못했습니다."
      if command -v systemctl >/dev/null 2>&1; then
        systemctl restart vsftpd >/dev/null 2>&1 || true
      fi
    fi
    VSB="$(grep -E '^[[:space:]]*ftpd_banner[[:space:]]*=' "$VSFTPD_CONF" 2>/dev/null | tail -n 1)"
    [ -n "$VSB" ] && append_detail "vsftpd_banner(after)=$(echo "$VSB" | tr '\n' ' ')"
  fi

  # proftpd: DisplayLogin (있을 때만 추가)
  PROFTPD_CONF=""
  [ -f /etc/proftpd/proftpd.conf ] && PROFTPD_CONF="/etc/proftpd/proftpd.conf"
  [ -z "$PROFTPD_CONF" ] && [ -f /etc/proftpd.conf ] && PROFTPD_CONF="/etc/proftpd.conf"
  if command -v proftpd >/dev/null 2>&1 && [ -n "$PROFTPD_CONF" ]; then
    if ! grep -Ev '^[[:space:]]*#' "$PROFTPD_CONF" 2>/dev/null | grep -qiE '^[[:space:]]*DisplayLogin[[:space:]]+'; then
      mkdir -p /etc/proftpd 2>/dev/null || true
      printf "%s\n" "$WARNING_MSG" > /etc/proftpd/welcome.msg 2>/dev/null || fail "proftpd welcome.msg를 생성하지 못했습니다."
      echo "DisplayLogin /etc/proftpd/welcome.msg" >> "$PROFTPD_CONF" 2>/dev/null || fail "proftpd 설정에 DisplayLogin을 추가하지 못했습니다."
      if command -v systemctl >/dev/null 2>&1; then
        systemctl restart proftpd >/dev/null 2>&1 || true
      fi
    fi
    PDL="$(grep -iE '^[[:space:]]*DisplayLogin[[:space:]]+' "$PROFTPD_CONF" 2>/dev/null | tail -n 1)"
    [ -n "$PDL" ] && append_detail "proftpd_displaylogin(after)=$(echo "$PDL" | tr '\n' ' ')"
  fi

  # Exim: smtp_banner (있을 때만 추가/정규화)
  EXIM_CONF=""
  [ -f /etc/exim/exim.conf ] && EXIM_CONF="/etc/exim/exim.conf"
  [ -z "$EXIM_CONF" ] && [ -f /etc/exim4/exim4.conf ] && EXIM_CONF="/etc/exim4/exim4.conf"
  if (command -v exim >/dev/null 2>&1 || command -v exim4 >/dev/null 2>&1) && [ -n "$EXIM_CONF" ]; then
    if grep -Eq '^[[:space:]]*smtp_banner[[:space:]]*=' "$EXIM_CONF" 2>/dev/null; then
      sed -i -E 's/^[[:space:]]*smtp_banner[[:space:]]*=.*/smtp_banner = ESMTP/' "$EXIM_CONF" 2>/dev/null || true
    else
      echo 'smtp_banner = ESMTP' >> "$EXIM_CONF" 2>/dev/null || fail "exim 설정에 smtp_banner를 추가하지 못했습니다."
    fi
    if command -v systemctl >/dev/null 2>&1; then
      systemctl restart exim >/dev/null 2>&1 || systemctl restart exim4 >/dev/null 2>&1 || true
    fi
    EXB="$(grep -E '^[[:space:]]*smtp_banner[[:space:]]*=' "$EXIM_CONF" 2>/dev/null | tail -n 1)"
    [ -n "$EXB" ] && append_detail "exim_smtp_banner(after)=$(echo "$EXB" | tr '\n' ' ')"
  fi

  # DNS(BIND): version 숨김(options 블록에 없을 때만 추가)
  if (command -v named >/dev/null 2>&1 || command -v named-checkconf >/dev/null 2>&1) && [ -f /etc/named.conf ]; then
    if grep -qE '^[[:space:]]*options[[:space:]]*\{' /etc/named.conf 2>/dev/null; then
      if ! grep -Ev '^[[:space:]]*#|^[[:space:]]*$' /etc/named.conf 2>/dev/null | grep -qE '^[[:space:]]*version[[:space:]]+"[^"]*";'; then
        cp -a /etc/named.conf "/etc/named.conf.bak_$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true
        # options { 바로 다음 줄에 삽입
        sed -i -E '/^[[:space:]]*options[[:space:]]*\{/{n; s/^/    version "not currently available";\n/; }' /etc/named.conf 2>/dev/null || true
        if command -v systemctl >/dev/null 2>&1; then
          systemctl restart named >/dev/null 2>&1 || true
        fi
      fi
      NVER="$(grep -E '^[[:space:]]*version[[:space:]]+"[^"]*";' /etc/named.conf 2>/dev/null | tail -n 1)"
      [ -n "$NVER" ] && append_detail "named_version(after)=$(echo "$NVER" | tr '\n' ' ')"
    fi
  fi

  # 최종 REASON_LINE
  if [ "$IS_SUCCESS" -eq 1 ]; then
    REASON_LINE="로그인 경고 메시지(서버/SSH 등)가 설정되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
  else
    REASON_LINE="로그인 경고 메시지 설정을 시도했으나 일부 조치가 실패하여 조치가 완료되지 않았습니다."
  fi
fi

# raw_evidence 구성(이전 설정 미포함: 현재/조치 후 상태만 detail에 기록)
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE
$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

# JSON escape 처리 (따옴표, 줄바꿈)
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/"/\\"/g' \
  | sed ':a;N;$!ba;s/\n/\\n/g')

echo ""
cat << EOF
{
    "item_code": "$ID",
    "action_date": "$ACTION_DATE",
    "is_success": $IS_SUCCESS,
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
}
EOF