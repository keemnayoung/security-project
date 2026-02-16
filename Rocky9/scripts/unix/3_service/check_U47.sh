#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-47
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 스팸 메일 릴레이 제한
# @Description : SMTP 서버의 릴레이 기능 제한 여부 점검
# @Criteria_Good : 메일 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정
# @Criteria_Bad : 메일 서비스 사용 시 릴레이 방지 설정 또는 릴레이 대상 접근 제어 설정
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-47 스팸 메일 릴레이 제한

# 기본 변수
ID="U-47"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""

# ✅ 따옴표 깨짐/파싱 오류 방지: heredoc로 CHECK_COMMAND 정의
CHECK_COMMAND=$(cat <<'EOF'
( command -v sendmail >/dev/null 2>&1 && sendmail -d0 < /dev/null 2>/dev/null );
( [ -f /etc/mail/sendmail.cf ] && grep -inE "promiscuous_relay|Relaying denied" /etc/mail/sendmail.cf 2>/dev/null );
( command -v postconf >/dev/null 2>&1 && postconf -n 2>/dev/null );
( [ -f /etc/postfix/main.cf ] && grep -nE "^(mynetworks|smtpd_(relay|recipient)_restrictions)[[:space:]]*=" /etc/postfix/main.cf 2>/dev/null );
( command -v exim >/dev/null 2>&1 && exim -bV 2>/dev/null );
( command -v exim4 >/dev/null 2>&1 && exim4 -bV 2>/dev/null );
( grep -nE "relay_from_hosts|accept[[:space:]]+hosts[[:space:]]*=.*\\+relay_from_hosts" /etc/exim/exim.conf /etc/exim4/exim4.conf /etc/exim4/update-exim4.conf.conf 2>/dev/null );
EOF
)

VULNERABLE=0
FOUND_ANY=0
DETAIL_LINES=""

append_detail() {
  local line="$1"
  [ -z "$line" ] && return 0
  if [ -z "$DETAIL_LINES" ]; then
    DETAIL_LINES="$line"
  else
    DETAIL_LINES="${DETAIL_LINES}\n$line"
  fi
}

add_target_file() {
  local f="$1"
  [ -z "$f" ] && return 0
  if [ -z "$TARGET_FILE" ]; then
    TARGET_FILE="$f"
  else
    TARGET_FILE="${TARGET_FILE}, $f"
  fi
}

contains_open_all_network() {
  echo "$1" | grep -qE '(^|[[:space:],])0\.0\.0\.0/0($|[[:space:],])|(^|[[:space:],])::/0($|[[:space:],])|(^|[[:space:],])0/0($|[[:space:],])'
}

# -----------------------------
# 1) Sendmail 점검
# -----------------------------
if command -v sendmail >/dev/null 2>&1; then
  FOUND_ANY=1
  SM_CF="/etc/mail/sendmail.cf"
  SM_MC="/etc/mail/sendmail.mc"
  add_target_file "$SM_CF"
  [ -f "$SM_MC" ] && add_target_file "$SM_MC"
  add_target_file "/etc/mail/access"
  add_target_file "/etc/mail/access.db"

  SM_VER_RAW="$(sendmail -d0 < /dev/null 2>/dev/null | grep -i 'Version' | head -n1)"
  SM_VER="$(echo "$SM_VER_RAW" | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -n1)"
  [ -z "$SM_VER" ] && SM_VER="unknown"

  if [ ! -f "$SM_CF" ]; then
    VULNERABLE=1
    append_detail "[sendmail] sendmail=FOUND version=$SM_VER but $SM_CF=NOT_FOUND -> 릴레이 제한 설정을 확인할 수 없어 취약 판정"
  else
    if grep -q "promiscuous_relay" "$SM_CF" 2>/dev/null; then
      VULNERABLE=1
      append_detail "[sendmail] $SM_CF에 'promiscuous_relay' 설정이 존재 -> 오픈 릴레이 위험"
    else
      append_detail "[sendmail] $SM_CF에서 promiscuous_relay 미탐지 -> 무조건 릴레이 설정 없음"
    fi

    if grep -q "Relaying denied" "$SM_CF" 2>/dev/null; then
      append_detail "[sendmail] $SM_CF에서 'Relaying denied' 문자열 확인(릴레이 차단 신호)"
    else
      append_detail "[sendmail] $SM_CF에서 'Relaying denied' 문자열 미확인(구성에 따라 없을 수 있음) -> 릴레이 정책 추가 확인 권장"
    fi

    if [ -f "/etc/mail/access" ] || [ -f "/etc/mail/access.db" ]; then
      append_detail "[sendmail] /etc/mail/access 또는 access.db 존재 -> access 기반 릴레이 제어 구성 신호"
    else
      append_detail "[sendmail] /etc/mail/access 및 access.db 미존재(참고) -> 운영 정책에 따라 access 기반 제어 사용 여부 확인"
    fi

    if [ -f "$SM_MC" ] && grep -qE 'FEATURE\(\s*`promiscuous_relay`\s*\)' "$SM_MC" 2>/dev/null; then
      VULNERABLE=1
      append_detail "[sendmail] $SM_MC에 FEATURE(`promiscuous_relay`) 존재 -> 오픈 릴레이 위험"
    fi
  fi
fi

# -----------------------------
# 2) Postfix 점검
# -----------------------------
POSTFIX_FOUND=0
if command -v postconf >/dev/null 2>&1 || command -v postfix >/dev/null 2>&1; then
  FOUND_ANY=1
  POSTFIX_FOUND=1
  PF_MAIN="/etc/postfix/main.cf"
  add_target_file "$PF_MAIN"

  PF_EFFECTIVE=""
  if command -v postconf >/dev/null 2>&1; then
    PF_EFFECTIVE="$(postconf -n 2>/dev/null)"
  fi

  get_pf_param() {
    local key="$1"
    local line=""
    if [ -n "$PF_EFFECTIVE" ]; then
      line="$(echo "$PF_EFFECTIVE" | grep -E "^${key}[[:space:]]*=" | head -n1)"
      [ -n "$line" ] && { echo "$line"; return 0; }
    fi
    if [ -f "$PF_MAIN" ]; then
      line="$(grep -nE "^[[:space:]]*${key}[[:space:]]*=" "$PF_MAIN" 2>/dev/null | grep -v '^[[:space:]]*#' | head -n1)"
      [ -n "$line" ] && { echo "$line"; return 0; }
    fi
    echo ""
  }

  PF_MYNETWORKS_LINE="$(get_pf_param "mynetworks")"
  PF_RELAY_LINE="$(get_pf_param "smtpd_relay_restrictions")"
  PF_RCPT_LINE="$(get_pf_param "smtpd_recipient_restrictions")"

  if [ -n "$PF_MYNETWORKS_LINE" ]; then
    if contains_open_all_network "$PF_MYNETWORKS_LINE"; then
      VULNERABLE=1
      append_detail "[postfix] mynetworks가 전체 허용으로 설정됨 -> 오픈 릴레이 위험 | $PF_MYNETWORKS_LINE"
    else
      append_detail "[postfix] mynetworks 설정 확인(유효 설정 우선) | $PF_MYNETWORKS_LINE"
    fi
  else
    append_detail "[postfix] mynetworks 설정 라인 미확인 -> 기본값 적용 가능(운영 정책에 따라 허용 네트워크 확인 필요)"
  fi

  FOUND_REJECT="N"
  echo "$PF_RELAY_LINE $PF_RCPT_LINE" | grep -q "reject_unauth_destination" && FOUND_REJECT="Y"

  if [ "$FOUND_REJECT" = "Y" ]; then
    append_detail "[postfix] (relay/recipient restrictions) reject_unauth_destination 포함 -> 릴레이 차단 핵심 조건 충족"
  else
    VULNERABLE=1
    append_detail "[postfix] (relay/recipient restrictions) reject_unauth_destination 미포함 -> 릴레이 제한이 미흡하여 취약"
    [ -n "$PF_RELAY_LINE" ] && append_detail "[postfix] smtpd_relay_restrictions | $PF_RELAY_LINE"
    [ -n "$PF_RCPT_LINE" ] && append_detail "[postfix] smtpd_recipient_restrictions | $PF_RCPT_LINE"
  fi
fi

# -----------------------------
# 3) Exim 점검
# -----------------------------
EXIM_CMD=""
command -v exim >/dev/null 2>&1 && EXIM_CMD="exim"
[ -z "$EXIM_CMD" ] && command -v exim4 >/dev/null 2>&1 && EXIM_CMD="exim4"

if [ -n "$EXIM_CMD" ]; then
  FOUND_ANY=1

  CONF_FILES=(
    "/etc/exim/exim.conf"
    "/etc/exim4/exim4.conf"
    "/etc/exim4/update-exim4.conf.conf"
  )

  FOUND_CONF="N"
  for conf in "${CONF_FILES[@]}"; do
    if [ -f "$conf" ]; then
      FOUND_CONF="Y"
      add_target_file "$conf"

      RELAY_LINE="$(grep -v '^[[:space:]]*#' "$conf" 2>/dev/null | grep -E 'relay_from_hosts' | head -n1)"
      if [ -n "$RELAY_LINE" ]; then
        append_detail "[exim] relay_from_hosts 설정 확인 | $RELAY_LINE"
        if echo "$RELAY_LINE" | grep -qE '(^|[[:space:]=,])\*($|[[:space:],])|0\.0\.0\.0/0|::/0|0/0'; then
          VULNERABLE=1
          append_detail "[exim] relay_from_hosts가 전체 허용으로 설정됨 -> 오픈 릴레이 위험"
        fi
      else
        append_detail "[exim] relay_from_hosts 설정 라인 미확인(구성에 따라 ACL 기반) -> 릴레이 정책 추가 확인 권장"
      fi

      if grep -qE 'accept[[:space:]]+hosts[[:space:]]*=[[:space:]]*\+relay_from_hosts' "$conf" 2>/dev/null; then
        append_detail "[exim] ACL에 accept hosts = +relay_from_hosts 확인"
      else
        append_detail "[exim] ACL에서 accept hosts = +relay_from_hosts 미확인(구성에 따라 다름)"
      fi

      break
    fi
  done

  if [ "$FOUND_CONF" = "N" ]; then
    VULNERABLE=1
    append_detail "[exim] exim=FOUND but config_file=NOT_FOUND -> 릴레이 제한 설정을 확인할 수 없어 취약 판정"
  fi
fi

# -----------------------------
# 4) 최종 판정/문구
# -----------------------------
if [ $FOUND_ANY -eq 0 ]; then
  STATUS="PASS"
  REASON_LINE="메일 서비스(sendmail/postfix/exim)가 설치되어 있지 않아 점검 대상이 없으므로 이 항목에 대한 보안 위협이 없습니다."
  DETAIL_CONTENT="none"
else
  if [ $VULNERABLE -eq 1 ]; then
    STATUS="FAIL"
    REASON_LINE="메일 서버 설정(sendmail/postfix/exim)에서 릴레이 제한이 미흡하거나 확인 불가한 구성(예: promiscuous_relay, mynetworks 전체 허용, reject_unauth_destination 미적용, relay_from_hosts 전체 허용 등)으로 확인되어 취약합니다. 조치 방법: 메일 서비스를 사용하지 않으면 서비스 중지/비활성화하고, 사용한다면 릴레이 허용 대상을 내부 네트워크로 제한(sendmail: promiscuous_relay 제거 및 access RELAY/REJECT 구성, postfix: mynetworks 제한 및 (relay/recipient)_restrictions에 reject_unauth_destination 적용, exim: relay_from_hosts 허용 범위 제한) 후 서비스를 재시작/재적용하세요."
  else
    STATUS="PASS"
    REASON_LINE="메일 서버 설정(sendmail/postfix/exim)에서 릴레이 제한이 적용되어 있고 오픈 릴레이로 판단되는 설정(전체 허용, promiscuous_relay 등)이 발견되지 않아 이 항목에 대한 보안 위협이 없습니다."
  fi

  DETAIL_CONTENT="$DETAIL_LINES"
  [ -z "$DETAIL_CONTENT" ] && DETAIL_CONTENT="none"
fi

[ -z "$TARGET_FILE" ] && TARGET_FILE="/etc/mail/sendmail.cf, /etc/mail/sendmail.mc, /etc/mail/access, /etc/mail/access.db, /etc/postfix/main.cf, /etc/exim/exim.conf, /etc/exim4/exim4.conf, /etc/exim4/update-exim4.conf.conf"

RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/"/\\"/g' \
  | sed ':a;N;$!ba;s/\n/\\n/g')

echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF