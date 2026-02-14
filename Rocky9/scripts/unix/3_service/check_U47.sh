#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
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
CHECK_COMMAND='sendmail -d0 -bt; grep -i "promiscuous_relay\|Relaying denied" /etc/mail/sendmail.cf; ls -l /etc/mail/access /etc/mail/access.db; grep -nE "^(mynetworks|smtpd_(relay|recipient)_restrictions)" /etc/postfix/main.cf; grep -nE "relay_from_hosts|acl_check_rcpt|accept[[:space:]]+hosts[[:space:]]*=.*\\+relay_from_hosts" /etc/exim/exim.conf /etc/exim4/exim4.conf /etc/exim4/update-exim4.conf.conf'

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

# -----------------------------
# 1) Sendmail 점검
#   - (가이드) sendmail 버전에 따라 릴레이 제한 룰/옵션 확인
#   - 단, 운영 환경마다 sendmail.cf 생성 방식(m4) 차이가 있어 핵심 시그널만 점검
# -----------------------------
if command -v sendmail >/dev/null 2>&1; then
  FOUND_ANY=1
  SM_CF="/etc/mail/sendmail.cf"
  add_target_file "$SM_CF"
  add_target_file "/etc/mail/access"
  add_target_file "/etc/mail/access.db"

  # 버전 추출(참고용)
  SM_VER_RAW="$(sendmail -d0 < /dev/null 2>/dev/null | grep -i 'Version' | head -n1)"
  SM_VER="$(echo "$SM_VER_RAW" | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -n1)"
  [ -z "$SM_VER" ] && SM_VER="unknown"

  if [ ! -f "$SM_CF" ]; then
    VULNERABLE=1
    append_detail "[sendmail] command=FOUND version=$SM_VER sendmail.cf=NOT_FOUND -> relay restriction status cannot be verified"
  else
    # 위험 시그널 1) promiscuous_relay 존재 여부
    if grep -q "promiscuous_relay" "$SM_CF" 2>/dev/null; then
      VULNERABLE=1
      append_detail "[sendmail] sendmail.cf contains 'promiscuous_relay' -> unconditional relay risk"
    else
      append_detail "[sendmail] promiscuous_relay=NOT_FOUND"
    fi

    # 위험 시그널 2) access / access.db 존재 여부(8.9+ 계열에서 흔한 제어 방식)
    if [ ! -f "/etc/mail/access" ] && [ ! -f "/etc/mail/access.db" ]; then
      # access 파일이 없다고 무조건 릴레이가 열린 것은 아니지만,
      # 가이드 기준으로 '제어 미흡 가능'을 취약 근거로 잡음
      VULNERABLE=1
      append_detail "[sendmail] access/access.db=NOT_FOUND -> relay control may be insufficient"
    else
      append_detail "[sendmail] access/access.db=FOUND"
    fi

    # 위험 시그널 3) (구버전/일부 구성) 'Relaying denied' 룰 존재 여부
    # - 없다고 해서 100% 취약은 아니지만, 확인 신호로 활용
    if grep -q "Relaying denied" "$SM_CF" 2>/dev/null; then
      append_detail "[sendmail] 'Relaying denied' rule=FOUND"
    else
      append_detail "[sendmail] 'Relaying denied' rule=NOT_FOUND (verify relay rules if needed)"
    fi
  fi
fi

# -----------------------------
# 2) Postfix 점검
#   - 핵심: mynetworks가 전체 허용(0.0.0.0/0 등)인지
#   - 권고: relay/recipient restrictions에 reject_unauth_destination 존재 여부
# -----------------------------
if command -v postfix >/dev/null 2>&1 || command -v postconf >/dev/null 2>&1; then
  FOUND_ANY=1
  PF_MAIN="/etc/postfix/main.cf"
  add_target_file "$PF_MAIN"

  if [ ! -f "$PF_MAIN" ]; then
    VULNERABLE=1
    append_detail "[postfix] postfix command=FOUND main.cf=NOT_FOUND -> relay restriction status cannot be verified"
  else
    # 주석 제외 후 값 수집
    MYNETWORKS_LINE="$(grep -nE '^[[:space:]]*mynetworks[[:space:]]*=' "$PF_MAIN" 2>/dev/null | grep -v '^[[:space:]]*#' | head -n1)"
    RELAY_RESTR_LINE="$(grep -nE '^[[:space:]]*smtpd_relay_restrictions[[:space:]]*=' "$PF_MAIN" 2>/dev/null | grep -v '^[[:space:]]*#' | head -n1)"
    RCPT_RESTR_LINE="$(grep -nE '^[[:space:]]*smtpd_recipient_restrictions[[:space:]]*=' "$PF_MAIN" 2>/dev/null | grep -v '^[[:space:]]*#' | head -n1)"

    if [ -n "$MYNETWORKS_LINE" ]; then
      if echo "$MYNETWORKS_LINE" | grep -qE '0\.0\.0\.0/0|::/0'; then
        VULNERABLE=1
        append_detail "[postfix] mynetworks allows all (0.0.0.0/0 or ::/0) -> open relay risk | $MYNETWORKS_LINE"
      else
        append_detail "[postfix] mynetworks=SET | $MYNETWORKS_LINE"
      fi
    else
      # 설정이 없으면 기본값이 적용되지만, 운영 정책상 확인 필요
      append_detail "[postfix] mynetworks=NOT_SET (default applies) -> verify allowed networks"
    fi

    # reject_unauth_destination 존재 여부 점검(대표적인 릴레이 방지 핵심)
    FOUND_REJECT="N"
    echo "$RELAY_RESTR_LINE $RCPT_RESTR_LINE" | grep -q "reject_unauth_destination" && FOUND_REJECT="Y"

    if [ "$FOUND_REJECT" = "Y" ]; then
      append_detail "[postfix] reject_unauth_destination=FOUND (relay protection signal)"
    else
      # 없는 경우 가이드 기준으로 미흡 가능 → 취약 처리
      VULNERABLE=1
      append_detail "[postfix] reject_unauth_destination=NOT_FOUND -> relay protection may be insufficient"
      [ -n "$RELAY_RESTR_LINE" ] && append_detail "[postfix] smtpd_relay_restrictions | $RELAY_RESTR_LINE"
      [ -n "$RCPT_RESTR_LINE" ] && append_detail "[postfix] smtpd_recipient_restrictions | $RCPT_RESTR_LINE"
    fi
  fi
fi

# -----------------------------
# 3) Exim 점검
#   - relay_from_hosts가 * / 0.0.0.0/0 이면 취약
#   - ACL에서 accept hosts = +relay_from_hosts 형태 확인(구성 신호)
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
        append_detail "[exim] relay_from_hosts=SET | $RELAY_LINE"
        if echo "$RELAY_LINE" | grep -qE '\*|0\.0\.0\.0/0|::/0'; then
          VULNERABLE=1
          append_detail "[exim] relay_from_hosts allows all (* or 0.0.0.0/0 or ::/0) -> open relay risk"
        fi
      else
        append_detail "[exim] relay_from_hosts=NOT_SET (verify default relay policy)"
      fi

      if grep -qE 'accept[[:space:]]+hosts[[:space:]]*=[[:space:]]*\+relay_from_hosts' "$conf" 2>/dev/null; then
        append_detail "[exim] acl accept hosts = +relay_from_hosts=FOUND"
      else
        append_detail "[exim] acl accept hosts = +relay_from_hosts=NOT_FOUND (verify ACL policy if needed)"
      fi

      break
    fi
  done

  if [ "$FOUND_CONF" = "N" ]; then
    VULNERABLE=1
    append_detail "[exim] command=FOUND but config_file=NOT_FOUND -> relay restriction status cannot be verified"
  fi
fi

# -----------------------------
# 4) 최종 판정/문구(U-15~U-16 톤)
# -----------------------------
if [ $FOUND_ANY -eq 0 ]; then
  STATUS="PASS"
  REASON_LINE="메일 서비스(sendmail/postfix/exim)가 설치되어 있지 않아 점검 대상이 없습니다."
  DETAIL_CONTENT="none"
else
  if [ $VULNERABLE -eq 1 ]; then
    STATUS="FAIL"
    REASON_LINE="스팸 메일 릴레이 제한 설정이 기준에 부합하지 않거나 확인할 수 없어 취약합니다. 외부에서 메일 서버를 경유한 스팸 발송(오픈 릴레이)이 발생할 수 있으므로 릴레이 허용 대상(네트워크/호스트)을 운영 정책에 맞게 제한하고 관련 설정을 보완해야 합니다."
  else
    STATUS="PASS"
    REASON_LINE="스팸 메일 릴레이가 제한되어 있어 이 항목에 대한 보안 위협이 없습니다."
  fi

  DETAIL_CONTENT="$DETAIL_LINES"
  [ -z "$DETAIL_CONTENT" ] && DETAIL_CONTENT="none"
fi

# target_file 기본값 보정
[ -z "$TARGET_FILE" ] && TARGET_FILE="/etc/mail/sendmail.cf, /etc/mail/access, /etc/mail/access.db, /etc/postfix/main.cf, /etc/exim/exim.conf, /etc/exim4/exim4.conf, /etc/exim4/update-exim4.conf.conf"

# raw_evidence 구성 (첫 줄: 평가 이유 / 다음 줄: 상세 증적)
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

# JSON 저장을 위한 escape 처리 (따옴표, 줄바꿈)
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/"/\\"/g' \
  | sed ':a;N;$!ba;s/\n/\\n/g')

# scan_history 저장용 JSON 출력
echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF