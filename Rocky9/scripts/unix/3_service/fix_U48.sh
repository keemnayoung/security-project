#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-48
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : expn, vrfy 명령어 제한
# @Description : SMTP expn, vrfy 명령어를 제한
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-48 expn, vrfy 명령어 제한

# 기본 변수
ID="U-48"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

TARGET_FILE="/etc/mail/sendmail.cf, /etc/postfix/main.cf, (exim config)"

CHECK_COMMAND='
# Sendmail
[ -f /etc/mail/sendmail.cf ] && grep -inE "^[[:space:]]*O[[:space:]]+PrivacyOptions=" /etc/mail/sendmail.cf 2>/dev/null | head -n 3 || echo "sendmail_cf_not_found_or_no_privacyoptions";
# Postfix
[ -f /etc/postfix/main.cf ] && grep -nEv "^[[:space:]]*#" /etc/postfix/main.cf 2>/dev/null | grep -niE "^[[:space:]]*disable_vrfy_command[[:space:]]*=" | head -n 3 || echo "postfix_main_cf_not_found_or_no_disable_vrfy_command";
# Exim
for f in /etc/exim/exim.conf /etc/exim4/exim4.conf; do
  [ -f "$f" ] && echo "exim_conf=$f" && grep -nEv "^[[:space:]]*#" "$f" 2>/dev/null | grep -niE "^[[:space:]]*acl_smtp_(vrfy|expn)[[:space:]]*=" | head -n 5 && break
done
(command -v systemctl >/dev/null 2>&1 && (
  for u in sendmail.service postfix.service exim.service exim4.service; do
    systemctl list-unit-files 2>/dev/null | grep -qiE "^${u}[[:space:]]" && echo "unit:$u enabled=$(systemctl is-enabled "$u" 2>/dev/null || echo unknown) active=$(systemctl is-active "$u" 2>/dev/null || echo unknown)";
  done
)) || echo "systemctl_not_found"
'

REASON_LINE=""
DETAIL_CONTENT=""
ACTION_ERR_LOG=""
MODIFIED=0
FAIL_FLAG=0

# (필수) root 권한 권장 안내(실패 원인 명확화용)
if [ "$(id -u)" -ne 0 ]; then
  ACTION_ERR_LOG="(주의) root 권한이 아니면 설정 파일 수정 및 서비스 재시작이 실패할 수 있습니다."
fi

append_err() {
  if [ -n "$ACTION_ERR_LOG" ]; then
    ACTION_ERR_LOG="${ACTION_ERR_LOG}\n$1"
  else
    ACTION_ERR_LOG="$1"
  fi
}

append_detail() {
  if [ -n "$DETAIL_CONTENT" ]; then
    DETAIL_CONTENT="${DETAIL_CONTENT}\n$1"
  else
    DETAIL_CONTENT="$1"
  fi
}

backup_file() {
  local f="$1"
  [ -f "$f" ] || return 0
  cp -a "$f" "${f}.bak_$(date +%Y%m%d_%H%M%S)" 2>/dev/null || append_err "$f 백업 실패"
}

restart_if_unit_exists() {
  local unit="$1"
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl list-unit-files 2>/dev/null | grep -qiE "^${unit}[[:space:]]" || return 0
  systemctl restart "$unit" 2>/dev/null || append_err "systemctl restart ${unit} 실패"
}

########################################
# 1) Sendmail: PrivacyOptions에 goaway 포함
########################################
CF_FILE="/etc/mail/sendmail.cf"
if command -v sendmail >/dev/null 2>&1 && [ -f "$CF_FILE" ]; then
  if grep -inE '^[[:space:]]*O[[:space:]]+PrivacyOptions=' "$CF_FILE" 2>/dev/null | grep -qi 'goaway'; then
    : # already ok
  else
    backup_file "$CF_FILE"
    if grep -qE '^[[:space:]]*O[[:space:]]+PrivacyOptions=' "$CF_FILE" 2>/dev/null; then
      sed -i '/^[[:space:]]*O[[:space:]]\+PrivacyOptions=/ s/$/,goaway/' "$CF_FILE" 2>/dev/null \
        || append_err "sendmail.cf PrivacyOptions에 goaway 추가 실패"
    else
      echo "O PrivacyOptions=goaway" >> "$CF_FILE" 2>/dev/null || append_err "sendmail.cf PrivacyOptions 신규 추가 실패"
    fi
    MODIFIED=1
    restart_if_unit_exists "sendmail.service"
  fi
fi

########################################
# 2) Postfix: disable_vrfy_command = yes 보장
########################################
MAIN_CF="/etc/postfix/main.cf"
if command -v postfix >/dev/null 2>&1 && [ -f "$MAIN_CF" ]; then
  backup_needed=0

  if ! grep -nEv "^[[:space:]]*#" "$MAIN_CF" 2>/dev/null | grep -qiE '^[[:space:]]*disable_vrfy_command[[:space:]]*='; then
    backup_needed=1
    echo "disable_vrfy_command = yes" >> "$MAIN_CF" 2>/dev/null || append_err "postfix disable_vrfy_command 추가 실패"
    MODIFIED=1
  else
    # 값이 no/false/0 등으로 되어 있으면 yes로 교체(주석 제외)
    if grep -nEv "^[[:space:]]*#" "$MAIN_CF" 2>/dev/null | grep -qiE '^[[:space:]]*disable_vrfy_command[[:space:]]*=[[:space:]]*(no|false|0)([[:space:]]|$)'; then
      backup_needed=1
      sed -i 's/^[[:space:]]*disable_vrfy_command[[:space:]]*=.*/disable_vrfy_command = yes/g' "$MAIN_CF" 2>/dev/null \
        || append_err "postfix disable_vrfy_command 수정 실패"
      MODIFIED=1
    fi
  fi

  [ "$backup_needed" -eq 1 ] && backup_file "$MAIN_CF"

  postfix reload 2>/dev/null || append_err "postfix reload 실패"
fi

########################################
# 3) Exim: acl_smtp_vrfy/acl_smtp_expn accept 허용 제거(주석)
########################################
if command -v exim >/dev/null 2>&1 || command -v exim4 >/dev/null 2>&1; then
  CONF_FILES=("/etc/exim/exim.conf" "/etc/exim4/exim4.conf")
  for conf in "${CONF_FILES[@]}"; do
    if [ -f "$conf" ]; then
      # accept로 열려있는 경우만 주석 처리(주석 제외)
      if grep -nEv "^[[:space:]]*#" "$conf" 2>/dev/null | grep -qiE '^[[:space:]]*acl_smtp_(vrfy|expn)[[:space:]]*=[[:space:]]*accept([[:space:]]|$)'; then
        backup_file "$conf"
        sed -i 's/^[[:space:]]*\(acl_smtp_vrfy[[:space:]]*=[[:space:]]*accept\)/#\1/g' "$conf" 2>/dev/null || true
        sed -i 's/^[[:space:]]*\(acl_smtp_expn[[:space:]]*=[[:space:]]*accept\)/#\1/g' "$conf" 2>/dev/null || true
        MODIFIED=1
        restart_if_unit_exists "exim4.service"
        restart_if_unit_exists "exim.service"
      fi
      break
    fi
  done
fi

########################################
# 4) 조치 후 검증(현재/조치 후 설정만 기록)
########################################
# Sendmail 검증
if command -v sendmail >/dev/null 2>&1; then
  if [ -f "$CF_FILE" ]; then
    PO_LINE="$(grep -inE '^[[:space:]]*O[[:space:]]+PrivacyOptions=' "$CF_FILE" 2>/dev/null | head -n 1)"
    [ -z "$PO_LINE" ] && PO_LINE="PrivacyOptions_line_not_found"
    append_detail "sendmail_privacyoptions(after)=$PO_LINE"
    echo "$PO_LINE" | grep -qi 'goaway' || FAIL_FLAG=1
  else
    append_detail "sendmail_cf(after)=not_found"
  fi
fi

# Postfix 검증
if command -v postfix >/dev/null 2>&1; then
  if [ -f "$MAIN_CF" ]; then
    VRFY_LINE="$(grep -nEv '^[[:space:]]*#' "$MAIN_CF" 2>/dev/null | grep -niE '^[[:space:]]*disable_vrfy_command[[:space:]]*=' | head -n 1)"
    [ -z "$VRFY_LINE" ] && VRFY_LINE="disable_vrfy_command_not_set"
    append_detail "postfix_disable_vrfy_command(after)=$VRFY_LINE"
    echo "$VRFY_LINE" | grep -qiE '=.*yes' || FAIL_FLAG=1
  else
    append_detail "postfix_main_cf(after)=not_found"
    FAIL_FLAG=1
  fi
fi

# Exim 검증(accept가 남아있으면 실패)
if command -v exim >/dev/null 2>&1 || command -v exim4 >/dev/null 2>&1; then
  found=0
  for f in /etc/exim/exim.conf /etc/exim4/exim4.conf; do
    [ -f "$f" ] || continue
    found=1
    line="$(grep -nEv '^[[:space:]]*#' "$f" 2>/dev/null | grep -niE '^[[:space:]]*acl_smtp_(vrfy|expn)[[:space:]]*=' | head -n 2 | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g')"
    [ -z "$line" ] && line="no_acl_smtp_vrfy_expn_active"
    append_detail "exim_acl(after) file=$f ${line}"
    grep -nEv "^[[:space:]]*#" "$f" 2>/dev/null | grep -qiE '^[[:space:]]*acl_smtp_(vrfy|expn)[[:space:]]*=[[:space:]]*accept' && FAIL_FLAG=1
    break
  done
  [ "$found" -eq 0 ] && append_detail "exim_conf(after)=not_found"
fi

########################################
# 5) 최종 판정
########################################
if [ "$FAIL_FLAG" -eq 0 ]; then
  IS_SUCCESS=1
  if [ "$MODIFIED" -eq 1 ]; then
    REASON_LINE="expn, vrfy 명령어가 제한되도록 설정이 변경되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
  else
    REASON_LINE="expn, vrfy 명령어 제한 설정이 적절히 유지되어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
  fi
else
  IS_SUCCESS=0
  REASON_LINE="조치를 수행했으나 expn, vrfy 명령어 제한 설정이 기준을 충족하지 못해 조치가 완료되지 않았습니다."
fi

if [ -n "$ACTION_ERR_LOG" ]; then
  DETAIL_CONTENT="$DETAIL_CONTENT\n$ACTION_ERR_LOG"
fi

# raw_evidence 구성
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

# JSON escape 처리 (따옴표, 줄바꿈)
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/"/\\"/g' \
  | sed ':a;N;$!ba;s/\n/\\n/g')

# DB 저장용 JSON 출력
echo ""
cat << EOF
{
    "item_code": "$ID",
    "action_date": "$ACTION_DATE",
    "is_success": $IS_SUCCESS,
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
}
EOF