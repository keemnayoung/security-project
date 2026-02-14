#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-47
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 스팸 메일 릴레이 제한
# @Description : 메일 서버의 릴레이 기능을 제한
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-47 스팸 메일 릴레이 제한

# 기본 변수
ID="U-47"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND='
# Sendmail
[ -f /etc/mail/access ] && (grep -nEv "^[[:space:]]*#" /etc/mail/access 2>/dev/null | grep -nE "^(127\.0\.0\.1|localhost)[[:space:]]+RELAY" | head -n 5) || echo "sendmail_access_not_found_or_no_relay_rules";
[ -f /etc/mail/access.db ] && echo "sendmail_access_db_exists" || echo "sendmail_access_db_not_found";
# Postfix
[ -f /etc/postfix/main.cf ] && (
  grep -nEv "^[[:space:]]*#" /etc/postfix/main.cf 2>/dev/null | grep -niE "^[[:space:]]*mynetworks[[:space:]]*=" | head -n 3;
  grep -nEv "^[[:space:]]*#" /etc/postfix/main.cf 2>/dev/null | grep -niE "^[[:space:]]*smtpd_recipient_restrictions[[:space:]]*=" | head -n 3
) || echo "postfix_main_cf_not_found";
# Exim
for f in /etc/exim/exim.conf /etc/exim4/exim4.conf /etc/exim4/update-exim4.conf.conf; do
  [ -f "$f" ] && echo "exim_conf=$f" && grep -nEv "^[[:space:]]*#" "$f" 2>/dev/null | grep -niE "relay_from_hosts[[:space:]]*=" | head -n 3 && break
done
(command -v systemctl >/dev/null 2>&1 && (
  for u in sendmail.service postfix.service exim.service exim4.service; do
    systemctl list-unit-files 2>/dev/null | grep -qiE "^${u}[[:space:]]" && echo "unit:$u enabled=$(systemctl is-enabled "$u" 2>/dev/null || echo unknown) active=$(systemctl is-active "$u" 2>/dev/null || echo unknown)";
  done
)) || echo "systemctl_not_found"
'

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE="/etc/mail/access (/etc/mail/access.db), /etc/postfix/main.cf, exim config"

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

restart_if_unit_exists() {
  local unit="$1"
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl list-unit-files 2>/dev/null | grep -qiE "^${unit}[[:space:]]" || return 0
  systemctl restart "$unit" 2>/dev/null || append_err "systemctl restart ${unit} 실패"
}

backup_file() {
  local f="$1"
  [ -f "$f" ] || return 0
  cp -a "$f" "${f}.bak_$(date +%Y%m%d_%H%M%S)" 2>/dev/null || append_err "$f 백업 실패"
}

########################################
# 1) Sendmail: access 기반 RELAY 제한(로컬만 허용)
########################################
if command -v sendmail >/dev/null 2>&1; then
  ACCESS="/etc/mail/access"
  mkdir -p /etc/mail 2>/dev/null || true

  if [ ! -f "$ACCESS" ]; then
    touch "$ACCESS" 2>/dev/null || append_err "/etc/mail/access 생성 실패"
  fi

  if [ -f "$ACCESS" ]; then
    CHANGED=0
    grep -qiE '^[[:space:]]*127\.0\.0\.1[[:space:]]+RELAY' "$ACCESS" 2>/dev/null || { echo "127.0.0.1 RELAY" >> "$ACCESS" 2>/dev/null && CHANGED=1; }
    grep -qiE '^[[:space:]]*localhost[[:space:]]+RELAY' "$ACCESS" 2>/dev/null || { echo "localhost RELAY" >> "$ACCESS" 2>/dev/null && CHANGED=1; }

    if [ "$CHANGED" -eq 1 ]; then
      MODIFIED=1
    fi

    # access.db 생성(가능할 때만)
    if command -v makemap >/dev/null 2>&1; then
      makemap hash /etc/mail/access.db < /etc/mail/access 2>/dev/null || append_err "makemap access.db 생성 실패"
      [ -f /etc/mail/access.db ] || append_err "access.db 생성 확인 실패"
    else
      append_err "makemap 명령이 없어 access.db 생성을 수행하지 못했습니다."
    fi

    restart_if_unit_exists "sendmail.service"
  fi
fi

########################################
# 2) Postfix: mynetworks 과다 허용 제거 + recipient restriction 보장
########################################
if command -v postfix >/dev/null 2>&1; then
  MAIN_CF="/etc/postfix/main.cf"
  if [ -f "$MAIN_CF" ]; then
    backup_needed=0

    # mynetworks에 0.0.0.0/0 포함이면 취약 -> 표준값으로 치환
    if grep -nEv "^[[:space:]]*#" "$MAIN_CF" 2>/dev/null | grep -qiE '^[[:space:]]*mynetworks[[:space:]]*=[^#]*0\.0\.0\.0/0'; then
      backup_needed=1
      # 해당 라인 주석 처리 후 표준값 추가(중복 방지 위해 기존 127.0.0.0/8 있으면 추가 안함)
      sed -i 's/^[[:space:]]*\(mynetworks[[:space:]]*=.*0\.0\.0\.0\/0.*\)$/#\1/g' "$MAIN_CF" 2>/dev/null || append_err "postfix mynetworks 취약 라인 주석 실패"
      grep -nEv "^[[:space:]]*#" "$MAIN_CF" 2>/dev/null | grep -qiE '^[[:space:]]*mynetworks[[:space:]]*=[[:space:]]*127\.0\.0\.0/8([[:space:]]|$)' \
        || echo "mynetworks = 127.0.0.0/8" >> "$MAIN_CF"
      MODIFIED=1
    elif ! grep -nEv "^[[:space:]]*#" "$MAIN_CF" 2>/dev/null | grep -qiE '^[[:space:]]*mynetworks[[:space:]]*='; then
      backup_needed=1
      echo "mynetworks = 127.0.0.0/8" >> "$MAIN_CF"
      MODIFIED=1
    fi

    # smtpd_recipient_restrictions에 reject_unauth_destination 없으면 추가/보강
    if ! grep -nEv "^[[:space:]]*#" "$MAIN_CF" 2>/dev/null | grep -qiE '^[[:space:]]*smtpd_recipient_restrictions[[:space:]]*='; then
      backup_needed=1
      echo "smtpd_recipient_restrictions = permit_mynetworks, reject_unauth_destination" >> "$MAIN_CF"
      MODIFIED=1
    else
      if ! grep -nEv "^[[:space:]]*#" "$MAIN_CF" 2>/dev/null | grep -qiE '^[[:space:]]*smtpd_recipient_restrictions[[:space:]]*=.*reject_unauth_destination'; then
        backup_needed=1
        # 기존 라인 끝에 reject_unauth_destination 추가(단, 중복은 위에서 방지)
        sed -i '/^[[:space:]]*smtpd_recipient_restrictions[[:space:]]*=/ s/$/, reject_unauth_destination/' "$MAIN_CF" 2>/dev/null \
          || append_err "postfix smtpd_recipient_restrictions 보강 실패"
        MODIFIED=1
      fi
    fi

    if [ "$backup_needed" -eq 1 ]; then
      backup_file "$MAIN_CF"
    fi

    postfix reload 2>/dev/null || append_err "postfix reload 실패"
  fi
fi

########################################
# 3) Exim: relay_from_hosts 제한(로컬만)
########################################
if command -v exim >/dev/null 2>&1 || command -v exim4 >/dev/null 2>&1; then
  CONF_FILES=("/etc/exim/exim.conf" "/etc/exim4/exim4.conf" "/etc/exim4/update-exim4.conf.conf")
  for conf in "${CONF_FILES[@]}"; do
    if [ -f "$conf" ]; then
      backup_done=0

      # * 또는 0.0.0.0/0 허용이면 127.0.0.1로 제한
      if grep -nEv "^[[:space:]]*#" "$conf" 2>/dev/null | grep -qiE 'relay_from_hosts[[:space:]]*=.*(\*|0\.0\.0\.0/0)'; then
        backup_file "$conf"
        backup_done=1
        sed -i 's/relay_from_hosts[[:space:]]*=[[:space:]]*\*/relay_from_hosts = 127.0.0.1/g' "$conf" 2>/dev/null || append_err "exim relay_from_hosts(*) 변경 실패"
        sed -i 's/relay_from_hosts[[:space:]]*=[[:space:]]*0\.0\.0\.0\/0/relay_from_hosts = 127.0.0.1/g' "$conf" 2>/dev/null || append_err "exim relay_from_hosts(0.0.0.0/0) 변경 실패"
        MODIFIED=1
      fi

      # 설정이 없으면 추가
      if ! grep -nEv "^[[:space:]]*#" "$conf" 2>/dev/null | grep -qiE 'relay_from_hosts[[:space:]]*='; then
        [ "$backup_done" -eq 1 ] || backup_file "$conf"
        echo "relay_from_hosts = 127.0.0.1" >> "$conf" 2>/dev/null || append_err "exim relay_from_hosts 추가 실패"
        MODIFIED=1
      fi

      restart_if_unit_exists "exim4.service"
      restart_if_unit_exists "exim.service"
      break
    fi
  done
fi

########################################
# 4) 조치 후 검증 + 현재 설정만 detail 기록
########################################
# Sendmail 검증: access에 로컬 RELAY 2개 모두 있는지(가능한 범위)
SENDMAIL_OK=1
if command -v sendmail >/dev/null 2>&1; then
  if [ -f /etc/mail/access ]; then
    a1="$(grep -nEv '^[[:space:]]*#' /etc/mail/access 2>/dev/null | grep -nE '^[[:space:]]*127\.0\.0\.1[[:space:]]+RELAY' | head -n 1)"
    a2="$(grep -nEv '^[[:space:]]*#' /etc/mail/access 2>/dev/null | grep -nE '^[[:space:]]*localhost[[:space:]]+RELAY' | head -n 1)"
    [ -z "$a1" ] && SENDMAIL_OK=0
    [ -z "$a2" ] && SENDMAIL_OK=0
    append_detail "sendmail_access_rules(after)=${a1:-missing_127.0.0.1_RELAY} | ${a2:-missing_localhost_RELAY}"
    append_detail "sendmail_access_db(after)=$([ -f /etc/mail/access.db ] && echo exists || echo not_found)"
  else
    SENDMAIL_OK=0
    append_detail "sendmail_access(after)=not_found"
  fi
fi

# Postfix 검증: mynetworks에 0.0.0.0/0 남아있으면 실패, recipient_restrictions에 reject_unauth_destination 없으면 실패
POSTFIX_OK=1
if command -v postfix >/dev/null 2>&1; then
  if [ -f /etc/postfix/main.cf ]; then
    mn="$(grep -nEv '^[[:space:]]*#' /etc/postfix/main.cf 2>/dev/null | grep -niE '^[[:space:]]*mynetworks[[:space:]]*=' | head -n 1)"
    rr="$(grep -nEv '^[[:space:]]*#' /etc/postfix/main.cf 2>/dev/null | grep -niE '^[[:space:]]*smtpd_recipient_restrictions[[:space:]]*=' | head -n 1)"
    append_detail "postfix_mynetworks(after)=${mn:-not_set}"
    append_detail "postfix_recipient_restrictions(after)=${rr:-not_set}"
    grep -nEv '^[[:space:]]*#' /etc/postfix/main.cf 2>/dev/null | grep -qiE '^[[:space:]]*mynetworks[[:space:]]*=[^#]*0\.0\.0\.0/0' && POSTFIX_OK=0
    grep -nEv '^[[:space:]]*#' /etc/postfix/main.cf 2>/dev/null | grep -qiE '^[[:space:]]*smtpd_recipient_restrictions[[:space:]]*=.*reject_unauth_destination' || POSTFIX_OK=0
  else
    POSTFIX_OK=0
    append_detail "postfix_main_cf(after)=not_found"
  fi
fi

# Exim 검증: relay_from_hosts가 * 또는 0.0.0.0/0이면 실패
EXIM_OK=1
if command -v exim >/dev/null 2>&1 || command -v exim4 >/dev/null 2>&1; then
  found=0
  for f in /etc/exim/exim.conf /etc/exim4/exim4.conf /etc/exim4/update-exim4.conf.conf; do
    [ -f "$f" ] || continue
    found=1
    line="$(grep -nEv '^[[:space:]]*#' "$f" 2>/dev/null | grep -niE 'relay_from_hosts[[:space:]]*=' | head -n 1)"
    [ -z "$line" ] && line="relay_from_hosts_not_set"
    append_detail "exim_relay_from_hosts(after) file=$f line=$line"
    grep -nEv '^[[:space:]]*#' "$f" 2>/dev/null | grep -qiE 'relay_from_hosts[[:space:]]*=.*(\*|0\.0\.0\.0/0)' && EXIM_OK=0
    break
  done
  [ "$found" -eq 0 ] && { EXIM_OK=0; append_detail "exim_conf(after)=not_found"; }
fi

# 최종 판정: 설치/사용하는 MTA가 있는 경우에만 해당 검증이 의미있음.
# 여기서는 “발견된 설정 중 취약 패턴이 남아있으면 FAIL” 방식으로 처리.
if [ "$SENDMAIL_OK" -eq 0 ] || [ "$POSTFIX_OK" -eq 0 ] || [ "$EXIM_OK" -eq 0 ]; then
  FAIL_FLAG=1
fi

if [ "$FAIL_FLAG" -eq 0 ]; then
  IS_SUCCESS=1
  if [ "$MODIFIED" -eq 1 ]; then
    REASON_LINE="스팸 메일 릴레이가 제한되도록 설정이 변경되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
  else
    REASON_LINE="스팸 메일 릴레이 제한 설정이 적절히 유지되어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
  fi
else
  IS_SUCCESS=0
  REASON_LINE="조치를 수행했으나 스팸 메일 릴레이 제한 설정이 기준을 충족하지 못해 조치가 완료되지 않았습니다."
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