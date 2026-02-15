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
CATEGORY="서비스관리"
TITLE="expn, vrfy 명령어 제한"
IMPORTANCE="중"

# 출력(요청한 스크립트 기준: scan_history 형식 유지)
STATUS="PASS"
EVIDENCE=""
ACTION_LOG=""

SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

# 유틸
is_active() {
  systemctl is-active --quiet "$1" 2>/dev/null
}

append_log() {
  # 문장 구분을 위해 줄바꿈으로 누적
  [ -n "$ACTION_LOG" ] && ACTION_LOG="${ACTION_LOG}\n"
  ACTION_LOG="${ACTION_LOG}$1"
}

# 조치 이후(After) 증적 수집용
AFTER_LINES=()
TARGET_FILES=()

add_target_file() {
  local f="$1"
  [ -f "$f" ] && TARGET_FILES+=("$f")
}

add_after_line() {
  local s="$1"
  [ -n "$s" ] && AFTER_LINES+=("$s")
}

# -------------------------
# [Sendmail]
# 가이드: PrivacyOptions에 goaway 또는 (noexpn+novrfy)
# 조치는 goaway 추가로 표준화
# 서비스명: sendmail 또는 sm-mta 가능
# -------------------------
SENDMAIL_CF="/etc/mail/sendmail.cf"
SENDMAIL_INSTALLED=0
if command -v sendmail >/dev/null 2>&1 || [ -f "$SENDMAIL_CF" ]; then
  SENDMAIL_INSTALLED=1
fi

if [ $SENDMAIL_INSTALLED -eq 1 ]; then
  if is_active "sendmail" || is_active "sm-mta"; then
    if [ -f "$SENDMAIL_CF" ]; then
      add_target_file "$SENDMAIL_CF"

      # 현재 PrivacyOptions 라인(주석 제외, 마지막 라인 기준)
      PRIV_LINE="$(grep -inE '^[[:space:]]*O[[:space:]]+PrivacyOptions' "$SENDMAIL_CF" 2>/dev/null | tail -n 1)"
      PRIV_VAL="$(printf '%s' "$PRIV_LINE" | sed -E 's/^[0-9]+:[[:space:]]*O[[:space:]]+PrivacyOptions[[:space:]]*=?[[:space:]]*//I')"

      # 이미 안전(goaway or noexpn+novrfy)
      if echo "$PRIV_VAL" | grep -qiE '(^|,)[[:space:]]*goaway([[:space:]]*,|$)'; then
        append_log "Sendmail: PrivacyOptions에 goaway가 이미 설정되어 있습니다."
      elif echo "$PRIV_VAL" | grep -qiE '(^|,)[[:space:]]*noexpn([[:space:]]*,|$)' \
        && echo "$PRIV_VAL" | grep -qiE '(^|,)[[:space:]]*novrfy([[:space:]]*,|$)'; then
        append_log "Sendmail: PrivacyOptions에 noexpn, novrfy가 이미 설정되어 있습니다."
      else
        # 조치: PrivacyOptions 라인이 있으면 goaway 추가, 없으면 새로 추가
        if grep -qiE '^[[:space:]]*O[[:space:]]+PrivacyOptions' "$SENDMAIL_CF" 2>/dev/null; then
          # 마지막 PrivacyOptions 라인에 goaway가 없으면 ,goaway 추가(= 유무 모두 처리)
          # O PrivacyOptions=...  /  O PrivacyOptions ...
          sed -i -E '/^[[:space:]]*O[[:space:]]+PrivacyOptions/I{
            /goaway/I! s/[[:space:]]*=?[[:space:]]*(.*)$/=\1,goaway/
          }' "$SENDMAIL_CF"
        else
          echo "O PrivacyOptions=authwarnings,novrfy,noexpn,goaway" >> "$SENDMAIL_CF"
        fi
        systemctl restart sendmail 2>/dev/null || systemctl restart sm-mta 2>/dev/null || true
        append_log "Sendmail: sendmail.cf의 PrivacyOptions에 goaway를 추가(또는 포함)하도록 조치했습니다."
      fi

      # After 증적(조치 이후만)
      AFTER_PRIV="$(grep -inE '^[[:space:]]*O[[:space:]]+PrivacyOptions' "$SENDMAIL_CF" 2>/dev/null | tail -n 1)"
      add_after_line "Sendmail After: ${AFTER_PRIV:-privacyoptions_not_found}"
    else
      # 활성인데 설정파일 확인 불가 -> 조치 실패로 취급
      STATUS="FAIL"
      append_log "Sendmail: 서비스는 활성 상태이나 /etc/mail/sendmail.cf 파일을 확인할 수 없어 조치가 완료되지 않았습니다."
    fi
  else
    append_log "Sendmail: 서비스가 비활성(미사용) 상태라 조치 대상이 아닙니다."
  fi
fi

# -------------------------
# [Postfix]
# 가이드: disable_vrfy_command = yes
# -------------------------
POSTFIX_CF="/etc/postfix/main.cf"
POSTFIX_INSTALLED=0
if command -v postfix >/dev/null 2>&1 || [ -f "$POSTFIX_CF" ]; then
  POSTFIX_INSTALLED=1
fi

if [ $POSTFIX_INSTALLED -eq 1 ]; then
  if is_active "postfix"; then
    if [ -f "$POSTFIX_CF" ]; then
      add_target_file "$POSTFIX_CF"

      # 조치: 주석/공백 변형 고려하여 활성 라인 기준으로 맞춤
      # 1) 활성 라인이 있으면 yes로 교체
      if grep -nEv '^[[:space:]]*#' "$POSTFIX_CF" 2>/dev/null | grep -qiE '^[[:space:]]*disable_vrfy_command[[:space:]]*='; then
        sed -i -E 's/^[[:space:]]*disable_vrfy_command[[:space:]]*=.*/disable_vrfy_command = yes/I' "$POSTFIX_CF"
        append_log "Postfix: main.cf의 disable_vrfy_command 값을 yes로 설정했습니다."
      else
        # 2) 활성 라인이 없으면 추가(주석 라인이 있더라도 활성 라인을 새로 둠)
        echo "disable_vrfy_command = yes" >> "$POSTFIX_CF"
        append_log "Postfix: main.cf에 disable_vrfy_command = yes를 추가했습니다."
      fi

      postfix reload 2>/dev/null || systemctl reload postfix 2>/dev/null || systemctl restart postfix 2>/dev/null || true

      # After 증적(조치 이후만)
      AFTER_POSTFIX="$(grep -inE '^[[:space:]]*disable_vrfy_command[[:space:]]*=' "$POSTFIX_CF" 2>/dev/null | tail -n 1)"
      add_after_line "Postfix After: ${AFTER_POSTFIX:-disable_vrfy_command_not_found}"
    else
      STATUS="FAIL"
      append_log "Postfix: 서비스는 활성 상태이나 /etc/postfix/main.cf 파일을 확인할 수 없어 조치가 완료되지 않았습니다."
    fi
  else
    append_log "Postfix: 서비스가 비활성(미사용) 상태라 조치 대상이 아닙니다."
  fi
fi

# -------------------------
# [Exim]
# 가이드: acl_smtp_vrfy=accept / acl_smtp_expn=accept 허용 시 취약 -> 제거/제한
# 여기서는 accept 라인을 주석 처리로 조치
# -------------------------
EXIM_INSTALLED=0
if command -v exim >/dev/null 2>&1 || command -v exim4 >/dev/null 2>&1 || [ -f /etc/exim/exim.conf ] || [ -f /etc/exim4/exim4.conf ]; then
  EXIM_INSTALLED=1
fi

if [ $EXIM_INSTALLED -eq 1 ]; then
  if is_active "exim" || is_active "exim4"; then
    CONF_FILES=("/etc/exim/exim.conf" "/etc/exim4/exim4.conf")
    FOUND_CONF=0
    for conf in "${CONF_FILES[@]}"; do
      if [ -f "$conf" ]; then
        FOUND_CONF=1
        add_target_file "$conf"

        # accept 허용 라인(주석 제외) 있으면 주석 처리
        if grep -nEv '^[[:space:]]*#' "$conf" 2>/dev/null | grep -qiE '^[[:space:]]*acl_smtp_(vrfy|expn)[[:space:]]*=[[:space:]]*accept\b'; then
          sed -i -E 's/^[[:space:]]*(acl_smtp_vrfy[[:space:]]*=[[:space:]]*accept\b)/#\1/I' "$conf"
          sed -i -E 's/^[[:space:]]*(acl_smtp_expn[[:space:]]*=[[:space:]]*accept\b)/#\1/I' "$conf"
          append_log "Exim: acl_smtp_vrfy/acl_smtp_expn accept 허용 설정을 주석 처리했습니다."
        else
          append_log "Exim: acl_smtp_vrfy/acl_smtp_expn accept 허용 설정이 없어 추가 조치가 필요하지 않습니다."
        fi

        systemctl restart exim 2>/dev/null || systemctl restart exim4 2>/dev/null || true

        # After 증적(조치 이후만)
        AFTER_EXIM="$(grep -inE '^[[:space:]]*#?[[:space:]]*acl_smtp_(vrfy|expn)[[:space:]]*=' "$conf" 2>/dev/null | tail -n 5)"
        add_after_line "Exim After (${conf}): ${AFTER_EXIM:-acl_smtp_rules_not_found}"
      fi
    done

    if [ $FOUND_CONF -eq 0 ]; then
      STATUS="FAIL"
      append_log "Exim: 서비스는 활성 상태이나 설정 파일을 확인할 수 없어 조치가 완료되지 않았습니다."
    fi
  else
    append_log "Exim: 서비스가 비활성(미사용) 상태라 조치 대상이 아닙니다."
  fi
fi

# -------------------------
# 최종 검증(After 검증)로 PASS/FAIL 확정
# - 활성 서비스가 하나라도 있고, 그 활성 서비스의 제한 설정이 만족되어야 PASS
# - 설치되어 있어도 모두 비활성이면 PASS(미사용)
# -------------------------
FOUND_ANY=0
FOUND_ACTIVE=0
VERIFY_FAIL=0

# Sendmail verify
if [ $SENDMAIL_INSTALLED -eq 1 ]; then
  FOUND_ANY=1
  if is_active "sendmail" || is_active "sm-mta"; then
    FOUND_ACTIVE=1
    if [ -f "$SENDMAIL_CF" ]; then
      PRIV_LINE_V="$(grep -inE '^[[:space:]]*O[[:space:]]+PrivacyOptions' "$SENDMAIL_CF" 2>/dev/null | tail -n 1)"
      PRIV_VAL_V="$(printf '%s' "$PRIV_LINE_V" | sed -E 's/^[0-9]+:[[:space:]]*O[[:space:]]+PrivacyOptions[[:space:]]*=?[[:space:]]*//I')"
      if echo "$PRIV_VAL_V" | grep -qiE '(^|,)[[:space:]]*goaway([[:space:]]*,|$)'; then
        :
      elif echo "$PRIV_VAL_V" | grep -qiE '(^|,)[[:space:]]*noexpn([[:space:]]*,|$)' \
        && echo "$PRIV_VAL_V" | grep -qiE '(^|,)[[:space:]]*novrfy([[:space:]]*,|$)'; then
        :
      else
        VERIFY_FAIL=1
      fi
    else
      VERIFY_FAIL=1
    fi
  fi
fi

# Postfix verify
if [ $POSTFIX_INSTALLED -eq 1 ]; then
  FOUND_ANY=1
  if is_active "postfix"; then
    FOUND_ACTIVE=1
    if [ -f "$POSTFIX_CF" ]; then
      if ! grep -nEv '^[[:space:]]*#' "$POSTFIX_CF" 2>/dev/null | grep -qiE '^[[:space:]]*disable_vrfy_command[[:space:]]*=[[:space:]]*yes\b'; then
        VERIFY_FAIL=1
      fi
    else
      VERIFY_FAIL=1
    fi
  fi
fi

# Exim verify
if [ $EXIM_INSTALLED -eq 1 ]; then
  FOUND_ANY=1
  if is_active "exim" || is_active "exim4"; then
    FOUND_ACTIVE=1
    # 활성인데 accept 허용이 남아있으면 FAIL
    if [ -f /etc/exim/exim.conf ] && grep -nEv '^[[:space:]]*#' /etc/exim/exim.conf 2>/dev/null | grep -qiE '^[[:space:]]*acl_smtp_(vrfy|expn)[[:space:]]*=[[:space:]]*accept\b'; then
      VERIFY_FAIL=1
    fi
    if [ -f /etc/exim4/exim4.conf ] && grep -nEv '^[[:space:]]*#' /etc/exim4/exim4.conf 2>/dev/null | grep -qiE '^[[:space:]]*acl_smtp_(vrfy|expn)[[:space:]]*=[[:space:]]*accept\b'; then
      VERIFY_FAIL=1
    fi
  fi
fi

if [ $FOUND_ANY -eq 0 ]; then
  STATUS="PASS"
  EVIDENCE="메일 서비스가 설치되어 있지 않아 조치 대상이 없으며 이 항목에 대한 보안 위협이 없습니다."
elif [ $FOUND_ACTIVE -eq 0 ]; then
  STATUS="PASS"
  EVIDENCE="메일 서비스가 비활성(미사용) 상태라 조치 대상이 아니며 이 항목에 대한 보안 위협이 없습니다."
else
  if [ $VERIFY_FAIL -eq 1 ] || [ "$STATUS" = "FAIL" ]; then
    STATUS="FAIL"
    EVIDENCE="조치를 시도했으나 expn/vrfy 제한 설정이 최종 검증에서 충족되지 않아 조치가 완료되지 않았습니다."
  else
    STATUS="PASS"
    EVIDENCE="expn/vrfy 제한 설정이 조치 이후 최종 검증에서 확인되어 조치가 완료되었습니다."
  fi
fi

# 메시지 정리
if [ -z "$ACTION_LOG" ]; then
  ACTION_LOG="조치할 항목이 없거나(이미 제한/미사용/미설치) 변경 사항이 없습니다."
else
  ACTION_LOG="메일 서버의 expn/vrfy 명령어 제한 조치를 수행했습니다.\n${ACTION_LOG}"
fi

# ---- After 값만 raw_evidence에 넣기 (요청사항) ----
TARGET_FILE="$(printf "%s\n" "${TARGET_FILES[@]}" | awk 'NF' | sort -u)"
[ -z "$TARGET_FILE" ] && TARGET_FILE="N/A"

# After 설정(요약)
AFTER_SUMMARY="$(printf "%s\n" "${AFTER_LINES[@]}" | awk 'NF')"
[ -z "$AFTER_SUMMARY" ] && AFTER_SUMMARY="after_setting_not_available"

CHECK_COMMAND="( command -v sendmail >/dev/null 2>&1 && [ -f /etc/mail/sendmail.cf ] && grep -in '^O[[:space:]]\\+PrivacyOptions' /etc/mail/sendmail.cf 2>/dev/null || true ); ( command -v postfix >/dev/null 2>&1 && [ -f /etc/postfix/main.cf ] && grep -inE '^[[:space:]]*disable_vrfy_command[[:space:]]*=' /etc/postfix/main.cf 2>/dev/null || true ); ( (command -v exim >/dev/null 2>&1 || command -v exim4 >/dev/null 2>&1) && ( [ -f /etc/exim/exim.conf ] && grep -inE '^acl_smtp_(vrfy|expn)[[:space:]]*=' /etc/exim/exim.conf 2>/dev/null || true ) && ( [ -f /etc/exim4/exim4.conf ] && grep -inE '^acl_smtp_(vrfy|expn)[[:space:]]*=' /etc/exim4/exim4.conf 2>/dev/null || true ) )"

REASON_LINE="$ACTION_LOG"
DETAIL_CONTENT="상태: ${STATUS}\n근거: ${EVIDENCE}\n(조치 이후 설정)\n${AFTER_SUMMARY}\n대상 파일: ${TARGET_FILE}"

json_escape() {
  # 백슬래시/줄바꿈/따옴표 escape
  printf '%s' "$1" | sed ':a;N;$!ba;s/\\/\\\\/g;s/\n/\\n/g;s/"/\\"/g'
}

RAW_EVIDENCE_JSON=$(cat <<EOF
{
  "command": "$(json_escape "$CHECK_COMMAND")",
  "detail": "$(json_escape "${REASON_LINE}\n${DETAIL_CONTENT}")",
  "target_file": "$(json_escape "$TARGET_FILE")"
}
EOF
)

RAW_EVIDENCE_ESCAPED="$(json_escape "$RAW_EVIDENCE_JSON")"

# JSON 출력 직전 빈 줄(프로젝트 규칙)
echo ""
cat << EOF
{
  "item_code": "$ID",
  "status": "$STATUS",
  "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
  "scan_date": "$SCAN_DATE"
}
EOF