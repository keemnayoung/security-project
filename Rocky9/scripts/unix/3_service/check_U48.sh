#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-48
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : expn, vrfy 명령어 제한
# @Description : SMTP 서비스 사용 시 expn, vrfy 명령어 사용 금지 설정 여부 점검
# @Criteria_Good : 메일 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정
# @Criteria_Bad : 메일 서비스 사용 시 메일 서비스 설정 파일에 noexpn, novrfy 또는 goaway 옵션 추가 설정
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-48 expn, vrfy 명령어 제한


# 1. 항목 정보 정의
ID="U-48"
CATEGORY="서비스 관리"
TITLE="expn, vrfy 명령어 제한"
IMPORTANCE="중"

# 2. 진단 로직
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

CHECK_COMMAND='(systemctl is-active postfix 2>/dev/null; systemctl is-active sendmail 2>/dev/null; systemctl is-active sm-mta 2>/dev/null; systemctl is-active exim 2>/dev/null); (test -f /etc/mail/sendmail.cf && grep -inE "^[[:space:]]*O[[:space:]]+PrivacyOptions" /etc/mail/sendmail.cf); (test -f /etc/postfix/main.cf && grep -inE "^[[:space:]]*disable_vrfy_command[[:space:]]*=" /etc/postfix/main.cf); (test -f /etc/exim/exim.conf && grep -inE "^[[:space:]]*acl_smtp_(vrfy|expn)[[:space:]]*=" /etc/exim/exim.conf); (test -f /etc/exim4/exim4.conf && grep -inE "^[[:space:]]*acl_smtp_(vrfy|expn)[[:space:]]*=" /etc/exim4/exim4.conf)'

REASON_LINE=""
DETAIL_CONTENT=""

VULNERABLE=0
FOUND_ANY=0
FOUND_ACTIVE=0

PASS_PARTS=()
FAIL_PARTS=()
TARGET_FILES=()
HASH_LINES=()

escape_json_str() {
  # 백슬래시 -> \\ , 줄바꿈 -> \n , 따옴표 -> \"
  printf '%s' "$1" | sed ':a;N;$!ba;s/\\/\\\\/g;s/\n/\\n/g;s/"/\\"/g'
}

add_file_hash() {
  local f="$1"
  local h="NOT_FOUND"
  if [ -n "$f" ] && [ -f "$f" ]; then
    h="$(sha256sum "$f" 2>/dev/null | awk '{print $1}')"
    [ -z "$h" ] && h="HASH_ERROR"
  fi
  HASH_LINES+=("$f (hash=$h)")
}

is_active() {
  local svc="$1"
  systemctl is-active --quiet "$svc" 2>/dev/null
}

# -----------------------------
# [Sendmail]
# - 가이드: PrivacyOptions에 goaway 또는 (noexpn + novrfy) 필요
# - 서비스 미사용(비활성)이면 PASS(또는 N/A 취지)로 처리하되 비활성화 권고
# -----------------------------
SENDMAIL_CF="/etc/mail/sendmail.cf"
SENDMAIL_INSTALLED=0
if command -v sendmail >/dev/null 2>&1 || [ -f "$SENDMAIL_CF" ]; then
  SENDMAIL_INSTALLED=1
  FOUND_ANY=1
fi

if [ $SENDMAIL_INSTALLED -eq 1 ]; then
  # 활성 서비스명은 환경별로 sendmail 또는 sm-mta일 수 있어 둘 다 확인
  if is_active "sendmail" || is_active "sm-mta"; then
    FOUND_ACTIVE=1
    if [ -f "$SENDMAIL_CF" ]; then
      TARGET_FILES+=("$SENDMAIL_CF")
      add_file_hash "$SENDMAIL_CF"

      # 주석 제외, 마지막 PrivacyOptions 라인 기준
      PRIV_LINE="$(grep -inE '^[[:space:]]*O[[:space:]]+PrivacyOptions' "$SENDMAIL_CF" 2>/dev/null | tail -n 1)"
      PRIV_VAL="$(printf '%s' "$PRIV_LINE" | sed -E 's/^[0-9]+:[[:space:]]*O[[:space:]]+PrivacyOptions[[:space:]]*=?[[:space:]]*//I')"

      # goaway 또는 noexpn+novrfy (공백/쉼표 포함 허용)
      if echo "$PRIV_VAL" | grep -qiE '(^|,)[[:space:]]*goaway([[:space:]]*,|$)'; then
        PASS_PARTS+=("Sendmail: ${SENDMAIL_CF} PrivacyOptions에 goaway가 설정되어 expn/vrfy 관련 정보 노출 위험이 없습니다.")
      elif echo "$PRIV_VAL" | grep -qiE '(^|,)[[:space:]]*noexpn([[:space:]]*,|$)' \
        && echo "$PRIV_VAL" | grep -qiE '(^|,)[[:space:]]*novrfy([[:space:]]*,|$)'; then
        PASS_PARTS+=("Sendmail: ${SENDMAIL_CF} PrivacyOptions에 noexpn, novrfy가 설정되어 expn/vrfy 관련 정보 노출 위험이 없습니다.")
      else
        VULNERABLE=1
        FAIL_PARTS+=("Sendmail: ${SENDMAIL_CF}의 PrivacyOptions에 goaway 또는 (noexpn+novrfy) 설정이 없어 취약합니다.")
      fi
    else
      # 활성인데 설정 파일이 없으면 검증 불가 → 취약(운영 관점에서 위험)
      VULNERABLE=1
      FAIL_PARTS+=("Sendmail: 서비스는 활성 상태이나 ${SENDMAIL_CF} 파일을 확인할 수 없어 expn/vrfy 제한 여부를 검증할 수 없어 취약합니다.")
    fi
  else
    PASS_PARTS+=("Sendmail: 서비스가 비활성 상태라 expn/vrfy 요청을 처리하지 않아 이 항목에 대한 보안 위협이 없습니다(미사용 시 disable 권고).")
  fi
fi

# -----------------------------
# [Postfix]
# - 가이드: main.cf에 disable_vrfy_command = yes 필요
# - 참고: Postfix는 기본적으로 expn을 지원하지 않음(가이드 문구)
# -----------------------------
POSTFIX_CF="/etc/postfix/main.cf"
POSTFIX_INSTALLED=0
if command -v postfix >/dev/null 2>&1 || [ -f "$POSTFIX_CF" ]; then
  POSTFIX_INSTALLED=1
  FOUND_ANY=1
fi

if [ $POSTFIX_INSTALLED -eq 1 ]; then
  if is_active "postfix"; then
    FOUND_ACTIVE=1
    if [ -f "$POSTFIX_CF" ]; then
      TARGET_FILES+=("$POSTFIX_CF")
      add_file_hash "$POSTFIX_CF"

      # 주석 제외 + 공백 허용
      if grep -nEv '^[[:space:]]*#' "$POSTFIX_CF" 2>/dev/null | grep -qiE '^[[:space:]]*disable_vrfy_command[[:space:]]*=[[:space:]]*yes\b'; then
        PASS_PARTS+=("Postfix: ${POSTFIX_CF}에 disable_vrfy_command=yes가 설정되어 vrfy로 인한 정보 노출 위험이 없습니다(※ expn은 기본 미지원).")
      else
        VULNERABLE=1
        FAIL_PARTS+=("Postfix: ${POSTFIX_CF}에 disable_vrfy_command=yes가 설정되어 있지 않아 취약합니다.")
      fi
    else
      VULNERABLE=1
      FAIL_PARTS+=("Postfix: 서비스는 활성 상태이나 ${POSTFIX_CF} 파일을 확인할 수 없어 vrfy 제한 여부를 검증할 수 없어 취약합니다.")
    fi
  else
    PASS_PARTS+=("Postfix: 서비스가 비활성 상태라 vrfy 요청을 처리하지 않아 이 항목에 대한 보안 위협이 없습니다(미사용 시 disable 권고).")
  fi
fi

# -----------------------------
# [Exim]
# - 가이드: exim.conf 또는 exim4.conf에 acl_smtp_vrfy=accept / acl_smtp_expn=accept 있으면 취약
# -----------------------------
EXIM_CONF_CANDIDATES=("/etc/exim/exim.conf" "/etc/exim4/exim4.conf")
EXIM_INSTALLED=0
if command -v exim >/dev/null 2>&1 || command -v exim4 >/dev/null 2>&1 || [ -f "/etc/exim/exim.conf" ] || [ -f "/etc/exim4/exim4.conf" ]; then
  EXIM_INSTALLED=1
  FOUND_ANY=1
fi

if [ $EXIM_INSTALLED -eq 1 ]; then
  if is_active "exim"; then
    FOUND_ACTIVE=1
    FOUND_CONF=0
    for conf in "${EXIM_CONF_CANDIDATES[@]}"; do
      if [ -f "$conf" ]; then
        FOUND_CONF=1
        TARGET_FILES+=("$conf")
        add_file_hash "$conf"

        # 주석 제외 + accept로 명시된 경우만 취약으로 판정
        if grep -nEv '^[[:space:]]*#' "$conf" 2>/dev/null | grep -qiE '^[[:space:]]*acl_smtp_(vrfy|expn)[[:space:]]*=[[:space:]]*accept\b'; then
          VULNERABLE=1
          FAIL_PARTS+=("Exim: ${conf}에서 acl_smtp_vrfy/acl_smtp_expn이 accept로 설정되어 있어 취약합니다.")
        else
          PASS_PARTS+=("Exim: ${conf}에서 acl_smtp_vrfy/acl_smtp_expn이 accept로 허용되지 않아 expn/vrfy 관련 정보 노출 위험이 없습니다.")
        fi
      fi
    done

    if [ $FOUND_CONF -eq 0 ]; then
      VULNERABLE=1
      FAIL_PARTS+=("Exim: 서비스는 활성 상태이나 설정 파일(/etc/exim/exim.conf, /etc/exim4/exim4.conf)을 확인할 수 없어 expn/vrfy 제한 여부를 검증할 수 없어 취약합니다.")
    fi
  else
    PASS_PARTS+=("Exim: 서비스가 비활성 상태라 expn/vrfy 요청을 처리하지 않아 이 항목에 대한 보안 위협이 없습니다(미사용 시 disable 권고).")
  fi
fi

# -----------------------------
# 최종 판정/메시지 구성
# -----------------------------
TARGET_FILE="$(printf "%s\n" "${TARGET_FILES[@]}" | awk 'NF' | sort -u)"
[ -z "$TARGET_FILE" ] && TARGET_FILE="N/A"

HASH_SUMMARY="$(printf "%s\n" "${HASH_LINES[@]}" | awk 'NF' | sort -u)"
[ -z "$HASH_SUMMARY" ] && HASH_SUMMARY="N/A"

if [ $FOUND_ANY -eq 0 ]; then
  STATUS="PASS"
  REASON_LINE="메일 서비스가 설치되어 있지 않아 점검 대상이 없으므로 이 항목에 대한 보안 위협이 없습니다."
  DETAIL_CONTENT="(판정 결과) 메일 서비스 미설치\n(조치 참고) 미설치 상태 유지\n(대상 파일) N/A"
else
  if [ $FOUND_ACTIVE -eq 0 ]; then
    # 가이드: 메일 서비스 미사용 시 PASS 또는 N/A → 여기서는 PASS로 처리 + disable 권고
    STATUS="PASS"
    REASON_LINE="메일 서비스가 비활성(미사용) 상태라 expn/vrfy 요청을 처리하지 않아 이 항목에 대한 보안 위협이 없습니다."
    DETAIL_CONTENT="(판정 결과) 설치되어 있으나 서비스가 비활성 상태\n(권고) 미사용 시 systemctl disable --now <서비스명>으로 중지/비활성화 권장\n(대상 파일) ${TARGET_FILE}"
  else
    if [ $VULNERABLE -eq 1 ]; then
      STATUS="FAIL"
      REASON_LINE="설정 파일에서 expn/vrfy 제한 설정이 미흡하여 취약합니다."
      DETAIL_CONTENT="(판정 근거)\n- $(printf "%s\n" "${FAIL_PARTS[@]}" | awk 'NF' | sed 's/$/\n- /' | sed '$ s/\n- $//')\n(간단 조치)\n- Sendmail: /etc/mail/sendmail.cf PrivacyOptions에 goaway 또는 noexpn,novrfy 추가 후 재시작\n- Postfix: /etc/postfix/main.cf에 disable_vrfy_command = yes 설정 후 postfix reload\n- Exim: acl_smtp_vrfy=accept / acl_smtp_expn=accept 설정 제거(또는 제한) 후 재시작\n(대상 파일/해시)\n${HASH_SUMMARY}"
    else
      STATUS="PASS"
      REASON_LINE="설정 파일에서 expn/vrfy 제한 설정이 확인되어 이 항목에 대한 보안 위협이 없습니다."
      DETAIL_CONTENT="(판정 결과)\n- $(printf "%s\n" "${PASS_PARTS[@]}" | awk 'NF' | sed 's/$/\n- /' | sed '$ s/\n- $//')\n(대상 파일/해시)\n${HASH_SUMMARY}"
    fi
  fi
fi

RAW_EVIDENCE_JSON="$(cat <<EOF
{
  "command":"$(escape_json_str "$CHECK_COMMAND")",
  "detail":"$(escape_json_str "${REASON_LINE}\n${DETAIL_CONTENT}")",
  "target_file":"$(escape_json_str "$TARGET_FILE")"
}
EOF
)"

RAW_EVIDENCE_ESCAPED="$(escape_json_str "$RAW_EVIDENCE_JSON")"

# JSON 출력 직전 빈 줄(프로젝트 규칙)
echo ""
cat <<EOF
{
  "item_code": "$ID",
  "status": "$STATUS",
  "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
  "scan_date": "$SCAN_DATE"
}
EOF