#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.0
# @Author: 이가영
# @Last Updated: 2026-02-15
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-46
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 일반 사용자의 메일 서비스 실행 방지
# @Description : SMTP 서비스 사용 시 일반 사용자의 q 옵션 제한 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-46 일반 사용자의 메일 서비스 실행 방지

# 1. 항목 정보 정의
ID="U-46"
CATEGORY="서비스 관리"
TITLE="일반 사용자의 메일 서비스 실행 방지"
IMPORTANCE="상"

# 2. 조치 로직
STATUS="PASS"
ACTION_LOG=""
TARGET_FILES=()

# 권한 판정: others execute(x) 여부 (o 자리의 x 비트=1이면 실행 가능)
is_others_exec_on() {
  local p="$1"
  [[ "$p" =~ ^[0-9]{3,4}$ ]] || return 2
  local o=$(( p % 10 ))
  (( (o & 1) == 1 ))
}

add_target_file() {
  local f="$1"
  [ -n "$f" ] && TARGET_FILES+=("$f")
}

# -----------------------
# [Sendmail] - restrictqrun 적용
# -----------------------
SENDMAIL_CF=""
if command -v sendmail >/dev/null 2>&1; then
  [ -f /etc/mail/sendmail.cf ] && SENDMAIL_CF="/etc/mail/sendmail.cf"
  [ -z "$SENDMAIL_CF" ] && [ -f /etc/sendmail.cf ] && SENDMAIL_CF="/etc/sendmail.cf"

  if [ -n "$SENDMAIL_CF" ]; then
    add_target_file "$SENDMAIL_CF"

    # 주석 제외 PrivacyOptions 라인(대표 1개) 확인
    PRIV_LINE="$(grep -iE '^[[:space:]]*(O[[:space:]]+)?PrivacyOptions([[:space:]]*=|[[:space:]]+)' "$SENDMAIL_CF" 2>/dev/null | grep -v '^[[:space:]]*#' | tail -n 1)"

    if [ -z "$PRIV_LINE" ]; then
      # 라인 자체가 없으면 최소 설정을 추가
      echo "O PrivacyOptions=restrictqrun" >> "$SENDMAIL_CF"
      ACTION_LOG="${ACTION_LOG} sendmail: PrivacyOptions 라인이 없어 restrictqrun 라인을 추가했습니다."
    else
      if echo "$PRIV_LINE" | grep -qi 'restrictqrun'; then
        ACTION_LOG="${ACTION_LOG} sendmail: restrictqrun이 이미 설정되어 있어 변경하지 않았습니다."
      else
        # 기존 라인에 restrictqrun 추가 (O PrivacyOptions=... 또는 PrivacyOptions=... 모두 처리)
        # 1) '...=' 뒤에 토큰들을 보존하면서 마지막에 ,restrictqrun 추가
        sed -i -r '/^[[:space:]]*(O[[:space:]]+)?PrivacyOptions[[:space:]]*=/I {
          /restrictqrun/I! s/[[:space:]]*$//;
          /restrictqrun/I! s/$/,restrictqrun/;
        }' "$SENDMAIL_CF"
        ACTION_LOG="${ACTION_LOG} sendmail: PrivacyOptions에 restrictqrun을 추가했습니다."
      fi
    fi

    # 서비스 재시작(가능한 경우만)
    if command -v systemctl >/dev/null 2>&1; then
      systemctl restart sendmail 2>/dev/null || true
    fi
  fi
fi

# -----------------------
# [Postfix] - postsuper others 실행 권한 제거
# -----------------------
POSTSUPER="/usr/sbin/postsuper"
if [ -f "$POSTSUPER" ]; then
  add_target_file "$POSTSUPER"
  PERMS="$(stat -c '%a' "$POSTSUPER" 2>/dev/null)"
  if [ -z "$PERMS" ]; then
    STATUS="FAIL"
    ACTION_LOG="${ACTION_LOG} postfix: postsuper 권한 정보를 확인하지 못해 조치가 완료되지 않았습니다."
  else
    if is_others_exec_on "$PERMS"; then
      chmod o-x "$POSTSUPER" 2>/dev/null || true
      ACTION_LOG="${ACTION_LOG} postfix: postsuper의 others 실행 권한(o+x)을 제거했습니다."
    else
      ACTION_LOG="${ACTION_LOG} postfix: postsuper의 others 실행 권한(o+x)이 없어 변경하지 않았습니다."
    fi
  fi
fi

# -----------------------
# [Exim] - exiqgrep others 실행 권한 제거
# -----------------------
EXIQGREP="/usr/sbin/exiqgrep"
if [ -f "$EXIQGREP" ]; then
  add_target_file "$EXIQGREP"
  PERMS="$(stat -c '%a' "$EXIQGREP" 2>/dev/null)"
  if [ -z "$PERMS" ]; then
    STATUS="FAIL"
    ACTION_LOG="${ACTION_LOG} exim: exiqgrep 권한 정보를 확인하지 못해 조치가 완료되지 않았습니다."
  else
    if is_others_exec_on "$PERMS"; then
      chmod o-x "$EXIQGREP" 2>/dev/null || true
      ACTION_LOG="${ACTION_LOG} exim: exiqgrep의 others 실행 권한(o+x)을 제거했습니다."
    else
      ACTION_LOG="${ACTION_LOG} exim: exiqgrep의 others 실행 권한(o+x)이 없어 변경하지 않았습니다."
    fi
  fi
fi

# -----------------------
# 조치 후 최종 검증(현재 설정만 수집)
# -----------------------
VERIFY_FAIL=0
AFTER_LINES=""

# sendmail after
if [ -n "$SENDMAIL_CF" ] && [ -f "$SENDMAIL_CF" ]; then
  AFTER_PRIV="$(grep -iE '^[[:space:]]*(O[[:space:]]+)?PrivacyOptions([[:space:]]*=|[[:space:]]+)' "$SENDMAIL_CF" 2>/dev/null | grep -v '^[[:space:]]*#' | tail -n 1)"
  if [ -z "$AFTER_PRIV" ]; then
    VERIFY_FAIL=1
    AFTER_LINES="${AFTER_LINES}- sendmail: PrivacyOptions 라인이 없어 취약 상태입니다.\n"
  else
    if echo "$AFTER_PRIV" | grep -qi 'restrictqrun'; then
      AFTER_LINES="${AFTER_LINES}- sendmail: ${SENDMAIL_CF}의 PrivacyOptions에 restrictqrun이 적용되어 있습니다. (현재: ${AFTER_PRIV})\n"
    else
      VERIFY_FAIL=1
      AFTER_LINES="${AFTER_LINES}- sendmail: ${SENDMAIL_CF}의 PrivacyOptions에 restrictqrun이 없어 취약 상태입니다. (현재: ${AFTER_PRIV})\n"
    fi
  fi
fi

# postfix after
if [ -f "$POSTSUPER" ]; then
  AFTER_P="$(stat -c '%a' "$POSTSUPER" 2>/dev/null)"
  if [ -z "$AFTER_P" ]; then
    VERIFY_FAIL=1
    AFTER_LINES="${AFTER_LINES}- postfix: ${POSTSUPER} 권한을 재확인하지 못해 취약 여부 판단이 불가합니다.\n"
  else
    if is_others_exec_on "$AFTER_P"; then
      VERIFY_FAIL=1
      AFTER_LINES="${AFTER_LINES}- postfix: ${POSTSUPER}에 others 실행 권한(o+x)이 남아 있어 취약 상태입니다. (현재: ${AFTER_P})\n"
    else
      AFTER_LINES="${AFTER_LINES}- postfix: ${POSTSUPER}에 others 실행 권한(o+x)이 없어 양호 상태입니다. (현재: ${AFTER_P})\n"
    fi
  fi
fi

# exim after
if [ -f "$EXIQGREP" ]; then
  AFTER_E="$(stat -c '%a' "$EXIQGREP" 2>/dev/null)"
  if [ -z "$AFTER_E" ]; then
    VERIFY_FAIL=1
    AFTER_LINES="${AFTER_LINES}- exim: ${EXIQGREP} 권한을 재확인하지 못해 취약 여부 판단이 불가합니다.\n"
  else
    if is_others_exec_on "$AFTER_E"; then
      VERIFY_FAIL=1
      AFTER_LINES="${AFTER_LINES}- exim: ${EXIQGREP}에 others 실행 권한(o+x)이 남아 있어 취약 상태입니다. (현재: ${AFTER_E})\n"
    else
      AFTER_LINES="${AFTER_LINES}- exim: ${EXIQGREP}에 others 실행 권한(o+x)이 없어 양호 상태입니다. (현재: ${AFTER_E})\n"
    fi
  fi
fi

# 대상이 하나도 없으면(메일 서비스 미설치/미존재) PASS 처리
if [ ${#TARGET_FILES[@]} -eq 0 ]; then
  STATUS="PASS"
  REASON_LINE="메일 서비스 관련 점검 대상이 없어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
  DETAIL_CONTENT="(조치 후 설정)\n- 점검 대상 파일/바이너리가 발견되지 않았습니다."
else
  if [ "$VERIFY_FAIL" -eq 1 ] || [ "$STATUS" = "FAIL" ]; then
    STATUS="FAIL"
    REASON_LINE="조치 이후에도 일반 사용자의 메일 서비스 실행 제한이 완전히 적용되지 않아 취약합니다."
  else
    STATUS="PASS"
    REASON_LINE="조치 이후 설정/권한이 기준에 부합하여 이 항목에 대한 보안 위협이 없습니다."
  fi

  [ -z "$ACTION_LOG" ] && ACTION_LOG="변경 사항이 없습니다."
  DETAIL_CONTENT="(조치 내역) ${ACTION_LOG}\n\n(조치 후 설정)\n${AFTER_LINES}"
fi

TARGET_FILE="$(printf "%s\n" "${TARGET_FILES[@]}" | awk 'NF')"

# ===== 출력 포맷(scan_history) =====
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
CHECK_COMMAND="(command -v sendmail >/dev/null 2>&1 && (grep -iE '^[[:space:]]*(O[[:space:]]+)?PrivacyOptions' /etc/mail/sendmail.cf 2>/dev/null | grep -v '^#' || grep -iE '^[[:space:]]*(O[[:space:]]+)?PrivacyOptions' /etc/sendmail.cf 2>/dev/null | grep -v '^#')); ([ -f /usr/sbin/postsuper ] && stat -c '%a %n' /usr/sbin/postsuper 2>/dev/null); ([ -f /usr/sbin/exiqgrep ] && stat -c '%a %n' /usr/sbin/exiqgrep 2>/dev/null)"

json_escape() {
  # backslash/quote/newline escape
  printf '%s' "$1" | sed ':a;N;$!ba;s/\\/\\\\/g;s/\n/\\n/g;s/"/\\"/g'
}

RAW_EVIDENCE_JSON="$(cat <<EOF
{
  "command":"$(json_escape "$CHECK_COMMAND")",
  "detail":"$(json_escape "${REASON_LINE}\n${DETAIL_CONTENT}")",
  "target_file":"$(json_escape "$TARGET_FILE")"
}
EOF
)"

RAW_EVIDENCE_ESCAPED="$(json_escape "$RAW_EVIDENCE_JSON")"

echo ""
cat <<EOF
{
  "item_code": "$ID",
  "status": "$STATUS",
  "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
  "scan_date": "$SCAN_DATE"
}
EOF