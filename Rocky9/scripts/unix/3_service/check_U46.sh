#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-46
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 일반 사용자의 메일 서비스 실행 방지
# @Description : SMTP 서비스 사용 시 일반 사용자의 q 옵션 제한 여부 점검
# @Criteria_Good : 메일 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정
# @Criteria_Bad : 메일 서비스 사용 시 메일 서비스의 q 옵션 제한 설정
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-46 일반 사용자의 메일 서비스 실행 방지

# 1. 항목 정보 정의
ID="U-46"
CATEGORY="서비스 관리"
TITLE="일반 사용자의 메일 서비스 실행 방지"
IMPORTANCE="상"

# 2. 진단 로직
STATUS="PASS"
VULNERABLE=0

EVIDENCE_LINES=""
TARGET_FILES=()
FILE_HASH="NOT_FOUND"

# 판정 보조 함수: others execute(x) 여부 확인
# - perms: 3자리(예: 755)
# - others 자릿수의 x(1) 비트가 켜져 있으면 일반 사용자 실행 가능
is_others_exec_on() {
  local p="$1"
  [[ "$p" =~ ^[0-9]{3,4}$ ]] || return 2
  local o=$(( p % 10 ))
  (( (o & 1) == 1 ))
}

append_evidence() {
  local line="$1"
  if [ -z "$EVIDENCE_LINES" ]; then
    EVIDENCE_LINES="$line"
  else
    EVIDENCE_LINES="${EVIDENCE_LINES}\n- $line"
  fi
}

add_target_file() {
  local f="$1"
  [ -n "$f" ] && TARGET_FILES+=("$f")
}

# [Sendmail] - PrivacyOptions에 restrictqrun 포함 여부
# - sendmail.cf 내 표기: "O PrivacyOptions=..." 또는 "PrivacyOptions=..."
if command -v sendmail >/dev/null 2>&1; then
  CF_FILE=""
  [ -f /etc/mail/sendmail.cf ] && CF_FILE="/etc/mail/sendmail.cf"
  [ -z "$CF_FILE" ] && [ -f /etc/sendmail.cf ] && CF_FILE="/etc/sendmail.cf"

  if [ -n "$CF_FILE" ]; then
    add_target_file "$CF_FILE"

    # 주석(#) 제외, PrivacyOptions 설정 라인만 추출
    PRIVACY_LINE="$(grep -iE '^[[:space:]]*(O[[:space:]]+)?PrivacyOptions([[:space:]]*=|[[:space:]]+)' "$CF_FILE" 2>/dev/null | grep -v '^[[:space:]]*#' | tail -n 1)"

    if [ -z "$PRIVACY_LINE" ]; then
      VULNERABLE=1
      append_evidence "sendmail: ${CF_FILE}에 PrivacyOptions 설정 라인이 없어 취약합니다."
    else
      if echo "$PRIVACY_LINE" | grep -qi 'restrictqrun'; then
        append_evidence "sendmail: ${CF_FILE}의 PrivacyOptions에 restrictqrun이 포함되어 있어 이 항목에 대한 보안 위협이 없습니다."
      else
        VULNERABLE=1
        append_evidence "sendmail: ${CF_FILE}의 PrivacyOptions에 restrictqrun이 없어 취약합니다. (현재: ${PRIVACY_LINE})"
      fi
    fi
  else
    append_evidence "sendmail: 설치는 되어 있으나 sendmail.cf 파일을 찾지 못해 설정 확인이 제한됩니다."
  fi
fi

# [Postfix] - /usr/sbin/postsuper 일반 사용자 실행(o+x) 여부
if command -v postsuper >/dev/null 2>&1; then
  POSTSUPER="/usr/sbin/postsuper"
  if [ -f "$POSTSUPER" ]; then
    add_target_file "$POSTSUPER"
    PERMS="$(stat -c '%a' "$POSTSUPER" 2>/dev/null)"

    if [ -z "$PERMS" ]; then
      VULNERABLE=1
      append_evidence "postfix: ${POSTSUPER} 권한을 확인하지 못해 취약 여부 판단이 불가합니다.(stat 실패)"
    else
      if is_others_exec_on "$PERMS"; then
        VULNERABLE=1
        append_evidence "postfix: ${POSTSUPER}에 others 실행 권한(o+x)이 있어 취약합니다. (현재: ${PERMS})"
      else
        append_evidence "postfix: ${POSTSUPER}에 others 실행 권한(o+x)이 없어 이 항목에 대한 보안 위협이 없습니다. (현재: ${PERMS})"
      fi
    fi
  else
    append_evidence "postfix: postsuper 명령은 존재하나 ${POSTSUPER} 파일이 없어 확인이 제한됩니다."
  fi
fi

# [Exim] - /usr/sbin/exiqgrep 일반 사용자 실행(o+x) 여부
EXIQGREP="/usr/sbin/exiqgrep"
if [ -f "$EXIQGREP" ]; then
  add_target_file "$EXIQGREP"
  PERMS="$(stat -c '%a' "$EXIQGREP" 2>/dev/null)"

  if [ -z "$PERMS" ]; then
    VULNERABLE=1
    append_evidence "exim: ${EXIQGREP} 권한을 확인하지 못해 취약 여부 판단이 불가합니다.(stat 실패)"
  else
    if is_others_exec_on "$PERMS"; then
      VULNERABLE=1
      append_evidence "exim: ${EXIQGREP}에 others 실행 권한(o+x)이 있어 취약합니다. (현재: ${PERMS})"
    else
      append_evidence "exim: ${EXIQGREP}에 others 실행 권한(o+x)이 없어 이 항목에 대한 보안 위협이 없습니다. (현재: ${PERMS})"
    fi
  fi
fi

# 메일 서비스가 전혀 없는 경우
if [ ${#TARGET_FILES[@]} -eq 0 ]; then
  STATUS="PASS"
  REASON_LINE="메일 서비스가 설치되어 있지 않아 점검 대상이 없으며 이 항목에 대한 보안 위협이 없습니다."
  DETAIL_CONTENT="(판정 결과) 메일 서비스(sendmail/postfix/exim) 관련 점검 대상이 발견되지 않았습니다."
else
  if [ "$VULNERABLE" -eq 1 ]; then
    STATUS="FAIL"
    REASON_LINE="점검 대상에서 일반 사용자가 메일 큐/서비스 관련 기능을 실행할 수 있는 설정/권한이 확인되어 취약합니다."
    DETAIL_CONTENT="(판정 근거)\n- ${EVIDENCE_LINES}\n\n(간단 조치)\n- sendmail: sendmail.cf의 PrivacyOptions에 restrictqrun 추가 후 서비스 재시작\n- postfix: /usr/sbin/postsuper 일반 사용자 실행 권한 제거(chmod o-x /usr/sbin/postsuper)\n- exim: /usr/sbin/exiqgrep 일반 사용자 실행 권한 제거(chmod o-x /usr/sbin/exiqgrep)"
  else
    STATUS="PASS"
    REASON_LINE="점검 대상에서 일반 사용자 메일 서비스(메일 큐) 실행 제한이 설정되어 있어 이 항목에 대한 보안 위협이 없습니다."
    DETAIL_CONTENT="(판정 결과)\n- ${EVIDENCE_LINES}"
  fi
fi

# 대상 파일 문자열 구성 + 해시(가능한 경우 1개만 대표로 산출: 첫 번째 파일)
TARGET_FILE="$(printf "%s\n" "${TARGET_FILES[@]}" | awk 'NF')"
REP_FILE="$(printf "%s\n" "${TARGET_FILES[@]}" | head -n 1)"
if [ -n "$REP_FILE" ] && [ -f "$REP_FILE" ]; then
  FILE_HASH="$(sha256sum "$REP_FILE" 2>/dev/null | awk '{print $1}')"
  [ -z "$FILE_HASH" ] && FILE_HASH="HASH_ERROR"
else
  FILE_HASH="NOT_FOUND"
fi

# 3. 최종 출력(scan_history)
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

CHECK_COMMAND="(command -v sendmail >/dev/null 2>&1 && (grep -iE '^[[:space:]]*(O[[:space:]]+)?PrivacyOptions' /etc/mail/sendmail.cf 2>/dev/null | grep -v '^#' || grep -iE '^[[:space:]]*(O[[:space:]]+)?PrivacyOptions' /etc/sendmail.cf 2>/dev/null | grep -v '^#')); (command -v postsuper >/dev/null 2>&1 && stat -c '%a %n' /usr/sbin/postsuper 2>/dev/null); (test -f /usr/sbin/exiqgrep && stat -c '%a %n' /usr/sbin/exiqgrep 2>/dev/null)"

escape_json_str() {
  printf '%s' "$1" | sed ':a;N;$!ba;s/\\/\\\\/g;s/\n/\\n/g;s/"/\\"/g'
}

RAW_EVIDENCE_JSON="$(cat <<EOF
{
  "command":"$(escape_json_str "$CHECK_COMMAND")",
  "detail":"$(escape_json_str "${REASON_LINE}\n${DETAIL_CONTENT}\n(대상 파일)\n${TARGET_FILE}\n(대표 해시) ${REP_FILE} (sha256=${FILE_HASH})")",
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