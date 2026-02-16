#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.1
# @Author: 한은결
# @Last Updated: 2026-02-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-03
# @Category    : 계정 관리
# @Platform    : MySQL
# @Severity    : 상
# @Title       : 비밀번호 사용 기간 및 복잡도 정책 설정
# @Description : 기관 정책에 맞게 비밀번호 사용 기간 및 복잡도 정책이 적용되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-03"
STATUS="FAIL"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="mysql.system_variables"

TIMEOUT_BIN="$(command -v timeout 2>/dev/null || true)"
MYSQL_TIMEOUT=5
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"
export MYSQL_PWD="${MYSQL_PASSWORD}"
MYSQL_CMD_BASE="mysql --protocol=TCP -u${MYSQL_USER} -N -s -B -e"

is_integer() { [[ "$1" =~ ^[0-9]+$ ]]; }

run_mysql_query() {
  local query="$1"
  # 무한 대기 방지(timeout 있으면 적용)
  if [[ -n "$TIMEOUT_BIN" ]]; then
    $TIMEOUT_BIN "${MYSQL_TIMEOUT}s" $MYSQL_CMD_BASE "$query" 2>/dev/null || echo "ERROR_TIMEOUT"
  else
    $MYSQL_CMD_BASE "$query" 2>/dev/null || echo "ERROR"
  fi
}

# SQL 비밀번호 만료(default_password_lifetime) + validate_password(컴포넌트/플러그인) 관련 변수 조회
QUERY="
SHOW VARIABLES
WHERE Variable_name IN (
  'default_password_lifetime',
  'validate_password.policy',
  'validate_password.length',
  'validate_password.mixed_case_count',
  'validate_password.number_count',
  'validate_password.special_char_count',
  'validate_password_policy',
  'validate_password_length',
  'validate_password_mixed_case_count',
  'validate_password_number_count',
  'validate_password_special_char_count'
);
"

RESULT="$(run_mysql_query "$QUERY")"

REASON_LINE=""
DETAIL_CONTENT=""

# 실행 실패 분기(타임아웃/접속 오류)
if [[ "$RESULT" == "ERROR_TIMEOUT" ]]; then
  STATUS="FAIL"
  REASON_LINE="비밀번호 정책 변수 조회가 제한 시간(${MYSQL_TIMEOUT}초)을 초과하여 D-03 점검을 완료하지 못했습니다.\n조치 방법은 DB 상태/부하 및 접속 옵션을 확인한 뒤 재시도하는 것입니다."
  DETAIL_CONTENT="result=ERROR_TIMEOUT"
elif [[ "$RESULT" == "ERROR" ]]; then
  STATUS="FAIL"
  REASON_LINE="MySQL 접속 실패 또는 권한 부족으로 D-03(비밀번호 기간/복잡도) 점검을 수행할 수 없습니다.\n조치 방법은 진단 계정의 권한과 인증 정보를 확인하는 것입니다."
  DETAIL_CONTENT="result=ERROR"
else
  get_var() {
    local name="$1"
    echo "$RESULT" | awk -v k="$name" '$1==k{print $2; exit}'
  }

  PASSWORD_LIFETIME="$(get_var "default_password_lifetime")"
  POLICY="$(get_var "validate_password.policy")"
  [[ -z "$POLICY" ]] && POLICY="$(get_var "validate_password_policy")"
  LENGTH="$(get_var "validate_password.length")"
  [[ -z "$LENGTH" ]] && LENGTH="$(get_var "validate_password_length")"
  MIXED="$(get_var "validate_password.mixed_case_count")"
  [[ -z "$MIXED" ]] && MIXED="$(get_var "validate_password_mixed_case_count")"
  NUMBER="$(get_var "validate_password.number_count")"
  [[ -z "$NUMBER" ]] && NUMBER="$(get_var "validate_password_number_count")"
  SPECIAL="$(get_var "validate_password.special_char_count")"
  [[ -z "$SPECIAL" ]] && SPECIAL="$(get_var "validate_password_special_char_count")"

  REASONS=()

  # 만료 정책 점검(default_password_lifetime)
  if ! is_integer "$PASSWORD_LIFETIME"; then
    REASONS+=("default_password_lifetime 값을 확인할 수 없습니다.")
  elif [[ "$PASSWORD_LIFETIME" -le 0 ]]; then
    REASONS+=("default_password_lifetime=${PASSWORD_LIFETIME}(0 이하)로 만료 정책이 사실상 미적용 상태입니다.")
  fi

  # validate_password 정책 점검(LOW면 기준 미달)
  if [[ -z "$POLICY" ]]; then
    REASONS+=("validate_password 정책 변수를 확인할 수 없습니다(컴포넌트/플러그인 미적용 가능).")
  else
    POLICY_UPPER="$(echo "$POLICY" | tr '[:lower:]' '[:upper:]')"
    [[ "$POLICY_UPPER" == "LOW" ]] && REASONS+=("validate_password policy=LOW 입니다.")
  fi

  # 최소 길이 점검(기준: 8 이상)
  if ! is_integer "$LENGTH"; then
    REASONS+=("validate_password length 값을 확인할 수 없습니다.")
  elif [[ "$LENGTH" -lt 8 ]]; then
    REASONS+=("validate_password length=${LENGTH}(8 미만) 입니다.")
  fi

  # 조합 규칙 점검(기준: 각 1 이상)
  for rule in "대소문자:$MIXED" "숫자:$NUMBER" "특수문자:$SPECIAL"; do
    label="${rule%%:*}"
    value="${rule#*:}"
    if ! is_integer "$value"; then
      REASONS+=("${label} 최소 개수 값을 확인할 수 없습니다.")
      continue
    fi
    [[ "$value" -lt 1 ]] && REASONS+=("${label} 최소 개수=${value}(1 미만) 입니다.")
  done

  # 판정 분기(PASS/FAIL)
  if [[ "${#REASONS[@]}" -eq 0 ]]; then
    STATUS="PASS"
    REASON_LINE="비밀번호 사용 기간 및 복잡도 정책이 적용되어 있어 이 항목에 대한 보안 위협이 없습니다."
  else
    STATUS="FAIL"
    REASON_LINE="${REASONS[*]}\n조치 방법은 validate_password 컴포넌트/플러그인 적용 여부를 확인하고, default_password_lifetime 및 정책/길이/조합 규칙 값을 기준에 맞게 조정한 뒤 재점검하는 것입니다."
  fi

  DETAIL_CONTENT="default_password_lifetime=${PASSWORD_LIFETIME}, policy=${POLICY}, length=${LENGTH}, mixed=${MIXED}, number=${NUMBER}, special=${SPECIAL}"
  [[ "${#REASONS[@]}" -gt 0 ]] && DETAIL_CONTENT="${DETAIL_CONTENT}\nnon_compliance=${REASONS[*]}"
fi

CHECK_COMMAND="$MYSQL_CMD_BASE \"$QUERY\""
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