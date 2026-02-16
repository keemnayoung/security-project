#!/bin/bash
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.1
# @Author: 윤영아
# @Last Updated: 2026-02-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-08
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : 안전한 암호화 알고리즘 사용
# @Description : 해시 알고리즘 SHA-256 이상의 암호화 알고리즘을 사용하는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================


COMMON_FILE="$(cd "$(dirname "$0")/.." && pwd)/_pg_common.sh"
# shellcheck disable=SC1090
. "$COMMON_FILE"
load_pg_env

# D-08: 안전한 암호화 알고리즘 사용 점검 (로직 유지, 출력 형식(scan_history)만 통일)
# 기준:
# 1) pg_hba.conf(auth_method)에 md5가 존재하면 FAIL
# 2) 로그인 계정 해시(rolpassword)가 SCRAM-SHA-256이 아니면 FAIL

ID="D-08"
STATUS="FAIL"
EVIDENCE="N/A"

TARGET_FILE="pg_hba_file_rules,pg_authid.rolpassword"
CHECK_COMMAND="(pg_hba_file_rules의 md5 규칙 조회) + (pg_authid 로그인 계정 rolpassword SCRAM 여부 점검)"

run_psql() {
  local sql="$1"
  if PGPASSWORD="${POSTGRES_PASSWORD:-}" psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DB" -t -A -q -c "$sql" 2>/dev/null; then
    return 0
  fi
  if command -v sudo >/dev/null 2>&1; then
    sudo -u "$PG_SUPERUSER" psql -d "$POSTGRES_DB" -t -A -q -c "$sql" 2>/dev/null
    return $?
  fi
  return 1
}

format_md5_rules() {
  local rows="$1"
  local out=""
  while IFS='|' read -r ln typ db usr addr; do
    [ -n "$typ" ] || continue
    out="${out}${typ} db=${db} user=${usr} addr=${addr},"
  done <<< "$rows"
  printf "%s" "${out%,}"
}

format_non_scram() {
  local rows="$1"
  local out=""
  while IFS='|' read -r role algo; do
    [ -z "$role" ] && continue
    out="${out}${role}(${algo}),"
  done <<< "$rows"
  printf "%s" "${out%,}"
}

# pg_hba_file_rules에서 auth_method=md5 규칙 조회
MD5_RULE_ROWS=$(run_psql "
SELECT line_number || '|' || type || '|' ||
       COALESCE(array_to_string(database, ','), '') || '|' ||
       COALESCE(array_to_string(user_name, ','), '') || '|' ||
       COALESCE(address, 'local')
FROM pg_hba_file_rules
WHERE error IS NULL
  AND lower(auth_method) = 'md5'
ORDER BY line_number;
")

if [ $? -ne 0 ]; then
  STATUS="FAIL"
  EVIDENCE="pg_hba_file_rules를 조회하지 못하여 md5 인증 규칙 존재 여부를 점검할 수 없습니다.\n조치 방법은 접속 계정의 조회 권한과 PostgreSQL 상태를 확인해주시기 바랍니다."
  REASON_LINE="${EVIDENCE}"
  DETAIL_CONTENT="pg_hba_file_rules 조회 권한 및 DB 상태를 점검해주시기 바랍니다."
else
  # 로그인 가능 계정 중 SCRAM-SHA-256 미사용(또는 비밀번호 미설정) 계정 조회
  NON_SCRAM_ROWS=$(run_psql "
SELECT rolname || '|' ||
       CASE
         WHEN COALESCE(rolpassword, '') = '' THEN 'NO_PASSWORD'
         WHEN rolpassword LIKE 'SCRAM-SHA-256$%' THEN 'SCRAM-SHA-256'
         WHEN rolpassword LIKE 'md5%' THEN 'MD5'
         ELSE 'OTHER'
       END
FROM pg_authid
WHERE rolcanlogin = true
  AND rolname NOT LIKE 'pg_%'
  AND (
    COALESCE(rolpassword, '') = ''
    OR rolpassword NOT LIKE 'SCRAM-SHA-256$%'
  )
ORDER BY rolname;
")

  if [ $? -ne 0 ]; then
    STATUS="FAIL"
    EVIDENCE="pg_authid를 조회하지 못하여 계정별 해시 알고리즘을 점검할 수 없습니다.\n조치 방법은 PostgreSQL 접속 권한과 pg_authid 조회 권한을 확인해주시기 바랍니다."
    REASON_LINE="${EVIDENCE}"
    DETAIL_CONTENT="POSTGRES_USER 또는 PG_SUPERUSER 권한 및 pg_authid 조회 권한을 점검해주시기 바랍니다."
  else
    MD5_DESC="$(format_md5_rules "$MD5_RULE_ROWS")"
    NON_SCRAM_DESC="$(format_non_scram "$NON_SCRAM_ROWS")"

    if [ -z "$MD5_DESC" ] && [ -z "$NON_SCRAM_DESC" ]; then
      STATUS="PASS"
      EVIDENCE="md5 인증 규칙이 확인되지 않고, 모든 로그인 계정이 SCRAM-SHA-256을 사용하고 있으므로 이 항목에 대한 보안 위협이 없습니다."
      REASON_LINE="${EVIDENCE}"
      DETAIL_CONTENT="현재 기준에서 추가 조치가 필요하지 않습니다."
    else
      STATUS="FAIL"
      if [ -n "$MD5_DESC" ] && [ -n "$NON_SCRAM_DESC" ]; then
        EVIDENCE="md5 인증 규칙이 존재하고 SCRAM-SHA-256을 사용하지 않는 로그인 계정이 확인되어 계정 탈취 및 무차별 대입 공격 위험이 있습니다.\n조치 방법은 pg_hba.conf에서 md5 인증 규칙을 제거하고, 해당 계정의 비밀번호를 SCRAM-SHA-256 방식으로 재설정한 뒤 재검증해주시기 바랍니다."
      elif [ -n "$MD5_DESC" ]; then
        EVIDENCE="md5 인증 규칙이 존재하여 약한 해시 기반 인증이 사용될 수 있어 계정 탈취 위험이 있습니다.\n조치 방법은 pg_hba.conf에서 md5 인증 규칙을 제거하고 SCRAM-SHA-256 기반 인증으로 전환한 뒤 재검증해주시기 바랍니다."
      else
        EVIDENCE="SCRAM-SHA-256을 사용하지 않는 로그인 계정이 확인되어 비밀번호 유출 및 계정 탈취 위험이 있습니다.\n조치 방법은 해당 계정의 비밀번호를 SCRAM-SHA-256 방식으로 재설정하고 재검증해주시기 바랍니다."
      fi
      REASON_LINE="${EVIDENCE}"
      DETAIL_CONTENT="md5 인증 규칙은 ${MD5_DESC:-없음} 이며, SCRAM-SHA-256 미사용 계정은 ${NON_SCRAM_DESC:-없음} 입니다. md5 규칙 제거 및 계정 비밀번호 재설정 후 재점검해주시기 바랍니다."
    fi
  fi
fi

SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

escape_json_str() {
  echo "$1" | sed ':a;N;$!ba;s/\n/\\n/g' | sed 's/\\"/\\\\"/g; s/"/\\"/g'
}

RAW_EVIDENCE_JSON=$(cat <<EOF
{
  "command":"$(escape_json_str "$CHECK_COMMAND")",
  "detail":"$(escape_json_str "${REASON_LINE}\n${DETAIL_CONTENT}")",
  "target_file":"$(escape_json_str "$TARGET_FILE")"
}
EOF
)

RAW_EVIDENCE_ESCAPED="$(escape_json_str "$RAW_EVIDENCE_JSON")"

echo ""
cat <<EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF