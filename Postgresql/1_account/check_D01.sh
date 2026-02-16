#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.1
# @Author: 윤영아
# @Last Updated: 2026-02-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-01
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : 기본 계정의 비밀번호, 정책 등을 변경하여 사용
# @Description : DBMS 기본 계정의 초기 비밀번호 및 권한 정책 변경 사용 유무 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

COMMON_FILE="$(cd "$(dirname "$0")/.." && pwd)/_pg_common.sh"
# shellcheck disable=SC1090
. "$COMMON_FILE"
load_pg_env

# D-01: 기본 계정의 비밀번호, 정책 등을 변경하여 사용 (PostgreSQL)

ID="D-01"

STATUS="FAIL"
EVIDENCE="N/A"
GUIDE_MSG="N/A"

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

escape_json_str() {
  echo "$1" | sed ':a;N;$!ba;s/\n/\\n/g' | sed 's/\\/\\\\/g; s/"/\\"/g'
}

VULN_USERS=$(run_psql "
SELECT s.usename
FROM pg_shadow s
JOIN pg_roles r ON r.rolname = s.usename
WHERE r.rolsuper = true
  AND (s.passwd IS NULL OR s.passwd = '');
")

if [ $? -ne 0 ]; then
  STATUS="FAIL"
  EVIDENCE="SUPERUSER 비밀번호 설정 상태를 조회하지 못하여 점검을 수행할 수 없습니다.\n조치 방법은 postgres 계정으로 pg_shadow 조회 권한과 접속 정보를 확인해주시기 바랍니다."
  GUIDE_MSG="pg_shadow 조회 권한 및 접속 설정을 확인해주시기 바랍니다."
elif [ -z "$VULN_USERS" ]; then
  STATUS="PASS"
  EVIDENCE="SUPERUSER 계정에 비밀번호가 설정되어 있으며 비밀번호 미설정 계정이 확인되지 않으므로 이 항목에 대한 보안 위협이 없습니다."
  GUIDE_MSG="현재 기준에서 추가 조치가 필요하지 않습니다."
else
  STATUS="FAIL"
  EVIDENCE="비밀번호가 설정되지 않은 SUPERUSER 계정이 확인되어 관리자 계정 탈취 및 권한 오남용 위험이 있습니다.\n조치 방법은 해당 SUPERUSER 계정에 강력한 비밀번호를 설정해주시기 바랍니다."
  GUIDE_MSG="비밀번호 미설정 SUPERUSER 계정은 $(echo "$VULN_USERS" | tr '\n' ',' | sed 's/,$//') 입니다. 예) ALTER ROLE <계정명> WITH PASSWORD '<강력한 비밀번호>'; 를 적용해주시기 바랍니다."
fi

SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
CHECK_COMMAND="(psql 접속) SUPERUSER 중 passwd NULL/공란 계정 조회"
TARGET_FILE="pg_shadow"

REASON_LINE="$EVIDENCE"
DETAIL_CONTENT="$GUIDE_MSG"

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