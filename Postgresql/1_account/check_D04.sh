#!/bin/bash
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-04
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : DBMS 관리자 권한을 꼭 필요한 계정 및 그룹에 대해서만 허용
# @Description : 관리자 권한이 필요한 계정 및 그룹에만 관리자 권한을 부여하였는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================


COMMON_FILE="$(cd "$(dirname "$0")/.." && pwd)/_pg_common.sh"
# shellcheck disable=SC1090
. "$COMMON_FILE"
load_pg_env

# D-04: 관리자 권한 최소화 (출력 형식만 scan_history로 통일, 로직 유지)

ID="D-04"
STATUS="FAIL"
EVIDENCE="N/A"
GUIDE_MSG="N/A"

ALLOWED_SUPERUSERS="${ALLOWED_SUPERUSERS:-postgres}"
# 정책 허용 계정 + 실제 점검/조치 접속 관리자 계정(POSTGRES_USER/PG_SUPERUSER)을 모두 허용 목록으로 사용
MERGED_ALLOWED="${ALLOWED_SUPERUSERS},${POSTGRES_USER},${PG_SUPERUSER}"
ALLOWED_SUPERUSERS_MERGED="$(printf '%s' "$MERGED_ALLOWED" | tr ',' '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sed '/^$/d' | awk '!seen[$0]++' | paste -sd, -)"
[ -z "$ALLOWED_SUPERUSERS_MERGED" ] && ALLOWED_SUPERUSERS_MERGED="postgres"

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
  # JSON 문자열 안전 처리: \, ", 줄바꿈
  echo "$1" | sed ':a;N;$!ba;s/\n/\\n/g' | sed 's/\\/\\\\/g; s/"/\\"/g'
}

SQL_LIST=""
IFS=',' read -r -a _allowed_roles <<< "$ALLOWED_SUPERUSERS_MERGED"
for role in "${_allowed_roles[@]}"; do
  role="${role#"${role%%[![:space:]]*}"}"
  role="${role%"${role##*[![:space:]]}"}"
  [ -z "$role" ] && continue
  SQL_LIST="${SQL_LIST}'${role}',"
done
SQL_LIST="${SQL_LIST%,}"
[ -z "$SQL_LIST" ] && SQL_LIST="'postgres'"

EXTRA_ADMINS=$(run_psql "
SELECT rolname
FROM pg_roles
WHERE rolsuper = true
  AND rolname NOT IN (${SQL_LIST})
ORDER BY rolname;
")

if [ $? -ne 0 ]; then
  STATUS="FAIL"
  EVIDENCE="SUPERUSER 목록 조회 실패"
  GUIDE_MSG="postgres 계정 접근 권한을 확인하십시오."
elif [ -z "$EXTRA_ADMINS" ]; then
  STATUS="PASS"
  EVIDENCE="허용 목록(${ALLOWED_SUPERUSERS_MERGED}) 외 SUPERUSER 계정 없음"
  GUIDE_MSG="현재 기준에서 추가 조치가 필요하지 않습니다."
else
  STATUS="FAIL"
  EVIDENCE="허용 목록 외 SUPERUSER 계정: $(echo "$EXTRA_ADMINS" | tr '\n' ',' | sed 's/,$//')"
  GUIDE_MSG="불필요 계정에 대해 ALTER ROLE <계정명> NOSUPERUSER; ALTER ROLE <계정명> NOCREATEROLE; ALTER ROLE <계정명> NOCREATEDB; ALTER ROLE <계정명> NOREPLICATION; ALTER ROLE <계정명> NOBYPASSRLS; 로 관리자 권한을 회수하십시오."
fi

SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
CHECK_COMMAND="(psql) SELECT rolname FROM pg_roles WHERE rolsuper=true AND rolname NOT IN (${SQL_LIST});"
TARGET_FILE="pg_roles"

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