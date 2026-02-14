#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-02
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : 데이터베이스의 불필요 계정을 제거하거나, 잠금설정 후 사용
# @Description : DBMS에 존재하는 계정 중 DB 관리나 운용에 사용하지 않는 불필요한 계정이 존재하는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================


#!/bin/bash
COMMON_FILE="$(cd "$(dirname "$0")/.." && pwd)/_pg_common.sh"
# shellcheck disable=SC1090
. "$COMMON_FILE"
load_pg_env

# D-02: 불필요 계정 제거/잠금
ID="D-02"
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
  # JSON 문자열 안전 처리: \, ", 줄바꿈
  echo "$1" | sed ':a;N;$!ba;s/\n/\\n/g' | sed 's/\\/\\\\/g; s/"/\\"/g'
}

CANDIDATES=$(run_psql "
SELECT rolname
FROM pg_roles
WHERE rolcanlogin = true
  AND rolname NOT IN ('admin01')
  AND rolname NOT LIKE 'pg_%'
ORDER BY rolname;
")

if [ $? -ne 0 ]; then
  STATUS="FAIL"
  EVIDENCE="ROLE 목록 조회 실패"
  GUIDE_MSG="postgres 계정 접근 권한을 확인하십시오."
elif [ -z "$CANDIDATES" ]; then
  STATUS="PASS"
  EVIDENCE="불필요 계정 후보 없음"
  GUIDE_MSG="현재 기준에서 추가 조치가 필요하지 않습니다."
else
  STATUS="FAIL"
  EVIDENCE="불필요 계정 후보: $(echo "$CANDIDATES" | tr '\n' ',' | sed 's/,$//')"
  GUIDE_MSG="위 후보 계정들을 DROP ROLE 또는 ALTER ROLE <계정명> NOLOGIN으로 조치하겠습니다."
fi

SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
CHECK_COMMAND="(psql 접속) pg_roles에서 rolcanlogin=true 이면서 pg_% 제외 및 admin01 제외한 계정 후보 조회"
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