#!/bin/bash
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.1
# @Author: 윤영아
# @Last Updated: 2026-02-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-11
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : DBA 이외의 인가되지 않은 사용자가 시스템 테이블에 접근할 수 없도록 설정
# @Description : 시스템 테이블에 일반 사용자 계정이 접근할 수 없도록 설정되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================


COMMON_FILE="$(cd "$(dirname "$0")/.." && pwd)/_pg_common.sh"
# shellcheck disable=SC1090
. "$COMMON_FILE"
load_pg_env

ID="D-11"
STATUS="FAIL"
EVIDENCE="N/A"
GUIDE_MSG="N/A"

# _pg_common.sh에 escape_json / run_psql이 이미 있다고 가정(기존 스크립트 흐름 유지)
# 다만, 출력에서만 JSON 안전 처리가 필요하므로 별도 escape 함수는 아래에서 사용

ALLOWED_DBA_RAW="${D11_ALLOWED_DBA:-},postgres,${POSTGRES_USER},${PG_SUPERUSER}"

is_allowed_dba() {
  local acct="$1"
  local one=""
  IFS=',' read -r -a _arr <<< "$ALLOWED_DBA_RAW"
  for one in "${_arr[@]}"; do
    one="$(echo "$one" | xargs)"
    [ -z "$one" ] && continue
    [ "$acct" = "$one" ] && return 0
  done
  return 1
}

# 위험 권한 후보 조회(위험 내장 롤 멤버십 + 시스템 스키마 테이블 권한)
RISK_CANDIDATES=$(run_psql "
WITH risk_role_member AS (
  SELECT DISTINCT m.rolname AS account
  FROM pg_auth_members am
  JOIN pg_roles m ON m.oid = am.member
  JOIN pg_roles r ON r.oid = am.roleid
  WHERE m.rolcanlogin = true
    AND m.rolsuper = false
    AND m.rolname <> 'admin01'
    AND m.rolname NOT LIKE 'pg_%'
    AND r.rolname IN (
      'pg_read_all_data',
      'pg_write_all_data',
      'pg_execute_server_program',
      'pg_read_server_files',
      'pg_write_server_files',
      'pg_signal_backend'
    )
),
risk_table_grant AS (
  SELECT DISTINCT tp.grantee AS account
  FROM information_schema.table_privileges tp
  JOIN pg_roles pr ON pr.rolname = tp.grantee
  WHERE tp.table_schema IN ('pg_catalog', 'information_schema')
    AND tp.grantee <> 'PUBLIC'
    AND pr.rolcanlogin = true
    AND pr.rolsuper = false
    AND pr.rolname <> 'admin01'
    AND pr.rolname NOT LIKE 'pg_%'
),
risk_accounts AS (
  SELECT account FROM risk_role_member
  UNION
  SELECT account FROM risk_table_grant
)
SELECT account
FROM risk_accounts
ORDER BY account;
")
RC=$?

if [ $RC -ne 0 ]; then
  STATUS="FAIL"
  EVIDENCE="시스템 스키마 권한 위험 후보를 조회하지 못하여 미인가 계정 점검을 수행할 수 없습니다.\n조치 방법은 PostgreSQL 접속 정보와 점검 계정 권한을 확인해주시기 바랍니다."
  GUIDE_MSG="접속 정보 및 점검 계정 권한을 점검해주시기 바랍니다."
else
  FILTERED=""
  while IFS= read -r acct; do
    [ -z "$acct" ] && continue
    if is_allowed_dba "$acct"; then
      continue
    fi
    FILTERED="${FILTERED}${acct}"$'\n'
  done <<< "$RISK_CANDIDATES"

  FILTERED_CSV="$(echo "$FILTERED" | sed '/^$/d' | tr '\n' ',' | sed 's/,$//')"

  if [ -z "$FILTERED_CSV" ]; then
    STATUS="PASS"
    EVIDENCE="허용되지 않은 일반 계정에 시스템 스키마 관련 위험 권한이 확인되지 않아 이 항목에 대한 보안 위협이 없습니다."
    GUIDE_MSG="현재 기준에서 추가 조치가 필요하지 않습니다."
  else
    STATUS="FAIL"
    EVIDENCE="허용되지 않은 일반 계정에 시스템 스키마 관련 위험 권한이 확인되어 정보 노출 및 권한 오남용 위험이 있습니다.\n조치 방법은 해당 계정의 위험 내장 롤 멤버십을 제거하고, pg_catalog 또는 information_schema에 부여된 불필요 권한을 회수해주시기 바랍니다."
    GUIDE_MSG="미인가로 판단된 계정은 ${FILTERED_CSV} 입니다. 해당 계정의 위험 내장 롤(pg_read_all_data 등) 멤버십 제거 및 시스템 스키마 권한(REVOKE)을 적용해주시기 바랍니다."
  fi

  # ⚠️ 원본에 남아있던 미정의 변수(cnt) 기반 분기 블록은
  # 문법 오류/실행 오류를 유발하므로, '로직 변경'이 아니라 '깨진 잔여 코드 제거'로 정리합니다.
  # (cnt는 어디에서도 정의되지 않아 실행 시 즉시 실패합니다.)
fi

# ===== 표준 출력(scan_history) =====
CHECK_COMMAND="run_psql: 시스템 스키마 권한 위험 후보(role membership/table grants) 조회"
REASON_LINE="${EVIDENCE}"
DETAIL_CONTENT="${GUIDE_MSG}"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
TARGET_FILE="pg_auth_members,information_schema.table_privileges"

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