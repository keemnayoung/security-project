#!/bin/bash
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.1
# @Author: 윤영아
# @Last Updated: 2026-02-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-20
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 하
# @Title       : 인가되지 않은 Object Owner의 제한
# @Description : Object Owner가 인가된 계정에게만 존재하는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================


COMMON_FILE="$(cd "$(dirname "$0")/.." && pwd)/_pg_common.sh"
# shellcheck disable=SC1090
. "$COMMON_FILE"
load_pg_env

ID="D-20"
STATUS="FAIL"
EVIDENCE="N/A"
GUIDE_MSG="N/A"
ALLOWED_OBJECT_OWNERS="${ALLOWED_OBJECT_OWNERS:-postgres}"

SQL_LIST=$(printf "'%s'," $(echo "$ALLOWED_OBJECT_OWNERS" | tr ',' ' '))
SQL_LIST=${SQL_LIST%,}

# 비시스템 스키마 객체의 소유자(relowner)가 허용 목록 외인지 조회
UNAUTH_OWNERS=$(run_psql "
SELECT n.nspname || '.' || c.relname || ':' || pg_get_userbyid(c.relowner)
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname NOT IN ('pg_catalog','information_schema')
  AND c.relkind IN ('r','v','m','S','f')
  AND pg_get_userbyid(c.relowner) NOT IN (${SQL_LIST})
ORDER BY 1;
")
if [ $? -ne 0 ]; then
  STATUS="FAIL"
  EVIDENCE="객체 소유자 정보를 조회하지 못하여 점검을 수행할 수 없습니다.\n조치 방법은 DB 접속 정보와 점검 계정 권한을 확인해주시기 바랍니다."
  GUIDE_MSG="DB 접속 정보 및 점검 계정 권한을 점검해주시기 바랍니다."
elif [ -z "$UNAUTH_OWNERS" ]; then
  STATUS="PASS"
  EVIDENCE="비시스템 스키마 객체의 소유자가 허용 목록(${ALLOWED_OBJECT_OWNERS})으로 제한되어 있으므로 이 항목에 대한 보안 위협이 없습니다."
  GUIDE_MSG="현재 기준에서 추가 조치가 필요하지 않습니다."
else
  UNAUTH_COUNT="$(printf '%s\n' "$UNAUTH_OWNERS" | sed '/^$/d' | wc -l | xargs)"
  UNAUTH_OWNER_LIST="$(printf '%s\n' "$UNAUTH_OWNERS" | awk -F: 'NF>=2{print $2}' | sed '/^$/d' | sort -u | tr '\n' ',' | sed 's/,$//')"
  STATUS="FAIL"
  EVIDENCE="비시스템 스키마 객체의 소유자가 허용 목록에 포함되지 않아 권한 오남용 및 관리 통제 미흡 위험이 있습니다.\n조치 방법은 허용 계정 기준으로 객체 소유권을 정리하고, 불필요한 소유 계정은 권한을 최소화해주시기 바랍니다."
  GUIDE_MSG="인가되지 않은 소유자 계정은 ${UNAUTH_OWNER_LIST:-확인불가} 이며, 해당 객체 수는 ${UNAUTH_COUNT:-?}개입니다. 상세 항목은 $(echo "$UNAUTH_OWNERS" | tr '\n' ',' | sed 's/,$//') 입니다. 예) ALTER <OBJECT> <schema.object> OWNER TO <인가계정>; 적용 후 재점검해주시기 바랍니다."
fi

# ===== 표준 출력(scan_history) =====
CHECK_COMMAND="pg_class/pg_namespace 기반 비시스템 스키마 객체(relkind=r,v,m,S,f)의 relowner(소유자) 허용 목록(${ALLOWED_OBJECT_OWNERS}) 외 여부 점검"
REASON_LINE="${EVIDENCE}"
DETAIL_CONTENT="${GUIDE_MSG}"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
TARGET_FILE="pg_class.relowner (join pg_namespace; exclude pg_catalog/information_schema)"

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
