#!/bin/bash
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-18
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : 응용프로그램 또는 DBA 계정의 Role이 Public으로 설정되지 않도록 조정
# @Description : 응용 프로그램 또는 DBA 계정의 Role이 Public으로 설정되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================


COMMON_FILE="$(cd "$(dirname "$0")/.." && pwd)/_pg_common.sh"
# shellcheck disable=SC1090
. "$COMMON_FILE"
load_pg_env

ID="D-18"
STATUS="FAIL"
EVIDENCE="N/A"
GUIDE_MSG="N/A"

# NOTE:
# PostgreSQL은 object privilege에는 PUBLIC grantee를 지원하지만,
# role membership(ROLE을 PUBLIC에 부여)은 환경에 따라 불가/비표준이라 점검 신뢰도가 낮습니다.
# 본 점검은 "PUBLIC에 스키마 CREATE 권한이 남아있는지"를 점검합니다.
# (특히 schema public의 CREATE 권한은 권한 확산의 대표 원인)

PUBLIC_SCHEMA_CREATE=$(run_psql "
SELECT n.nspname || ':' || e.privilege_type
FROM pg_namespace n
JOIN LATERAL aclexplode(COALESCE(n.nspacl, acldefault('n', n.nspowner))) e ON true
WHERE e.grantee = 0
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND (
    (n.nspname = 'public' AND e.privilege_type = 'CREATE')
    OR
    (n.nspname <> 'public' AND e.privilege_type IN ('CREATE','USAGE'))
  )
ORDER BY 1;
")

if [ $? -ne 0 ]; then
  STATUS="FAIL"
  EVIDENCE="PUBLIC 스키마 권한 조회 실패"
  GUIDE_MSG="DB 접속 정보 및 pg_namespace/aclexplode 조회 권한을 확인하십시오."
elif [ -z "$PUBLIC_SCHEMA_CREATE" ]; then
  STATUS="PASS"
  EVIDENCE="PUBLIC 대상 스키마 권한 없음"
  GUIDE_MSG="현재 기준에서 추가 조치가 필요하지 않습니다."
else
  STATUS="FAIL"
  EVIDENCE="PUBLIC 대상 스키마 권한: $(echo "$PUBLIC_SCHEMA_CREATE" | tr '\n' ',' | sed 's/,$//')"
  GUIDE_MSG="특히 schema public에 대해 REVOKE CREATE ON SCHEMA public FROM PUBLIC; 을 적용하고, 불필요한 PUBLIC 권한을 회수하십시오."
fi

# ===== 표준 출력(scan_history) =====
CHECK_COMMAND="aclexplode 기반 PUBLIC(grantee=0) 스키마 권한(CREATE/USAGE) 점검"
REASON_LINE="D-18 ${STATUS}: ${EVIDENCE}"
DETAIL_CONTENT="${GUIDE_MSG}"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
TARGET_FILE="pg_namespace(nspacl),aclexplode(),schema(public 및 비시스템 스키마)"

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