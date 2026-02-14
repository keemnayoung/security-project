#!/bin/bash
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-21
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 중
# @Title       : 인가되지 않은 GRANT OPTION 사용 제한
# @Description : 일반 사용자에게 GRANT OPTION이 ROLE에 의하여 부여되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================


COMMON_FILE="$(cd "$(dirname "$0")/.." && pwd)/_pg_common.sh"
# shellcheck disable=SC1090
. "$COMMON_FILE"
load_pg_env

ID="D-21"
STATUS="FAIL"
EVIDENCE="N/A"
GUIDE_MSG="N/A"

TARGET_GRANTS=$(run_psql "
SELECT grantee || ':' || table_schema || '.' || table_name || ':' || privilege_type
FROM information_schema.role_table_grants rtg
JOIN pg_roles r ON r.rolname = rtg.grantee
WHERE rtg.is_grantable = 'YES'
  AND r.rolsuper = false
  AND r.rolname NOT LIKE 'pg_%'
  AND rtg.grantee <> 'PUBLIC'
ORDER BY 1;
")

if [ $? -ne 0 ]; then
  STATUS="FAIL"
  EVIDENCE="GRANT OPTION 조회 실패"
  GUIDE_MSG="DB 접속 정보를 확인하십시오."
elif [ -z "$TARGET_GRANTS" ]; then
  STATUS="PASS"
  EVIDENCE="일반 사용자 GRANT OPTION 미부여"
  GUIDE_MSG="현재 기준에서 추가 조치가 필요하지 않습니다."
else
  STATUS="FAIL"
  TOTAL_CNT="$(printf '%s\n' "$TARGET_GRANTS" | sed '/^$/d' | wc -l | xargs)"
  # dashboard.py는 evidence를 ". " 기준으로 분리해 줄바꿈(<br>) 처리하므로, 항목을 문장으로 나열한다.
  MAX_SHOW=50
  DETAIL="$(printf '%s\n' "$TARGET_GRANTS" | sed '/^$/d' | head -n "$MAX_SHOW")"
  DETAIL_SENTENCES="$(printf '%s\n' "$DETAIL" | awk 'NF{printf "%s. ",$0}')"
  if [ "${TOTAL_CNT:-0}" -gt "$MAX_SHOW" ]; then
    EVIDENCE="일반 사용자 GRANT OPTION 존재. ${DETAIL_SENTENCES}...(총 ${TOTAL_CNT}건, 표시 ${MAX_SHOW}건)."
  else
    EVIDENCE="일반 사용자 GRANT OPTION 존재. ${DETAIL_SENTENCES}총 ${TOTAL_CNT}건."
  fi
  GUIDE_MSG="REVOKE GRANT OPTION FOR <권한> ON <객체> FROM <계정명>; 으로 권한을 회수하십시오."
fi

# ===== 표준 출력(scan_history) =====
CHECK_COMMAND="information_schema.role_table_grants에서 is_grantable='YES' 이며 (rolsuper=false, grantee!='PUBLIC', grantee not like 'pg_%') 인 권한 재위임 가능 항목 존재 여부 점검"
REASON_LINE="D-21 ${STATUS}: ${EVIDENCE}"
DETAIL_CONTENT="${GUIDE_MSG}"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
TARGET_FILE="information_schema.role_table_grants"

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