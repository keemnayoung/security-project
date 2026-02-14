#!/bin/bash
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-06
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 중
# @Title       : DB 사용자 계정을 개별적으로 부여하여 사용
# @Description : DB 접근 시 사용자별로 서로 다른 계정을 사용하여 접근하는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# D-06 (PostgreSQL) - 로직 유지, 출력 형식(scan_history)만 통일

ID="D-06"
STATUS="FAIL"
EVIDENCE="N/A"

login_cnt=$(psql -U postgres -t -c \
"SELECT COUNT(*) FROM pg_roles WHERE rolcanlogin = true AND rolname <> 'postgres';" | xargs)

if [ "$login_cnt" -gt 1 ]; then
  STATUS="FAIL"
  EVIDENCE="로그인 가능한 계정이 다수 존재하나 사용자별 계정 사용 여부는 수동 확인 필요"
else
  STATUS="FAIL"
  EVIDENCE="공용 계정 사용 가능성 높음 (로그인 계정 수가 제한적)"
fi

# ② scan_history 출력 구성(
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
CHECK_COMMAND="psql -U postgres -t -c \"SELECT COUNT(*) FROM pg_roles WHERE rolcanlogin = true AND rolname <> 'postgres';\""
TARGET_FILE="pg_roles"

REASON_LINE="$EVIDENCE"
DETAIL_CONTENT="DB 접근 시 사용자별로 서로 다른 계정을 사용을 권장합니다."

escape_json_str() {
  # JSON 문자열 안전 처리: \, ", 줄바꿈
  echo "$1" | sed ':a;N;$!ba;s/\n/\\n/g' | sed 's/\\/\\\\/g; s/"/\\"/g'
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