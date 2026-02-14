#!/bin/bash
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-26
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @IMPORTANCE    : 상
# @Title       : 데이터베이스의 접근, 변경, 삭제 등의 감사 기록이 기관의 감사 기록 정책에 적합하도록 설정
# @Description : 감사 기록 정책 설정이 기관 정책에 적합하게 설정되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================


COMMON_FILE="$(cd "$(dirname "$0")/.." && pwd)/_pg_common.sh"
# shellcheck disable=SC1090
. "$COMMON_FILE"
load_pg_env

ID="D-26"
STATUS="FAIL"

TARGET_FILE="postgresql.conf(logging_collector)"
CHECK_COMMAND="SHOW logging_collector;"
REASON_LINE=""
DETAIL_CONTENT=""

CURRENT_VALUE="$(run_psql "SHOW logging_collector;" | xargs)"

if [ "$CURRENT_VALUE" = "on" ]; then
  STATUS="PASS"
  REASON_LINE="D-26 PASS: logging_collector=on"
  DETAIL_CONTENT="현재 기준에서 추가 조치가 필요하지 않습니다."
elif [ "$CURRENT_VALUE" = "off" ]; then
  STATUS="FAIL"
  REASON_LINE="D-26 FAIL: logging_collector=off"
  DETAIL_CONTENT="postgresql.conf 또는 ALTER SYSTEM으로 logging_collector=on 적용 후 서비스 재시작하십시오."
else
  STATUS="FAIL"
  REASON_LINE="D-26 FAIL: logging_collector 조회 실패"
  DETAIL_CONTENT="DB 접속 정보 및 설정 파일 권한을 확인하십시오."
fi

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
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

echo ""
cat <<EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF