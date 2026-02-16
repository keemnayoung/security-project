#!/bin/bash
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.1
# @Author: 윤영아
# @Last Updated: 2026-02-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-26
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
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

# SQL logging_collector 설정값 조회
CURRENT_VALUE="$(run_psql "SHOW logging_collector;" | xargs)"

if [ "$CURRENT_VALUE" = "on" ]; then
  STATUS="PASS"
  REASON_LINE="logging_collector=on 으로 설정되어 있어 이 항목에 대한 보안 위협이 없습니다."
  DETAIL_CONTENT="현재 기준에서 추가 조치가 필요하지 않습니다."
elif [ "$CURRENT_VALUE" = "off" ]; then
  STATUS="FAIL"
  REASON_LINE="logging_collector=off 로 설정되어 있어 감사 로그 수집이 누락될 수 있습니다.\n조치 방법은 postgresql.conf 또는 ALTER SYSTEM으로 logging_collector=on 적용 후 서비스 재시작을 수행해주시기 바랍니다."
  DETAIL_CONTENT="점검 기준은 logging_collector 활성화 입니다. 적용 후 SHOW logging_collector 재확인 및 서비스 재기동 상태를 점검해주시기 바랍니다."
else
  STATUS="FAIL"
  REASON_LINE="logging_collector 값을 확인하지 못하여 로그 수집 설정 상태를 판단할 수 없습니다.\n조치 방법은 DB 접속 정보 및 설정 조회 권한, 설정 파일 접근 권한을 점검해주시기 바랍니다."
  DETAIL_CONTENT="SHOW logging_collector 수행 결과가 비정상입니다. run_psql 접속 정보와 권한을 확인해주시기 바랍니다."
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