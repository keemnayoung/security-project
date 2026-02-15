#!/bin/bash
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-07
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 중
# @Title       : root 권한으로 서비스 구동 제한
# @Description : 서비스 구동 시 root 계정 또는 root 권한으로 구동되는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================


# D-07 (PostgreSQL) - 로직 유지, 출력 형식(scan_history)만 통일

ID="D-07"
STATUS="FAIL"
EVIDENCE="N/A"

# (기존 로직) root 권한으로 postgres 프로세스가 떠있는지 확인
root_cnt=$(ps -eo user,comm | grep postgres | grep -w root | wc -l)
if [ "$root_cnt" -eq 0 ]; then
  STATUS="PASS"
  EVIDENCE="PostgreSQL 서비스가 전용 계정(postgres)으로 실행 중"
else
  STATUS="FAIL"
  EVIDENCE="PostgreSQL 서비스가 root 권한으로 실행 중"
fi

# scan_history 표준 필드 구성
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
TARGET_FILE="account"
CHECK_COMMAND="ps -eo user,comm | grep postgres | grep -w root | wc -l"

if [ "$STATUS" = "PASS" ]; then
  REASON_LINE="D-07 양호: ${EVIDENCE}"
  DETAIL_CONTENT="PostgreSQL 프로세스가 root 계정으로 실행되지 않습니다."
else
  REASON_LINE="D-07 취약: ${EVIDENCE}"
  DETAIL_CONTENT="PostgreSQL 서비스는 root 권한이 아닌 전용 계정(postgres)으로 실행되도록 구성해야 합니다. 실행 계정 변경 후 시스템 재기동 명령어 sudo systemctl reload postgresql; 로 적용 여부를 확인하십시오."
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

echo ""
cat <<EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF