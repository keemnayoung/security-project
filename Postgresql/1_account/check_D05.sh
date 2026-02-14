#!/bin/bash
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-05
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 중
# @Title       : 비밀번호 재사용 제한 정책
# @Description : 비밀번호 변경 시 이전 비밀번호를 재사용할 수 없도록 비밀번호 제약 설정이 되어있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================


ID="D-05"
STATUS="FAIL"
EVIDENCE="PostgreSQL은 비밀번호 재사용 제한 기능을 제공하지 않아 운영 절차 또는 외부 인증 정책에 따른 관리 여부를 수동으로 확인할 필요가 있다."

# scan_history 표준 필드 구성
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
CHECK_COMMAND="N/A (PostgreSQL 자체 기능 미제공: password reuse restriction)"
TARGET_FILE="N/A"

REASON_LINE="$EVIDENCE"
DETAIL_CONTENT="운영 절차(비밀번호 이력 관리) 또는 외부 인증(PAM/LDAP/AD 등) 정책에서 비밀번호 재사용 제한이 적용되는지 확인해야 합니다."

escape_json_str() {
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