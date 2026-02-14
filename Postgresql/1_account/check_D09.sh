#!/bin/bash
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-09
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 중
# @Title       : 일정 횟수의 로그인 실패 시 이에 대한 잠금정책 설정
# @Description : DBMS 설정 중 일정 횟수의 로그인 실패 시 계정 잠금 정책에 대한 설정이 되어있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================


# 로직 유지 + 출력 형식(scan_history) 통일

ID="D-09"
STATUS="FAIL"
EVIDENCE="PostgreSQL은 로그인 실패 횟수 기반 계정 잠금 기능을 DBMS 자체적으로 제공하지 않습니다."

TARGET_FILE="password"
CHECK_COMMAND="PostgreSQL 자체 기능 부재(로그인 실패 횟수 기반 잠금 미제공) 확인"

REASON_LINE=""
DETAIL_CONTENT=""

# 기존 문장(로직) 유지
REASON_LINE="D-09 취약: ${EVIDENCE}"
DETAIL_CONTENT="운영체제 수준의 인증 통제(PAM) 또는 접근 제어 도구(fail2ban 등)를 활용하여 일정 횟수 이상의 로그인 실패 시 계정 또는 접속을 제한하도록 구성해야 합니다."

SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

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