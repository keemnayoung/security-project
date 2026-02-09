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

#!/bin/bash

ID="D-07"

CURRENT_STATUS="FAIL"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"

NOW=$(date '+%Y-%m-%d %H:%M:%S')

# PostgreSQL 프로세스가 root 권한으로 실행 중인지 확인
ROOT_CNT=$(ps -eo user,comm | awk '$2 ~ /postgres/ && $1 == "root"' | wc -l)

if [ "$ROOT_CNT" -eq 0 ]; then
    CURRENT_STATUS="PASS"
    ACTION_RESULT="NOT_REQUIRED"
    ACTION_LOG="양호: PostgreSQL 서비스가 전용 계정(postgres)으로 실행 중"
else
    CURRENT_STATUS="FAIL"
    ACTION_RESULT="MANUAL_REQUIRED"
    ACTION_LOG="취약: PostgreSQL 서비스가 root 권한으로 실행 중입니다. 서비스 실행 계정을 postgres 전용 계정으로 변경하고 systemd 서비스 설정을 점검하십시오."
fi

# JSON 출력 
cat <<EOF
{
  "check_id": "$ID",
  "status": "$CURRENT_STATUS",
  "action_result": "$ACTION_RESULT",
  "action_log": "$ACTION_LOG",
  "action_date": "$NOW",
  "check_date": "$NOW"
}
EOF

