# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-23
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : xp_cmdshell 사용 제한
# @Description : xp_cmdshell의 사용 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
ID="D-23"
CURRENT_STATUS="N/A"
ACTION_RESULT="NOT_APPLICABLE"
ACTION_LOG="해당 없음: MSSQL 전용 xp_cmdshell 기능은 PostgreSQL에 존재하지 않음"
NOW=$(date '+%Y-%m-%d %H:%M:%S')

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