# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-13
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 중
# @Title       : 불필요한 ODBC/OLE-DB 데이터 소스 제거
# @Description : 사용하지 않는 불필요한 ODBC/OLE-DB가 설치되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
ID="D-13"
CURRENT_STATUS="N/A"
ACTION_RESULT="NOT_APPLICABLE"
ACTION_LOG="해당 없음: Windows OS 전용 항목으로 PostgreSQL 환경에는 적용되지 않음"
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
