# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-15
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 하
# @Title       : 관리자 이외의 사용자가 오라클 리스너의 접속을 통해 리스너 로그 및 trace 파일에 대한 변경 제한
# @Description : Listener 관련 설정 파일의 접근 권한을 관리자만 가능하게 하고 Listener 파라미터의 변경 방지에 대한 옵션 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
ID="D-15"
CURRENT_STATUS="N/A"
ACTION_RESULT="NOT_APPLICABLE"
ACTION_LOG="해당 없음: Oracle DB Listener 전용 항목으로 PostgreSQL에는 적용되지 않음"
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

