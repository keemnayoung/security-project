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

#!/bin/bash
ID="D-06"

CURRENT_STATUS="FAIL"
ACTION_RESULT="MANUAL_REQUIRED"
ACTION_LOG="N/A"

NOW=$(date '+%Y-%m-%d %H:%M:%S')

# 로그인 가능한 DB 계정 목록 조회
LOGIN_ROLES=$(sudo -u postgres psql -t -c "
SELECT rolname
FROM pg_shadow
ORDER BY usename;
" 2>/dev/null | sed '/^\s*$/d')

USER_COUNT=$(echo "$DB_USERS" | wc -l | xargs)

# 2. 판단 로직
# 사용자별 계정 사용 여부는 정책/운영 확인이 필요하므로 자동 판정 불가
if [ "$USER_COUNT" -le 1 ]; then
    CURRENT_STATUS="FAIL"
    ACTION_RESULT="MANUAL_REQUIRED"
    ACTION_LOG="취약 가능성: 공용 계정 사용 여부를 수동으로 확인하고 사용자별 계정 분리를 검토 권장"
else
    CURRENT_STATUS="FAIL"
    ACTION_RESULT="MANUAL_REQUIRED"
    ACTION_LOG="수동 확인 필요: DB 사용자 계정 목록 조회됨($(echo "$DB_USERS" | tr '\n' ', ' | sed 's/, $//')). 각 계정이 사용자별로 분리되어 사용 중인지 운영 정책 및 접근 로그를 통해 확인"
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

