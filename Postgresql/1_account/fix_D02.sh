# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-02
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : 데이터베이스의 불필요 계정을 제거하거나, 잠금설정 후 사용
# @Description : DBMS에 존재하는 계정 중 DB 관리나 운용에 사용하지 않는 불필요한 계정이 존재하는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

#!/bin/bash
#!/bin/bash

ID="D-02"

CURRENT_STATUS="FAIL"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"

NOW=$(date '+%Y-%m-%d %H:%M:%S')

# 1. 현재 상태 점검 - 로그인 가능한 계정 존재 여부
CHECK_RESULT=$(sudo -u postgres psql -t -c "
SELECT rolname
FROM pg_roles
WHERE rolcanlogin = true
  AND rolname NOT IN ('postgres')
  AND rolname NOT LIKE 'pg_%'
ORDER BY rolname;
" 2>/dev/null | sed '/^\s*$/d')

if [ -z "$CHECK_RESULT" ]; then
    CURRENT_STATUS="PASS"
    ACTION_RESULT="NOT_REQUIRED"
    ACTION_LOG="양호: 로그인 가능한 불필요 계정 없음"
else
    CURRENT_STATUS="FAIL"
    ACTION_RESULT="MANUAL_REQUIRED"
    ACTION_LOG="수동 조치 필요: 로그인 가능한 계정 존재($(echo "$CHECK_RESULT" | tr '\n' ', ' | sed 's/, $//')).관리자 확인 후 불필요한 계정에 대해 다음 명령을 수동 실행하세요: sudo -u postgres psql → DROP ROLE 계정명;"
fi

# 2. JSON 출력 (D-01 형식과 동일)
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
