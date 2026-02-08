# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-18
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : 응용프로그램 또는 DBA 계정의 Role이 Public으로 설정되지 않도록 조정
# @Description : 응용 프로그램 또는 DBA 계정의 Role이 Public으로 설정되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
ID="D-18"
CURRENT_STATUS="FAIL"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"

NOW=$(date '+%Y-%m-%d %H:%M:%S')

# 1. PUBLIC Role에 권한이 부여된 객체 조회
TARGET_OBJECTS=$(sudo -u postgres psql -t -c "
SELECT DISTINCT table_schema || '.' || table_name
FROM information_schema.table_privileges
WHERE grantee = 'PUBLIC'
  AND table_schema NOT IN ('pg_catalog', 'information_schema');
" 2>/dev/null | sed '/^\s*$/d')

if [ -z "$TARGET_OBJECTS" ]; then
    CURRENT_STATUS="PASS"
    ACTION_RESULT="NOT_REQUIRED"
    ACTION_LOG="양호: PUBLIC Role에 부여된 불필요한 객체 권한이 존재하지 않음"
else
    # 2. PUBLIC Role 권한 회수 (자동 조치)
    for obj in $TARGET_OBJECTS; do
        sudo -u postgres psql -c "
        REVOKE ALL PRIVILEGES ON TABLE $obj FROM PUBLIC;
        " >/dev/null 2>&1
    done

    CURRENT_STATUS="PASS"
    ACTION_RESULT="SUCCESS"
    ACTION_LOG="자동 조치 완료: PUBLIC Role에 부여된 객체 권한을 회수함 (${TARGET_OBJECTS//[$'\n']/ , })"
fi

# 3. JSON 출력 
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

