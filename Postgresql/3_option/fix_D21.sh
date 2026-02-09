# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-21
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 중
# @Title       : 인가되지 않은 GRANT OPTION 사용 제한
# @Description : 일반 사용자에게 GRANT OPTION이 ROLE에 의하여 부여되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash

ID="D-21"

CURRENT_STATUS="FAIL"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"

NOW=$(date '+%Y-%m-%d %H:%M:%S')

# 1. 일반 사용자에게 GRANT OPTION이 부여된 객체 조회
TARGET_GRANTS=$(sudo -u postgres psql -t -c "
SELECT DISTINCT
  tp.grantee,
  tp.table_schema || '.' || tp.table_name AS object_name
FROM information_schema.table_privileges tp
JOIN pg_roles r ON tp.grantee = r.rolname
WHERE tp.is_grantable = 'YES'
  AND r.rolsuper = false
  AND tp.table_schema NOT IN ('pg_catalog', 'information_schema');
" 2>/dev/null | sed '/^\s*$/d')

# 2. 조치 수행
if [ -z "$TARGET_GRANTS" ]; then
    CURRENT_STATUS="PASS"
    ACTION_RESULT="NOT_REQUIRED"
    ACTION_LOG="조치 대상 없음: 일반 사용자에게 부여된 GRANT OPTION이 존재하지 않음"
else
    while read -r line; do
        GRANTEE=$(echo "$line" | awk '{print $1}')
        OBJECT=$(echo "$line" | awk '{print $2}')

        sudo -u postgres psql -c "
        REVOKE GRANT OPTION FOR ALL PRIVILEGES
        ON TABLE $OBJECT
        FROM \"$GRANTEE\";
        " >/dev/null 2>&1
    done <<< "$TARGET_GRANTS"

    CURRENT_STATUS="PASS"
    ACTION_RESULT="SUCCESS"
    ACTION_LOG="자동 조치 완료: 일반 사용자에게 부여된 GRANT OPTION을 회수함"
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

