# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-11
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : DBA 이외의 인가되지 않은 사용자가 시스템 테이블에 접근할 수 없도록 설정
# @Description : 시스템 테이블에 일반 사용자 계정이 접근할 수 없도록 설정되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash

ID="D-11"

CURRENT_STATUS="FAIL"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"

NOW=$(date '+%Y-%m-%d %H:%M:%S')

# 1. 시스템 테이블 접근 권한을 가진 일반 사용자 계정 조회
TARGET_USERS=$(sudo -u postgres psql -t -c "
SELECT DISTINCT tp.grantee
FROM information_schema.table_privileges tp
JOIN pg_roles r ON tp.grantee = r.rolname
WHERE tp.table_schema IN ('pg_catalog', 'information_schema')
  AND r.rolsuper = false;
" 2>/dev/null | sed '/^\s*$/d')

if [ -z "$TARGET_USERS" ]; then
    CURRENT_STATUS="PASS"
    ACTION_RESULT="NOT_REQUIRED"
    ACTION_LOG="양호: 일반 사용자 계정에 시스템 테이블 접근 권한이 부여되어 있지 않음"
else
    # 2. 시스템 테이블 접근 권한 회수
    for u in $TARGET_USERS; do
        sudo -u postgres psql -c "
        REVOKE ALL PRIVILEGES
        ON ALL TABLES IN SCHEMA pg_catalog
        FROM \"$u\";

        REVOKE ALL PRIVILEGES
        ON ALL TABLES IN SCHEMA information_schema
        FROM \"$u\";
        " >/dev/null 2>&1
    done

    CURRENT_STATUS="PASS"
    ACTION_RESULT="SUCCESS"
    ACTION_LOG="자동 조치 완료: 일반 사용자 계정(${TARGET_USERS//[$'\n']/ , })의 시스템 테이블 접근 권한을 회수함"
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

