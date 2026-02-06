# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-11
# @Category    : DBMS
# @Platform    : PostgreSQL
# @Severity    : 상
# @Title       : DBA 이외의 인가되지 않은 사용자가 시스템 테이블에 접근할 수 없도록 설정
# @Description : 일반 사용자 계정의 시스템 테이블 접근 권한 부여 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
ITEM_ID="D-11"
CATEGORY="접근관리"
CHECK_ITEM="시스템 테이블 접근 제한"
DESCRIPTION="일반 사용자 계정의 시스템 테이블 접근 권한 부여 여부 점검"
SEVERITY="상"
CHECKED_AT=$(date -Iseconds)

cnt=$(psql -U postgres -t -c "
SELECT COUNT(*)
FROM information_schema.table_privileges tp
JOIN pg_roles r ON tp.grantee = r.rolname
WHERE tp.table_schema IN ('pg_catalog', 'information_schema')
  AND r.rolsuper = false;
" | xargs)

if [ "$cnt" -eq 0 ]; then
  STATUS="양호"
  RESULT_MSG="일반 사용자 계정의 시스템 테이블 접근 권한 미부여"
else
  STATUS="취약"
  RESULT_MSG="일반 사용자 계정에 시스템 테이블 접근 권한 부여됨"
fi

cat <<EOF
{ "item_id":"$ITEM_ID",
"category":"$CATEGORY",
"check_item":"$CHECK_ITEM",
"description":"$DESCRIPTION",
"severity":"$SEVERITY",
"checked_at":"$CHECKED_AT",
"status":"$STATUS",
"result":"$RESULT_MSG",
"checked":true }
EOF
