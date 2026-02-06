# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-21
# @Category    : DBMS
# @Platform    : PostgreSQL
# @Severity    : 중
# @Title       : 인가되지 않은 GRANT OPTION 사용 제한
# @Description : 일반 사용자에게 WITH GRANT OPTION 권한 부여 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
ITEM_ID="D-21"
CATEGORY="옵션관리"
CHECK_ITEM="인가되지 않은 GRANT OPTION 사용 제한"
DESCRIPTION="일반 사용자에게 WITH GRANT OPTION 권한 부여 여부 점검"
SEVERITY="중"
CHECKED_AT=$(date -Iseconds)

cnt=$(psql -U postgres -t -c "
SELECT COUNT(*)
FROM information_schema.table_privileges tp
JOIN pg_roles r ON tp.grantee = r.rolname
WHERE tp.is_grantable = 'YES'
  AND r.rolsuper = false;
" | xargs)

if [ "$cnt" -eq 0 ]; then
  STATUS="양호"
  RESULT_MSG="일반 사용자에게 GRANT OPTION 미부여"
else
  STATUS="취약"
  RESULT_MSG="일반 사용자에게 GRANT OPTION 부여됨"
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
