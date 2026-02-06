# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-18
# @Category    : DBMS
# @Platform    : PostgreSQL
# @Severity    : 상
# @Title       : 응용 프로그램 또는 DBA 계정의 Role이 Public으로 설정되어 있는지 점검
# @Description : DB 객체에 PUBLIC 권한 부여 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
ITEM_ID="D-18"
CATEGORY="옵션관리"
CHECK_ITEM="PUBLIC Role 권한"
DESCRIPTION="DB 객체에 PUBLIC 권한 부여 여부 점검"
SEVERITY="상"
CHECKED_AT=$(date -Iseconds)

cnt=$(psql -U postgres -t -c "
SELECT COUNT(*)
FROM information_schema.table_privileges
WHERE grantee = 'PUBLIC';
" | xargs)

if [ "$cnt" -eq 0 ]; then
  STATUS="양호"
  RESULT_MSG="PUBLIC Role에 불필요한 권한이 부여되지 않음"
else
  STATUS="취약"
  RESULT_MSG="PUBLIC Role에 부여된 객체 권한 존재"
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
