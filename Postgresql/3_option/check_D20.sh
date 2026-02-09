# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-20
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 하
# @Title       : 인가되지 않은 Object Owner의 제한
# @Description : Object Owner가 인가된 계정에게만 존재하는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
ITEM_ID="D-20"
CATEGORY="옵션관리"
CHECK_ITEM="Object Owner 제한"
DESCRIPTION="Object Owner가 인가된 계정에게만 존재하는지 점검"
IMPORTANCE="하"
CHECKED_AT=$(date -Iseconds)

cnt=$(psql -U postgres -t -c "
SELECT COUNT(DISTINCT c.relowner)
FROM pg_class c
WHERE c.relowner NOT IN (
    SELECT usesysid
    FROM pg_user
    WHERE usesuper = true
);
" | xargs)


if [ "$cnt" -eq 0 ]; then
  STATUS="양호"
  RESULT_MSG="DB 객체가 관리자(postgres)계정으로만 소유됨"
else
  STATUS="취약"
  RESULT_MSG="일반 계정이 소유한 DB 객체가 존재함"
fi


cat <<EOF
{ "item_id":"$ITEM_ID",
"category":"$CATEGORY",
"check_item":"$CHECK_ITEM",
"description":"$DESCRIPTION",
"IMPORTANCE":"$IMPORTANCE",
"checked_at":"$CHECKED_AT",
"status":"$STATUS",
"result":"$RESULT_MSG",
"checked":true }
EOF
