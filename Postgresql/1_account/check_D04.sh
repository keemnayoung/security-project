# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-04
# @Category    : DBMS
# @Platform    : PostgreSQL
# @Severity    : 상
# @Title       : DBMS 관리자 권한을 꼭 필요한 계정 및 그룹에 대해서만 허용
# @Description : DB 관리자 권한이 필요한 계정에만 슈퍼유저 권한이 부여되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
ITEM_ID="D-04"
CATEGORY="계정관리"
CHECK_ITEM="관리자 권한 계정 최소화"
DESCRIPTION="DB 관리자 권한이 필요한 계정에만 슈퍼유저 권한이 부여되어 있는지 점검"
SEVERITY="상"
CHECKED_AT=$(date -Iseconds)

cnt=$(psql -U postgres -t -c \
"SELECT COUNT(*) FROM pg_roles WHERE rolsuper = true AND rolname <> 'postgres';" | xargs)

if [ "$cnt" -eq 0 ]; then
  STATUS="양호"
  RESULT_MSG="postgres 외 불필요한 관리자 권한 계정 없음"
else
  STATUS="취약"
  RESULT_MSG="postgres 외 관리자 권한이 부여된 계정 존재"
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
