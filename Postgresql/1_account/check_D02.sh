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
ITEM_ID="D-02"
CATEGORY="계정관리"
CHECK_ITEM="불필요 계정 존재"
DESCRIPTION="DBMS에 존재하는 계정 중 DB 관리나 운용에 사용하지 않는 불필요한 계정이 존재하는지 점검"
IMPORTANCE="상"
CHECKED_AT=$(date -Iseconds)

#postgres 기본 관리자 계정에 속하지 않고 이름에 test,demo,temp가 들어간 계정 제외
cnt=$(psql -U postgres -t -c \
"SELECT COUNT(*) FROM pg_roles WHERE rolcanlogin = true
  AND rolname NOT IN ('postgres')
  AND (
    rolname ILIKE '%test%'
    OR rolname ILIKE '%demo%'
    OR rolname ILIKE '%temp%'
  );" | xargs)

if [ "$cnt" -eq 0 ]; then
  STATUS="양호"
  RESULT_MSG="불필요 계정 없음"
else
  STATUS="취약"
  RESULT_MSG="불필요 계정 존재"
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
