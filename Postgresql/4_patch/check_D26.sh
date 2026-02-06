# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-26
# @Category    : DBMS
# @Platform    : PostgreSQL
# @Severity    : 상
# @Title       : DB 감사 로그 정책
# @Description : DBMS 접근·변경·삭제에 대한 감사 로그 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
ITEM_ID="D-26"
CATEGORY="패치관리"
CHECK_ITEM="DB 감사 로그 정책"
DESCRIPTION="DBMS 접근·변경·삭제에 대한 감사 로그 설정 여부 점검"
SEVERITY="상"
CHECKED_AT=$(date -Iseconds)

log_collector=$(psql -U postgres -t -c "SHOW logging_collector;" 2>/dev/null | xargs)

if [ "$log_collector" = "on" ]; then
  STATUS="양호"
  RESULT_MSG="DB 감사 로그 수집 기능(logging_collector)이 활성화됨"
else
  STATUS="취약"
  RESULT_MSG="DB 감사 로그 수집 기능(logging_collector)이 비활성화됨"
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
