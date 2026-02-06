# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-13
# @Category    : DBMS
# @Platform    : PostgreSQL
# @Severity    : 중
# @Title       : 불필요한 ODBC/OLE-DB 데이터 소스 제거
# @Description : Windows OS 전용 항목으로 PostgreSQL 환경에는 적용되지 않음
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
ITEM_ID="D-13"
CATEGORY="접근관리"
CHECK_ITEM="ODBC/OLE-DB 데이터 소스 관리"
DESCRIPTION="Windows OS 전용 항목으로 PostgreSQL 환경에는 적용되지 않음"
SEVERITY="중"
CHECKED_AT=$(date -Iseconds)

STATUS="N/A"
RESULT_MSG="Windows OS 전용 항목으로 PostgreSQL(Rocky Linux) 환경에는 해당 없음"


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
