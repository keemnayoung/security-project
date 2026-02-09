# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-24
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : Registry Procedure 권한 제한
# @Description : MSSQL 전용 Registry Procedure 기능은 PostgreSQL에 존재하지 않음
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
ITEM_ID="D-24"
CATEGORY="옵션관리"
CHECK_ITEM="Registry Procedure 권한 제한"
DESCRIPTION="MSSQL 전용 Registry Procedure 기능은 PostgreSQL에 존재하지 않음"
IMPORTANCE="상"
CHECKED_AT=$(date -Iseconds)

STATUS="N/A"
RESULT_MSG="PostgreSQL DBMS에는 Registry Procedure(xp_reg*) 기능이 존재하지 않아 점검 대상 아님"
CHECKED=false

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
