# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-22
# @Category    : DBMS
# @Platform    : PostgreSQL
# @Severity    : 하
# @Title       : 데이터베이스의 자원 제한 기능을 TRUE로 설정
# @Description : Oracle DB 전용 RESOURCE_LIMIT 항목으로 PostgreSQL에는 해당 기능 없음
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
ITEM_ID="D-22"
CATEGORY="옵션관리"
CHECK_ITEM="DB 자원 제한 기능"
DESCRIPTION="Oracle DB 전용 RESOURCE_LIMIT 항목으로 PostgreSQL에는 해당 기능 없음"
SEVERITY="하"
CHECKED_AT=$(date -Iseconds)

STATUS="N/A"
RESULT_MSG="PostgreSQL DBMS에는 RESOURCE_LIMIT 파라미터가 존재하지 않아 점검 대상 아님"
CHECKED=false

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
