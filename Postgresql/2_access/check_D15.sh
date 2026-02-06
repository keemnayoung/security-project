# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-15
# @Category    : DBMS
# @Platform    : PostgreSQL
# @Severity    : 하
# @Title       : 관리자 이외의 사용자가 오라클 리스너의 접속을 통해 리스너 로그 및 trace 파일에 대한 변경 제한
# @Description : Oracle DB Listener 전용 항목으로 PostgreSQL에는 적용되지 않음
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
ITEM_ID="D-15"
CATEGORY="접근관리"
CHECK_ITEM="Listener 설정 보호"
DESCRIPTION="Oracle DB Listener 전용 항목으로 PostgreSQL에는 적용되지 않음"
SEVERITY="하"
CHECKED_AT=$(date -Iseconds)

STATUS="N/A"
RESULT_MSG="PostgreSQL에는 Listener 및 lsnrctl 개념이 없어 점검 대상이 아님"

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
