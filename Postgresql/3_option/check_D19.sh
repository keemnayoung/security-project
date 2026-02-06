# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-19
# @Category    : DBMS
# @Platform    : PostgreSQL
# @Severity    : 상
# @Title       : 감사 로그 설정
# @Description : Oracle DB 전용 항목으로 PostgreSQL에는 해당 없음
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
ITEM_ID="D-19"
CATEGORY="옵션관리"
CHECK_ITEM="OS 인증 연계"
DESCRIPTION="Oracle DB 전용 항목으로 PostgreSQL에는 해당 없음"
SEVERITY="상"
CHECKED_AT=$(date -Iseconds)

STATUS="N/A"
RESULT_MSG="PostgreSQL은 OS 계정과 DB 계정을 분리하여 운영함"

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
