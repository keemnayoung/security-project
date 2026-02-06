# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-17
# @Category    : DBMS
# @Platform    : PostgreSQL
# @Severity    : 하
# @Title       : Audit Table 접근 통제
# @Description : PostgreSQL에는 Audit Table 개념이 없어 점검 대상 아님
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
ITEM_ID="D-17"
CATEGORY="옵션관리"
CHECK_ITEM="Audit Table 접근 통제"
DESCRIPTION="PostgreSQL에는 Audit Table 개념이 없어 점검 대상 아님"
SEVERITY="하"
CHECKED_AT=$(date -Iseconds)

STATUS="N/A"
RESULT_MSG="PostgreSQL은 파일 기반 감사 로그 구조를 사용하여 Audit Table 점검 대상이 아님"

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
