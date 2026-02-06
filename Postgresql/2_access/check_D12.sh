# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-12
# @Category    : DBMS
# @Platform    : PostgreSQL
# @Severity    : 상
# @Title       : 안전한 리스너 비밀번호 설정 및 사용
# @Description : DBMS 접속 이력에 대한 로그가 정상적으로 수집되고 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
ITEM_ID="D-12"
CATEGORY="접근관리"
CHECK_ITEM="Listener 보안 설정"
DESCRIPTION="PostgreSQL에는 Listener 개념이 없어 해당 없음"
SEVERITY="상"
CHECKED_AT=$(date -Iseconds)

STATUS="N/A"
RESULT_MSG="Oracle DB Listener 보안 항목으로 PostgreSQL에는 적용되지 않음"

cat <<EOF
{
  "item_id":"$ITEM_ID",
  "category":"$CATEGORY",
  "check_item":"$CHECK_ITEM",
  "description":"$DESCRIPTION",
  "severity":"$SEVERITY",
  "checked_at":"$CHECKED_AT",
  "status":"$STATUS",
  "result":"$RESULT_MSG",
  "checked": false
}
EOF
