# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-07
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 중
# @Title       : root 권한으로 서비스 구동 제한
# @Description : 서비스 구동 시 root 계정 또는 root 권한으로 구동되는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
ITEM_ID="D-07"
CATEGORY="계정관리"
CHECK_ITEM="root 권한 서비스 구동 제한"
DESCRIPTION="서비스 구동 시 root 계정 또는 root 권한으로 구동되는지 점검"
IMPORTANCE="중"
CHECKED_AT=$(date -Iseconds)

root_cnt=$(ps -eo user,comm | grep postgres | grep -w root | wc -l)

if [ "$root_cnt" -eq 0 ]; then
  STATUS="양호"
  RESULT_MSG="PostgreSQL 서비스가 전용 계정(postgres)으로 실행 중"
else
  STATUS="취약"
  RESULT_MSG="PostgreSQL 서비스가 root 권한으로 실행 중"
fi

cat <<EOF
{
  "item_id":"$ITEM_ID",
  "category":"$CATEGORY",
  "check_item":"$CHECK_ITEM",
  "description":"$DESCRIPTION",
  "IMPORTANCE":"$IMPORTANCE",
  "checked_at":"$CHECKED_AT",
  "status":"$STATUS",
  "result":"$RESULT_MSG",
  "checked": true
}
EOF
