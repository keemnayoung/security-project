# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-01
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : 기본 계정의 비밀번호, 정책 등을 변경하여 사용
# @Description : DBMS 기본 계정의 초기 비밀번호 및 권한 정책 변경 사용 유무 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

#!/bin/bash
ITEM_ID="D-01"
CATEGORY="계정관리"
CHECK_ITEM="DB 기본 계정 비밀번호 변경 여부"
DESCRIPTION="DBMS 기본 계정의 초기 비밀번호 및 권한 정책 변경 사용 유무 점검"
IMPORTANCE="상"

CHECKED_AT=$(date -Iseconds)

result=$(psql -U postgres -t -c \
"SELECT usename FROM pg_shadow WHERE usename='postgres' AND passwd IS NULL;" 2>/dev/null)

if [ -z "$result" ]; then
  STATUS="양호"
  RESULT_MSG="초기 비밀번호가 변경되어 있음"
  CHECKED=true
else
  STATUS="취약"
  RESULT_MSG="초기 비밀번호가 변경되어 있지 않음"
  CHECKED=true
fi

cat <<EOF
{
  "item_id": "$ITEM_ID",
  "category": "$CATEGORY",
  "check_item": "$CHECK_ITEM",
  "description": "$DESCRIPTION",
  "IMPORTANCE": "$IMPORTANCE",
  "checked_at": "$CHECKED_AT",
  "status": "$STATUS",
  "result": "$RESULT_MSG",
  "checked": $CHECKED
}
EOF
