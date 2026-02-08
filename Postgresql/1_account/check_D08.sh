# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-08
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : 안전한 암호화 알고리즘 사용
# @Description : 해시 알고리즘 SHA-256 이상의 암호화 알고리즘을 사용하는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
ITEM_ID="D-08"
CATEGORY="계정관리"
CHECK_ITEM="비밀번호 암호화 알고리즘"
DESCRIPTION="해시 알고리즘 SHA-256 이상의 암호화 알고리즘을 사용하는지 점검"
IMPORTANCE="상"
CHECKED_AT=$(date -Iseconds)

enc=$(psql -U postgres -t -c "SHOW password_encryption;" | xargs)

if [ "$enc" = "scram-sha-256" ]; then
  STATUS="양호"
  RESULT_MSG="SHA-256 기반 SCRAM 암호화 알고리즘 사용"
else
  STATUS="취약"
  RESULT_MSG="SHA-256 미만 암호화 알고리즘 사용($enc)"
fi

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
