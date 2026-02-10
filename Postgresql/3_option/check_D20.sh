# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-20
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 하
# @Title       : 인가되지 않은 Object Owner의 제한
# @Description : Object Owner가 인가된 계정에게만 존재하는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
ID="D-20"
CATEGORY="옵션관리"
TITLE="인가되지 않은 Object Owner의 제한"
IMPORTANCE="하"
DATE=(date '+%Y-%m-%d %H:%M:%S')
TARGET_FILE="pg_class.relowner"
ACTION_IMPACT="Object 소유 권한이 관리자 계정으로 제한되며, 일반적인 서비스 운영에는 영향이 없습니다."
IMPACT_LEVEL="MEDIUM"


cnt=$(psql -U postgres -t -c "
SELECT COUNT(DISTINCT c.relowner)
FROM pg_class c
WHERE c.relowner NOT IN (
    SELECT usesysid
    FROM pg_user
    WHERE usesuper = true
);
" | xargs)


if [ "$cnt" -eq 0 ]; then
  STATUS="양호"
  EVIDENCE="DB 객체가 관리자(postgres)계정으로만 소유됨"
else
  STATUS="취약"
  EVIDENCE="일반 계정이 소유한 DB 객체가 존재함"
fi

cat <<EOF
{ 
"check_id":"$ID",
"category":"$CATEGORY",
"title":"$TITLE",
"importance":"$IMPORTANCE",
"status":"$STATUS",
"evidence":"$EVIDENCE",
"guide": "",
"target_file":"$TARGET_FILE",
"action_impact":"$ACTION_IMPACT",
"impact_level":"$IMPACT_LEVEL",
"check_date": "$DATE"
}
EOF
