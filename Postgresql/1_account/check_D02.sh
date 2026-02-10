# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-02
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : 데이터베이스의 불필요 계정을 제거하거나, 잠금설정 후 사용
# @Description : DBMS에 존재하는 계정 중 DB 관리나 운용에 사용하지 않는 불필요한 계정이 존재하는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

#!/bin/bash
ID="D-02"
CATEGORY="계정 관리"
TITLE="데이터베이스의 불필요 계정을 제거하거나, 잠금설정 후 사용"

IMPORTANCE="상"
DATE=(date '+%Y-%m-%d %H:%M:%S')

TARGET_FILE="pg_roles.rolcanlogin, pg_class.relowner"
IMPACT_LEVEL="MEDIUM"
ACTION_IMPACT="Demonstration 계정 및 불필요한 계정의 사용이 제한되며, 해당 계정이 소유한 객체(Object)는 더 이상 사용되지 않습니다."

#postgres 기본 관리자 계정에 속하지 않고 이름에 test,demo,temp가 들어간 계정 제외
cnt=$(psql -U postgres -t -c \
"SELECT COUNT(*) FROM pg_roles WHERE rolcanlogin = true
  AND rolname NOT IN ('postgres')
  AND (
    rolname ILIKE '%test%'
    OR rolname ILIKE '%demo%'
    OR rolname ILIKE '%temp%'
  );" | xargs)

if [ "$cnt" -eq 0 ]; then
  STATUS="양호"
  EVIDENCE="불필요 계정이 없습니다."
else
  STATUS="취약"
  EVIDENCE="불필요 계정 존재합니다."
fi

cat <<EOF
{ "check_id":"$ID",
"category":"$CATEGORY",
"title":"$TITLE",
"importance":"$IMPORTANCE",
"status":"$STATUS",
"evidence":"$EVIDENCE",
"target_file": "$TARGET_FILE",
"action_impact": "$ACTION_IMPACT",
"impact_level": "$IMPACT_LEVEL",
"check_date": "$DATE" }
EOF
