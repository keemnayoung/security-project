# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-11
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : DBA 이외의 인가되지 않은 사용자가 시스템 테이블에 접근할 수 없도록 설정
# @Description : 시스템 테이블에 일반 사용자 계정이 접근할 수 없도록 설정되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
ID="D-11"
CATEGORY="접근관리"
TITLE="DBA 이외의 인가되지 않은 사용자가 시스템 테이블에 접근할 수 없도록 설정"
IMPORTANCE="상"
DATE=(date '+%Y-%m-%d %H:%M:%S')
TARGET_FILE="pg_catalog.*, information_schema.*"
ACTION_IMPACT="일반 사용자 계정의 시스템 테이블 접근이 차단되며, 해당 권한을 전제로 동작하던 모니터링 또는 진단 기능은 DBA 계정으로 권한 전환이 필요할 수 있습니다."
IMPACT_LEVEL="HIGH"

cnt=$(psql -U postgres -t -c "
SELECT COUNT(*)
FROM information_schema.table_privileges tp
JOIN pg_roles r ON tp.grantee = r.rolname
WHERE tp.table_schema IN ('pg_catalog', 'information_schema')
  AND r.rolsuper = false;
" | xargs)

if [ "$cnt" -eq 0 ]; then
  STATUS="PASS"
  EVIDENCE="일반 사용자 계정의 시스템 테이블 접근 권한 미부여"
else
  STATUS="FAIL"
  EVIDENCE="일반 사용자 계정에 시스템 테이블 접근 권한 부여됨"
fi

cat <<EOF
{ 
"check_id":"$ID",
"category":"$CATEGORY",
"title":"$TITLE",
"importance":"$IMPORTANCE",
"status":"$STATUS",
"evidence":"$EVIDENCE",
"guide":"PostgreSQL 시스템 카탈로그(pg_catalog, information_schema)에 대해 일반 사용자 계정의 접근 권한을 제거하고, DBA 또는 관리자 계정만 조회 가능하도록 설정하십시오. 권한 변경 후 영향 여부를 확인해야 합니다.",
"target_file":"$TARGET_FILE",
"action_impact":"$ACTION_IMPACT",
"impact_level":"$IMPACT_LEVEL",
"check_date": "$DATE" }
EOF
