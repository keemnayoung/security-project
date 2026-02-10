# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-21
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 중
# @Title       : 인가되지 않은 GRANT OPTION 사용 제한
# @Description : 일반 사용자에게 GRANT OPTION이 ROLE에 의하여 부여되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
ID="D-21"
CATEGORY="옵션관리"
TITLE="인가되지 않은 GRANT OPTION 사용 제한"
IMPORTANCE="중"
DATE=(date '+%Y-%m-%d %H:%M:%S')
TARGET_FILE="information_schema.table_privileges"
ACTION_IMPACT="일반 사용자 계정이 다른 사용자에게 권한을 부여하는 기능이 제한되며, 서비스 동작에는 영향을 주지 않습니다."
IMPACT_LEVEL="LOW"

cnt=$(psql -U postgres -t -c "
SELECT COUNT(*)
FROM information_schema.table_privileges tp
JOIN pg_roles r ON tp.grantee = r.rolname
WHERE tp.is_grantable = 'YES'
  AND r.rolsuper = false;
" | xargs)

if [ "$cnt" -eq 0 ]; then
  STATUS="양호"
  EVIDENCE="일반 사용자에게 GRANT OPTION 미부여"
else
  STATUS="취약"
  EVIDENCE="일반 사용자에게 GRANT OPTION 부여됨"
fi

cat <<EOF
{ 
"check_id":"$ID",
"category":"$CATEGORY",
"title":"$TITLE",
"importance":"$IMPORTANCE",
"status":"$STATUS",
"evidence":"$EVIDENCE",
"guide":"PostgreSQL에서 GRANT OPTION이 부여된 객체 권한을 점검하고, 관리자 계정이 아닌 사용자에게 부여된 GRANT OPTION은 REVOKE 명령을 통해 제거하십시오.",
"target_file":"$TARGET_FILE",
"action_impact":"$ACTION_IMPACT",
"impact_level":"$IMPACT_LEVEL",
"check_date": "$DATE"
}
EOF
