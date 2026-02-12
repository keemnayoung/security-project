# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-18
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : 응용프로그램 또는 DBA 계정의 Role이 Public으로 설정되지 않도록 조정
# @Description : 응용 프로그램 또는 DBA 계정의 Role이 Public으로 설정되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
ID="D-18"
CATEGORY="옵션관리"
TITLE="PUBLIC Role 권한"
DESCRIPTION="응용 프로그램 또는 DBA 계정의 Role이 Public으로 설정되어 있는지 점검"
IMPORTANCE="상"
DATE=(date '+%Y-%m-%d %H:%M:%S')
TARGET_FILE="information_schema.table_privileges"
ACTION_IMPACT="PUBLIC Role을 통한 불필요한 객체 접근이 차단되며, 일반적인 경우 응용 프로그램 및 서비스 동작에는 영향이 없습니다."
IMPACT_LEVEL="MEDIUM"

cnt=$(psql -U postgres -t -c "
SELECT COUNT(*)
FROM information_schema.table_privileges
WHERE grantee = 'PUBLIC';
" | xargs)

if [ "$cnt" -eq 0 ]; then
  STATUS="PASS"
   EVIDENCE="PUBLIC Role에 불필요한 권한이 부여되지 않음"
else
  STATUS="FAIL"
   EVIDENCE="PUBLIC Role에 부여된 객체 권한 존재"
fi

cat <<EOF
{ 
"check_id":"$ID",
"category":"$CATEGORY",
"title":"$TITLE",
"importance":"$IMPORTANCE",
"status":"$STATUS",
"evidence":"$EVIDENCE",
"guide":"PostgreSQL에서 PUBLIC Role에 부여된 테이블 및 객체 권한을 점검하고, 불필요한 권한은 REVOKE 명령으로 제거하십시오. 필요한 권한은 개별 사용자 또는 Role에 명시적으로 부여해야 합니다.",
"target_file":"$TARGET_FILE",
"action_impact":"$ACTION_IMPACT",
"impact_level":"$IMPACT_LEVEL",
"check_date": "$DATE"
}
EOF
