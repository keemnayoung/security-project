# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-24
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : Registry Procedure 권한 제한
# @Description : MSSQL 전용 Registry Procedure 기능은 PostgreSQL에 존재하지 않음
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
ID="D-24"
CATEGORY="옵션관리"
TITLE="Registry Procedure 권한 제한"
IMPORTANCE="상"
DATE=(date '+%Y-%m-%d %H:%M:%S')
STATUS="N/A"
EVIDENCE="PostgreSQL에는 Registry Procedure(xp_reg*) 기능이 존재하지 않아 해당하지 않습니다."
TARGET_FILE="Registry Procedure"
ACTION_IMPACT="PostgreSQL에는 Registry Procedure(xp_reg*) 기능이 존재하지 않아 해당하지 않습니다."
IMPACT_LEVEL="LOW"

cat <<EOF
{ 
"check_id":"$ID",
"category":"$CATEGORY",
"title":"$TITLE",
"importance":"$IMPORTANCE",
"status":"$STATUS",
"evidence":"$EVIDENCE",
"guide": "PostgreSQL에는 Registry Procedure(xp_reg*) 기능이 존재하지 않아 해당하지 않습니다.",
"target_file":"$TARGET_FILE",
"action_impact":"$ACTION_IMPACT",
"impact_level":"$IMPACT_LEVEL",
"check_date": "$DATE"
}
EOF
