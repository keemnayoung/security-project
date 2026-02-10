# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-19
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES를 FALSE로 설정
# @Description : OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES가 FALSE로 설정이 적용되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
ID="D-19"
CATEGORY="옵션관리"
TITLE="OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES를 FALSE로 설정"
IMPORTANCE="상"
DATE=(date '+%Y-%m-%d %H:%M:%S')
STATUS="N/A"
EVIDENCE="PostgreSQL은 OS 계정과 DB 계정을 분리하여 운영함"
TARGET_FILE="OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES"
ACTION_IMPACT="PostgreSQL은 OS 계정과 DB 계정을 분리하여 운영하기때문에 해당없습니다."
IMPACT_LEVEL="LOW"

cat <<EOF
{ 
"check_id":"$ID",
"category":"$CATEGORY",
"title":"$TITLE",
"importance":"$IMPORTANCE",
"status":"$STATUS",
"evidence":"$EVIDENCE",
"guide": "PostgreSQL은 OS 계정과 DB 계정을 분리하여 운영하기때문에 해당없습니다.",
"target_file":"$TARGET_FILE",
"action_impact":"$ACTION_IMPACT",
"impact_level":"$IMPACT_LEVEL",
"check_date": "$DATE"
}

EOF
