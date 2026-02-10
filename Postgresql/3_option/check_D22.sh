# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-22
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 하
# @Title       : 데이터베이스의 자원 제한 기능을 TRUE로 설정
# @Description : RESOURCE_LIMIT 값이 TRUE로 설정되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
ID="D-22"
CATEGORY="옵션관리"
TITLE="DB 자원 제한 기능"
IMPORTANCE="하"
DATE=(date '+%Y-%m-%d %H:%M:%S')
STATUS="N/A"
EVIDENCE="PostgreSQL DBMS에는 RESOURCE_LIMIT 파라미터가 존재하지 않아 점검 대상 아님"
TARGET_FILE="RESOURCE_LIMIT"
ACTION_IMPACT="PostgreSQL DBMS에는 RESOURCE_LIMIT 파라미터가 존재하지 않아 조치 대상이 아니며, 서비스 운영에는 영향이 없습니다."
IMPACT_LEVEL="LOW"


cat <<EOF
{ 
"check_id":"$ID",
"category":"$CATEGORY",
"title":"$TITLE",
"importance":"$IMPORTANCE",
"status":"$STATUS",
"evidence":"$EVIDENCE",
"guide": "PostgreSQL DBMS에는 RESOURCE_LIMIT 파라미터가 존재하지 않아 조치 대상이 아니며, 서비스 운영에는 영향이 없습니다.",
"target_file":"$TARGET_FILE",
"action_impact":"$ACTION_IMPACT",
"impact_level":"$IMPACT_LEVEL",
"check_date": "$DATE"
}
EOF
