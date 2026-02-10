# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-23
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : xp_cmdshell 사용 제한
# @Description : xp_cmdshell의 사용 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
ID="D-23"
CATEGORY="옵션관리"
TITLE="xp_cmdshell 사용 제한"
IMPORTANCE="상"
DATE=(date '+%Y-%m-%d %H:%M:%S')
STATUS="N/A"
EVIDENCE="PostgreSQL DBMS에는 xp_cmdshell 또는 이에 상응하는 OS 명령 실행 기능이 존재하지 않아 점검 대상 아님"
TARGET_FILE="xp_cmdshell"
ACTION_IMPACT="PostgreSQL DBMS에는 xp_cmdshell 또는 이에 상응하는 OS 명령 실행 기능이 존재하지 않아 점검 대상이 아닙니다."
IMPACT_LEVEL="LOW"

cat <<EOF
{ 
"check_id":"$ID",
"category":"$CATEGORY",
"title":"$TITLE",
"importance":"$IMPORTANCE",
"status":"$STATUS",
"evidence":"$EVIDENCE",
"guide": "PostgreSQL DBMS에는 xp_cmdshell 또는 이에 상응하는 OS 명령 실행 기능이 존재하지 않아 점검 대상이 아닙니다.",
"target_file":"$TARGET_FILE",
"action_impact":"$ACTION_IMPACT",
"impact_level":"$IMPACT_LEVEL",
"check_date": "$DATE"
}
EOF
