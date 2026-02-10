# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-16
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 하
# @Title       : Windows 인증 모드 사용
# @Description : DB 로그인 시 Windows 인증 모드 적절성 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
ID="D-16"
CATEGORY="접근관리"
TITLE="Windows 인증 모드 사용"
IMPORTANCE="하"
DATE=(date '+%Y-%m-%d %H:%M:%S')
STATUS="N/A"
TARGET_FILE="Windows sa 계정"
EVIDENCE="PostgreSQL에는 Windows 인증 모드 및 sa 계정 개념이 없음"
ACTION_IMPACT="PostgreSQL에는 Windows 인증 모드 및 sa 계정이 없어 해당없습니다."
IMPACT_LEVEL="LOW"

cat <<EOF
{ 
"check_id":"$ID",
"category":"$CATEGORY",
"title":"$TITLE",
"importance":"$IMPORTANCE",
"status":"$STATUS",
"evidence":"$EVIDENCE",
"guide": "PostgreSQL에는 Windows 인증 모드 및 sa 계정이 없어 해당없습니다.",
"target_file":"$TARGET_FILE",
"action_impact":"$ACTION_IMPACT",
"impact_level":"$IMPACT_LEVEL",
"check_date": "$DATE"
}
EOF
