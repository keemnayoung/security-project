# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-01
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : 기본 계정의 비밀번호, 정책 등을 변경하여 사용
# @Description : DBMS 기본 계정의 초기 비밀번호 및 권한 정책 변경 사용 유무 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

#!/bin/bash

ID="D-01"
CATEGORY="계정 관리"
TITLE="기본 계정의 비밀번호, 정책 등을 변경하여 사용"
IMPORTANCE="상"
TARGET_FILE="pg_shadow.passwd"
IMPACT_LEVEL="MEDIUM"
ACTION_IMPACT="기본 관리자 계정의 불필요한 사용을 제한할 수 있습니다."
STATUS="FAIL"
EVIDENCE="N/A"
DATE=(date '+%Y-%m-%d %H:%M:%S')

PSQL_CMD="psql -U postgres -t -A -c"
QUERY="SELECT usename FROM pg_shadow WHERE usename='postgres' AND passwd IS NULL;"
RESULT=$($PSQL_CMD "$QUERY" 2>/dev/null)

if [ $? -ne 0 ]; then
    STATUS="FAIL"
    EVIDENCE="PostgreSQL 접속 실패 또는 권한이 부족합니다."
else
    if [ -z "$RESULT" ]; then
        STATUS="PASS"
        EVIDENCE="postgres 기본 계정의 비밀번호가 설정되어 있습니다."
    else
        STATUS="FAIL"
        EVIDENCE="postgres 기본 계정의 비밀번호가 설정되어 있지 않습니다."
    fi
fi

cat <<EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "ALTER USER postgres WITH PASSWORD '신규비밀번호'; 명령으로 비밀번호를 설정하세요.",
    "target_file": "$TARGET_FILE",
    "action_impact": "$ACTION_IMPACT",
    "impact_level": "$IMPACT_LEVEL",
    "check_date": "$DATE"
}
EOF
