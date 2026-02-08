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
TARGET_ACCOUNT="postgres"

ACTION_RESULT="FAIL"
CURRENT_STATUS="FAIL"
ACTION_LOG="N/A"

NOW=$(date '+%Y-%m-%d %H:%M:%S')

# 1. 상태 점검
CHECK_RESULT=$(sudo -u postgres psql -t -c \
"SELECT usename FROM pg_shadow WHERE usename='postgres' AND passwd IS NULL;" \
2>/dev/null)

if [ -z "$CHECK_RESULT" ]; then
    CURRENT_STATUS="PASS"
    ACTION_RESULT="NOT_REQUIRED"
    ACTION_LOG="양호: postgres 계정 비밀번호가 이미 설정되어 있음"
else
    CURRENT_STATUS="FAIL"
    ACTION_RESULT="MANUAL_REQUIRED"
    ACTION_LOG="수동 조치 필요: postgres 계정 passwd 컬럼이 NULL 상태입니다. 1) 관리자 계정으로 접속(sudo -u postgres psql) 2) ALTER USER postgres WITH PASSWORD '강력한비밀번호'; 명령을 실행하세요."
fi

# 2. JSON 출력
cat <<EOF
{
    "check_id": "$ID",
    "status": "$CURRENT_STATUS",
    "action_result": "$ACTION_RESULT",
    "action_log": "$ACTION_LOG",
    "action_date": "$NOW",
    "check_date": "$NOW"
}
EOF
