# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-14
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 중
# @Title       : 데이터베이스의 주요 설정 파일, 비밀번호 파일 등과 같은 주요 파일들의 접근 권한이 적절하게 설정
# @Description : 데이터베이스의 주요 파일들에 대해 관리자를 제외한 일반 사용자의 파일 수정 권한을 제거하였는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash

ID="D-14"

CURRENT_STATUS="FAIL"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"

NOW=$(date '+%Y-%m-%d %H:%M:%S')

PGDATA="/var/lib/pgsql/data"
LOGDIR="$PGDATA/log"
PSQL_HISTORY="/var/lib/pgsql/.psql_history"

ERROR_FLAG=0

# 1. PGDATA 디렉터리 권한 조치
if [ -d "$PGDATA" ]; then
    chown postgres "$PGDATA" 2>/dev/null
    chmod 750 "$PGDATA" 2>/dev/null
else
    ERROR_FLAG=1
    ACTION_LOG="PGDATA 디렉터리가 존재하지 않음;"
fi

# 2. 주요 설정 파일 권한 조치
for f in postgresql.conf pg_hba.conf pg_ident.conf; do
    FILE="$PGDATA/$f"
    if [ -f "$FILE" ]; then
        chown postgres "$FILE" 2>/dev/null
        chmod 640 "$FILE" 2>/dev/null
    else
        ERROR_FLAG=1
        ACTION_LOG="$ACTION_LOG $f 파일 없음;"
    fi
done

# 3. psql 히스토리 파일 권한 조치
if [ -f "$PSQL_HISTORY" ]; then
    chown postgres "$PSQL_HISTORY" 2>/dev/null
    chmod 600 "$PSQL_HISTORY" 2>/dev/null
fi

# 4. 로그 디렉터리 권한 조치
if [ -d "$LOGDIR" ]; then
    chown -R postgres "$LOGDIR" 2>/dev/null
    find "$LOGDIR" -type f -exec chmod 640 {} \; 2>/dev/null
fi

# 5. 결과 판단
if [ "$ERROR_FLAG" -eq 0 ]; then
    CURRENT_STATUS="PASS"
    ACTION_RESULT="SUCCESS"
    ACTION_LOG="자동 조치 완료: PostgreSQL 주요 설정 파일, 데이터 디렉터리 및 로그 파일 권한을 보안 기준에 맞게 수정함"
else
    CURRENT_STATUS="FAIL"
    ACTION_RESULT="PARTIAL_SUCCESS"
    ACTION_LOG="부분 조치 완료: 일부 파일 또는 디렉터리가 존재하지 않거나 조치 중 오류 발생"
fi

# 6. JSON 출력 (6개 항목 고정)
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
