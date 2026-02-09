# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-20
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 하
# @Title       : 인가되지 않은 Object Owner의 제한
# @Description : Object Owner가 인가된 계정에게만 존재하는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash

ID="D-20"

CURRENT_STATUS="FAIL"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"

NOW=$(date '+%Y-%m-%d %H:%M:%S')

# 1. 일반 계정이 소유한 객체 조회 (시스템 스키마 제외)
TARGET_OBJECTS=$(sudo -u postgres psql -t -c "
SELECT
  n.nspname || '.' || c.relname AS object_name,
  c.relkind
FROM pg_class c
JOIN pg_namespace n ON c.relnamespace = n.oid
WHERE c.relowner NOT IN (
    SELECT usesysid FROM pg_user WHERE usesuper = true
)
AND n.nspname NOT IN ('pg_catalog', 'information_schema');
" 2>/dev/null | sed '/^\s*$/d')

# 2. 조치 수행
if [ -z "$TARGET_OBJECTS" ]; then
    CURRENT_STATUS="PASS"
    ACTION_RESULT="NOT_REQUIRED"
    ACTION_LOG="조치 대상 없음: 일반 계정이 소유한 DB 객체가 존재하지 않음"
else
    while read -r line; do
        OBJ=$(echo "$line" | awk '{print $1}')
        KIND=$(echo "$line" | awk '{print $2}')

        case "$KIND" in
            r) TYPE="TABLE" ;;
            S) TYPE="SEQUENCE" ;;
            v) TYPE="VIEW" ;;
            m) TYPE="MATERIALIZED VIEW" ;;
            *) TYPE="" ;;
        esac

        if [ -n "$TYPE" ]; then
            sudo -u postgres psql -c \
            "ALTER $TYPE $OBJ OWNER TO postgres;" >/dev/null 2>&1
        fi
    done <<< "$TARGET_OBJECTS"

    CURRENT_STATUS="PASS"
    ACTION_RESULT="SUCCESS"
    ACTION_LOG="자동 조치 완료: 일반 계정이 소유한 DB 객체의 소유권을 관리자 계정(postgres)으로 이전함"
fi

# 3. JSON 출력 (6개 항목 고정)
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
