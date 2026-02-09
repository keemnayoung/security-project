#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-07
# ============================================================================
# [점검 항목 상세]
# @ID          : D-21
# @Category    : DBMS (Database Management System)
# @Platform    : MySQL 8.0.44
# @IMPORTANCE  : 중
# @Title       : 인가되지 않은 GRANT OPTION 사용 제한
# @Description : 일반 사용자에게 GRANT OPTION이 부여되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

set -euo pipefail

ITEM_ID="D-21"
CATEGORY="권한관리"
CHECK_ITEM="인가되지 않은 GRANT OPTION 사용 제한"
DESCRIPTION="일반 사용자에게 GRANT OPTION이 부여되어 있는지 점검"
IMPORTANCE="중"
CHECKED_AT=$(date -Iseconds)

STATUS="양호"
RESULT_MSG=""
CHECKED=true

DB_USER="${DB_USER:-root}"
DB_PASSWORD="${DB_PASSWORD:-}"
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-3306}"

MYSQL_CMD="mysql -N -B -h${DB_HOST} -P${DB_PORT} -u${DB_USER} -p${DB_PASSWORD}"

########################################
# 1. MySQL 접속 확인
########################################
if ! $MYSQL_CMD -e "SELECT 1" &>/dev/null; then
    STATUS="점검불가"
    RESULT_MSG="MySQL 접속 실패"
else

    ########################################
    # 2. GRANT OPTION 보유 계정 조회
    ########################################
    grant_users=$($MYSQL_CMD -e "
    SELECT DISTINCT GRANTEE
    FROM information_schema.user_privileges
    WHERE PRIVILEGE_TYPE='GRANT OPTION';" 2>/dev/null || echo "")

    ########################################
    # 3. DBA 계정 제외
    ########################################
    non_dba=$(echo "$grant_users" | grep -v -E "root|mysql.sys|mysql.session" || echo "")

    if [ -z "$grant_users" ]; then
        STATUS="양호"
        RESULT_MSG="GRANT OPTION 보유 계정 없음"
    elif [ -z "$non_dba" ]; then
        STATUS="양호"
        RESULT_MSG="DBA 계정에만 GRANT OPTION 부여됨"
    else
        STATUS="취약"
        bad_users=$(echo "$non_dba" | head -5 | tr '\n' ', ')
        RESULT_MSG="일반 계정에 GRANT OPTION 권한 존재: ${bad_users}"
    fi
fi

########################################
# JSON 결과 출력 (필수 형식)
########################################
cat <<EOF
{
  "item_id": "$ITEM_ID",
  "category": "$CATEGORY",
  "check_item": "$CHECK_ITEM",
  "description": "$DESCRIPTION",
  "IMPORTANCE": "$IMPORTANCE",
  "checked_at": "$CHECKED_AT",
  "status": "$STATUS",
  "result": "$RESULT_MSG",
  "checked": $CHECKED
}
EOF
