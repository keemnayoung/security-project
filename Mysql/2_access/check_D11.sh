#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-07
# ============================================================================
# [점검 항목 상세]
# @ID          : D-11
# @Category    : DBMS (Database Management System)
# @Platform    : MySQL 8.0.44
# @Severity    : 상
# @Title       : DBA 이외 사용자의 시스템 테이블 접근 제한
# @Description : mysql 등 시스템 스키마에 일반 사용자가 접근 불가하도록 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

set -euo pipefail

ITEM_ID="D-11"
CATEGORY="권한관리"
CHECK_ITEM="DBA 이외 사용자의 시스템 테이블 접근 제한"
DESCRIPTION="mysql 등 시스템 스키마에 일반 사용자가 접근 불가하도록 설정 여부 점검"
IMPORTANCE="상"
CHECKED_AT=$(date -Iseconds)

STATUS="수동진단"
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
    # 2. 시스템 스키마(mysql, sys, performance_schema) 접근 권한 보유 계정 조회
    ########################################
    sys_priv_users=$($MYSQL_CMD -e "
    SELECT DISTINCT GRANTEE 
    FROM information_schema.schema_privileges 
    WHERE TABLE_SCHEMA IN ('mysql','sys','performance_schema','information_schema')
    AND PRIVILEGE_TYPE IN ('SELECT','INSERT','UPDATE','DELETE','ALL PRIVILEGES');" 2>/dev/null || echo "")

    ########################################
    # 3. root 및 관리자 계정 제외
    ########################################
    non_dba=$(echo "$sys_priv_users" | grep -v -E "root|mysql.sys|mysql.session" || echo "")

    if [ -z "$sys_priv_users" ]; then
        STATUS="양호"
        RESULT_MSG="시스템 스키마 접근 권한 계정 없음"
    elif [ -z "$non_dba" ]; then
        STATUS="양호"
        RESULT_MSG="DBA 계정에만 시스템 테이블 접근 권한 부여됨"
    else
        STATUS="취약"
        bad_users=$(echo "$non_dba" | head -5 | tr '\n' ', ')
        RESULT_MSG="일반 계정에 시스템 테이블 접근 권한 존재: ${bad_users}"
    fi
fi

########################################
# JSON 결과 출력 (고정 형식)
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
