#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-07
# ============================================================================
# [점검 항목 상세]
# @ID          : D-04
# @Category    : DBMS (Database Management System)
# @Platform    : MySQL 8.0.44
# @IMPORTANCE  : 상
# @Title       : 데이터베이스 관리자 권한을 꼭 필요한 계정에만 부여
# @Description : 관리자 권한이 필요한 계정 및 그룹에만 관리자 권한을 부여하였는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

set -euo pipefail

ITEM_ID="D-04"
CATEGORY="계정관리"
CHECK_ITEM="데이터베이스 관리자 권한을 꼭 필요한 계정에만 부여"
DESCRIPTION="관리자 권한이 필요한 계정 및 그룹에만 관리자 권한을 부여하였는지 점검"
IMPORTANCE="상"
CHECKED_AT=$(date -Iseconds)

STATUS="양호"
RESULT_MSG=""
CHECKED=true

DB_USER="${DB_USER:-root}"
DB_PASSWORD="${DB_PASSWORD:-}"
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-3306}"

MYSQL_CMD="mysql -N -B -h ${DB_HOST} -P ${DB_PORT} -u ${DB_USER} -p${DB_PASSWORD}"

############################################
# 1. MySQL 접속 확인
############################################
if ! $MYSQL_CMD -e "SELECT 1;" >/dev/null 2>&1; then
  STATUS="점검불가"
  RESULT_MSG="MySQL 접속 실패"
else

############################################
# 2. 관리자급 권한 보유 계정 조회
############################################
ADMIN_QUERY="
SELECT GRANTEE, PRIVILEGE_TYPE
FROM INFORMATION_SCHEMA.USER_PRIVILEGES
WHERE PRIVILEGE_TYPE IN (
  'SUPER',
  'SYSTEM_VARIABLES_ADMIN',
  'BINLOG_ADMIN',
  'ROLE_ADMIN'
);"

admin_list=$($MYSQL_CMD -e "$ADMIN_QUERY" 2>/dev/null || true)

if [ -z "$admin_list" ]; then
  RESULT_MSG="관리자 권한 보유 계정 없음"
else
  vuln_accounts=""

  while read -r grantee privilege; do
    user=$(echo "$grantee" | cut -d"'" -f2)

    # 허용되는 시스템 관리자 계정
    if [[ "$user" != "root" && "$user" != "mysql.sys" && "$user" != "mysql.session" ]]; then
      vuln_accounts+="$grantee($privilege) "
    fi
  done <<< "$admin_list"

  if [ -n "$vuln_accounts" ]; then
    STATUS="취약"
    RESULT_MSG="불필요 관리자 권한 계정 존재: $vuln_accounts"
  else
    RESULT_MSG="관리자 권한이 필요한 계정에만 부여됨"
  fi
fi
fi

############################################
# 결과 출력 (지정 형식)
############################################
cat <<EOF
{
  "item_id": "$ITEM_ID",
  "category": "$CATEGORY",
  "check_item": "$CHECK_ITEM",
  "description": "$DESCRIPTION",
  "severity": "$SEVERITY",
  "checked_at": "$CHECKED_AT",
  "status": "$STATUS",
  "result": "$RESULT_MSG",
  "checked": $CHECKED
}
EOF
