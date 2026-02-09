#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 8.0.44
# @Author: 한은결
# @Last Updated: 2026-02-07
# ============================================================================
# [점검 항목 상세]
# @ID          : D-06
# @Category    : DBMS (Database Management System)
# @Platform    : MySQL 8.0.44
# @IMPORTANCE  : 중
# @Title       : DB 사용자 계정을 개별적으로 부여하여 사용
# @Description : DB 접근 시 사용자별로 서로 다른 계정을 사용하여 접근하는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

set -euo pipefail

ITEM_ID="D-06" 
CATEGORY="계정관리"
CHECK_ITEM="DB 사용자 계정을 개별적으로 부여하여 사용"
DESCRIPTION="DB 접근 시 사용자별로 서로 다른 계정을 사용하여 접근하는지 점검"
IMPORTANCE="중"
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
# 2. 전체 계정 목록 수집
############################################
users=$($MYSQL_CMD -e "SELECT user FROM mysql.user;" 2>/dev/null || true)

if [ -z "$users" ]; then
  STATUS="점검불가"
  RESULT_MSG="계정 목록 조회 실패"

else

vuln=0

############################################
# 3. 공유 계정으로 의심되는 이름 탐지
############################################
shared_accounts=$(echo "$users" | grep -iE '^(shared|public|common|generic|group|team|user|test|admin)$' || true)

############################################
# 4. root 외 동일 사용자 다중 host 사용 탐지
############################################
dup_accounts=$($MYSQL_CMD -e "
SELECT user FROM mysql.user
GROUP BY user
HAVING COUNT(host) > 5 AND user NOT IN ('root','mysql.sys','mysql.session');
" 2>/dev/null || true)

############################################
# 판정 로직
############################################
if [ -n "$shared_accounts" ]; then
  RESULT_MSG+="공유 계정 의심: $(echo "$shared_accounts" | tr '\n' ', '); "
  ((vuln++))
fi

if [ -n "$dup_accounts" ]; then
  RESULT_MSG+="다수 사용자가 공용 사용 가능 계정 존재: $(echo "$dup_accounts" | tr '\n' ', '); "
  ((vuln++))
fi

if [ "$vuln" -gt 0 ]; then
  STATUS="취약"
else
  RESULT_MSG="사용자별 개별 계정 사용으로 판단됨"
fi

fi
fi

############################################
# 결과 JSON 출력 (필수 형식)
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
