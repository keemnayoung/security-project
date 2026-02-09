#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-07
# ============================================================================
# [점검 항목 상세]
# @ID          : D-10
# @Category    : DBMS (Database Management System)
# @Platform    : MySQL 8.0.44
# @IMPORTANCE  : 상
# @Title       : 원격에서 DB서버로의 접속 제한
# @Description : 지정된 IP주소만 DB 서버에 접근 가능하도록 설정되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

set -euo pipefail

ITEM_ID="D-10"
CATEGORY="접근제어"
CHECK_ITEM="원격에서 DB서버로의 접속 제한"
DESCRIPTION="지정된 IP주소만 DB 서버에 접근 가능하도록 설정되어 있는지 점검"
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

inspection_summary=""
vulnerabilities=0

# 1. bind_address 확인
bind_addr=$($MYSQL_CMD -e "SHOW VARIABLES LIKE 'bind_address';" 2>/dev/null | tail -n +2 | awk '{print $2}' || echo "")
if [ -z "$bind_addr" ]; then
    inspection_summary+="bind_address 확인 불가\n"
    STATUS="수동진단"
    RESULT_MSG="MySQL 접속 실패 또는 bind_address 확인 불가"
elif [ "$bind_addr" = "0.0.0.0" ] || [ "$bind_addr" = "::" ]; then
    inspection_summary+="취약: bind_address가 ${bind_addr}로 모든 IP 허용\n"
    STATUS="취약"
    RESULT_MSG="bind_address가 모든 IP 허용"
    ((vulnerabilities++))
else
    inspection_summary+="양호: bind_address가 ${bind_addr}로 제한됨\n"
fi

# 2. 원격 접속 가능한 사용자 확인
remote_users=$($MYSQL_CMD -e "SELECT user, host FROM mysql.user WHERE host IN ('%', '0.0.0.0', '::') ORDER BY user, host;" 2>/dev/null || echo "")
remote_count=$(echo "$remote_users" | tail -n +2 | grep -v "^$" | wc -l || echo 0)
if [ "$remote_count" -gt 0 ]; then
    STATUS="취약"
    RESULT_MSG+=" ${remote_count}개 계정이 모든 원격 호스트에서 접속 가능"
    users_list=$(echo "$remote_users" | tail -n +2 | head -5 | tr '\n' ', ')
    inspection_summary+="취약: 원격 접속 허용 계정: ${users_list}\n"
    ((vulnerabilities++))
else
    inspection_summary+="양호: 원격 접속 허용 계정 없음\n"
fi

# 3. 포트 확인
port_value=$($MYSQL_CMD -e "SHOW VARIABLES LIKE 'port';" 2>/dev/null | tail -n +2 | awk '{print $2}' || echo "")
inspection_summary+="MySQL 포트: ${port_value}\n"

# 최종 판단
if [ $vulnerabilities -eq 0 ] && [ "$STATUS" != "수동진단" ]; then
    STATUS="양호"
    RESULT_MSG="원격 접속이 적절하게 제한됨"
fi

# JSON 출력
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
