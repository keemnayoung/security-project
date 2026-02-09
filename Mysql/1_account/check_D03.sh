#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-07
# ============================================================================
# [점검 항목 상세]
# @ID          : D-03
# @Category    : DBMS (Database Management System)
# @Platform    : MySQL 8.0.44
# @IMPORTANCE  : 상
# @Title       : 비밀번호 사용 기간 및 복잡도 정책 설정
# @Description : 기관 정책에 맞게 비밀번호 사용 기간 및 복잡도 설정이 적용되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

set -euo pipefail

ITEM_ID="D-03"
CATEGORY="계정관리"
CHECK_ITEM="비밀번호 사용 기간 및 복잡도 정책 설정"
DESCRIPTION="기관 정책에 맞게 비밀번호 사용 기간 및 복잡도 설정이 적용되어 있는지 점검"
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

vuln=0

############################################
# 2. validate_password 컴포넌트 확인
############################################
component=$($MYSQL_CMD -e "SELECT component_urn FROM mysql.component WHERE component_urn LIKE '%validate_password%';" 2>/dev/null || true)
if [ -z "$component" ]; then
  RESULT_MSG+="validate_password 컴포넌트 미설치; "
  ((vuln++))
fi

############################################
# 3. 비밀번호 최소 길이
############################################
min_len=$($MYSQL_CMD -e "SHOW VARIABLES LIKE 'validate_password.length';" 2>/dev/null | awk '{print $2}')
if [ -z "$min_len" ] || [ "$min_len" -lt 8 ]; then
  RESULT_MSG+="최소 길이 8 미만 (${min_len:-미설정}); "
  ((vuln++))
fi

############################################
# 4. 비밀번호 정책 강도
############################################
policy=$($MYSQL_CMD -e "SHOW VARIABLES LIKE 'validate_password.policy';" 2>/dev/null | awk '{print $2}')
if [[ "$policy" != "MEDIUM" && "$policy" != "1" && "$policy" != "STRONG" && "$policy" != "2" ]]; then
  RESULT_MSG+="비밀번호 정책 수준 낮음 (${policy}); "
  ((vuln++))
fi

############################################
# 5. 비밀번호 사용 기간
############################################
lifetime=$($MYSQL_CMD -e "SHOW VARIABLES LIKE 'default_password_lifetime';" 2>/dev/null | awk '{print $2}')
if [ -z "$lifetime" ] || [ "$lifetime" -eq 0 ]; then
  RESULT_MSG+="암호 사용 기간 미설정; "
  ((vuln++))
fi

############################################
# 6. 암호 재사용 제한
############################################
history=$($MYSQL_CMD -e "SHOW VARIABLES LIKE 'password_history';" 2>/dev/null | awk '{print $2}')
reuse=$($MYSQL_CMD -e "SHOW VARIABLES LIKE 'password_reuse_interval';" 2>/dev/null | awk '{print $2}')
if [ "${history:-0}" -eq 0 ] && [ "${reuse:-0}" -eq 0 ]; then
  RESULT_MSG+="암호 재사용 제한 없음; "
  ((vuln++))
fi

############################################
# 최종 판정
############################################
if [ "$vuln" -gt 0 ]; then
  STATUS="취약"
else
  RESULT_MSG="기관 정책에 맞는 비밀번호 정책 설정됨"
fi

fi

############################################
# 결과 출력 (필수 형식)
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
