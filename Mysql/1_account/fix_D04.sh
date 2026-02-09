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

#!/bin/bash

ID="D-04"
CATEGORY="계정관리"
TITLE="데이터베이스 관리자 권한을 꼭 필요한 계정 및 그룹에 대해서만 허용"
IMPORTANCE="상"

ACTION_TYPE="auto"
ACTION_RESULT="SUCCESS"
CURRENT_STATUS="PASS"
EVIDENCE=""
ACTION_LOG="관리자 권한(SUPER 등) 보유 계정 점검 및 불필요 권한 회수 시도"

NOW=$(date '+%Y-%m-%d %H:%M:%S')

DB_USER="${DB_USER:-root}"
DB_PASSWORD="${DB_PASSWORD:-}"
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-3306}"

MYSQL="mysql -h ${DB_HOST} -P ${DB_PORT} -u ${DB_USER} -p${DB_PASSWORD} -N -B 2>/dev/null"

############################################
# 1. MySQL 접속 확인
############################################
$MYSQL -e "SELECT 1;" >/dev/null 2>&1 || {
  CURRENT_STATUS="점검불가"
  ACTION_RESULT="ERROR"
  EVIDENCE="MySQL 접속 실패"
}

if [ "$CURRENT_STATUS" != "점검불가" ]; then

  ############################################
  # 2. SUPER 권한 보유 계정 조회
  ############################################
  ADMIN_ACCOUNTS=$($MYSQL -e "
  SELECT GRANTEE 
  FROM INFORMATION_SCHEMA.USER_PRIVILEGES 
  WHERE PRIVILEGE_TYPE='SUPER';
  " | tr -d "'")

  ############################################
  # 3. 허용 관리자 계정 목록 (기관 정책 기준)
  ############################################
  ALLOWED_ADMINS="root@localhost root@127.0.0.1 root@::1"

  UNAUTHORIZED=""

  for acc in $ADMIN_ACCOUNTS; do
      echo "$ALLOWED_ADMINS" | grep -qw "$acc"
      if [ $? -ne 0 ]; then
          UNAUTHORIZED="$UNAUTHORIZED $acc"

          # SUPER 권한 회수 시도
          USERNAME=$(echo $acc | cut -d@ -f1)
          HOSTNAME=$(echo $acc | cut -d@ -f2)
          $MYSQL -e "REVOKE SUPER ON *.* FROM '$USERNAME'@'$HOSTNAME';" >/dev/null 2>&1 || true
      fi
  done

  $MYSQL -e "FLUSH PRIVILEGES;" >/dev/null 2>&1

  ############################################
  # 4. 재확인
  ############################################
  REMAINING=$($MYSQL -e "
  SELECT GRANTEE 
  FROM INFORMATION_SCHEMA.USER_PRIVILEGES 
  WHERE PRIVILEGE_TYPE='SUPER';
  " | tr -d "'")

  ############################################
  # 5. 판단 기준 적용
  ############################################
  if [ -n "$UNAUTHORIZED" ]; then
      CURRENT_STATUS="FAIL"
      ACTION_RESULT="PARTIAL"
      EVIDENCE="불필요 관리자 권한 계정 존재: $UNAUTHORIZED"
  else
      CURRENT_STATUS="PASS"
      ACTION_RESULT="SUCCESS"
      EVIDENCE="관리자 권한이 필요한 계정에만 부여됨"
  fi
fi

############################################
# JSON 출력
############################################
cat <<EOF
{
  "check_id": "$ID",
  "category": "$CATEGORY",
  "title": "$TITLE",
  "importance": "$IMPORTANCE",
  "status": "$CURRENT_STATUS",
  "evidence": "$EVIDENCE",
  "guide": "SELECT GRANTEE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE PRIVILEGE_TYPE='SUPER'; 불필요 계정은 REVOKE SUPER ON *.* FROM 'user'@'host';",
  "action_type": "$ACTION_TYPE",
  "action_result": "$ACTION_RESULT",
  "action_log": "$ACTION_LOG",
  "action_date": "$NOW",
  "check_date": "$NOW"
}
EOF
