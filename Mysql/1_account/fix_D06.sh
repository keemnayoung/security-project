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

#!/bin/bash

ID="D-06"
CATEGORY="계정관리"
TITLE="DB 사용자 계정을 개별적으로 부여하여 사용"
IMPORTANCE="중"

ACTION_TYPE="auto"
ACTION_RESULT="SUCCESS"
CURRENT_STATUS="PASS"
EVIDENCE=""
ACTION_LOG="공용 계정 탐지 및 제거, 사용자별 계정 분리 정책 적용"

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
  # 2. 공용 계정 의심 목록 (정책 기준)
  ############################################
  SHARED_ACCOUNTS=$($MYSQL -e "
  SELECT user, host FROM mysql.user
  WHERE user IN ('test','admin','user','guest','shared','mysql');
  ")

  ############################################
  # 3. 공용 계정 삭제
  ############################################
  if [ -n "$SHARED_ACCOUNTS" ]; then
      CURRENT_STATUS="FAIL"
      ACTION_RESULT="PARTIAL"
      EVIDENCE="공용 계정 존재: $SHARED_ACCOUNTS"

      while read USER HOST; do
          $MYSQL -e "DROP USER '$USER'@'$HOST';" >/dev/null 2>&1 || true
      done <<< "$SHARED_ACCOUNTS"
  fi

  ############################################
  # 4. 사용자별 계정 생성 가이드 적용 예시
  ############################################
  # 실제 사용자 정보는 기관 정책에 따라 외부 입력 필요
  # 예시 계정 생성
  $MYSQL -e "CREATE USER IF NOT EXISTS 'dev_user'@'%' IDENTIFIED BY 'Dev@1234';" >/dev/null 2>&1
  $MYSQL -e "GRANT SELECT, INSERT ON testdb.* TO 'dev_user'@'%';" >/dev/null 2>&1

  $MYSQL -e "FLUSH PRIVILEGES;" >/dev/null 2>&1

  ############################################
  # 5. 재점검
  ############################################
  REMAIN=$($MYSQL -e "
  SELECT user FROM mysql.user
  WHERE user IN ('test','admin','user','guest','shared','mysql');
  ")

  if [ -z "$REMAIN" ]; then
      CURRENT_STATUS="PASS"
      ACTION_RESULT="SUCCESS"
      EVIDENCE="사용자별 계정 정책 적용 완료"
  fi
fi

############################################
# JSON 결과 출력
############################################
cat <<EOF
{
  "check_id": "$ID",
  "category": "$CATEGORY",
  "title": "$TITLE",
  "importance": "$IMPORTANCE",
  "status": "$CURRENT_STATUS",
  "evidence": "$EVIDENCE",
  "guide": "공용 계정 삭제 후 사용자별 계정 생성 및 최소 권한 부여. DROP USER 'user'@'host'; CREATE USER... GRANT 최소권한;",
  "action_type": "$ACTION_TYPE",
  "action_result": "$ACTION_RESULT",
  "action_log": "$ACTION_LOG",
  "action_date": "$NOW",
  "check_date": "$NOW"
}
EOF

