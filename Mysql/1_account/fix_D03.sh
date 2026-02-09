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

#!/bin/bash

ID="D-03"
CATEGORY="계정관리"
TITLE="비밀번호 사용 기간 및 복잡도를 기관의 정책에 맞도록 설정"
IMPORTANCE="중"

ACTION_TYPE="auto"
ACTION_RESULT="SUCCESS"
CURRENT_STATUS="PASS"
EVIDENCE=""
ACTION_LOG="기관 정책 기준으로 비밀번호 정책 자동 설정 시도"

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
  # 2. validate_password 컴포넌트 설치 확인
  ############################################
  COMPONENT=$($MYSQL -e "SELECT COUNT(*) FROM mysql.component WHERE component_urn LIKE '%validate_password%';" || echo 0)

  if [ "$COMPONENT" -eq 0 ]; then
    $MYSQL -e "INSTALL COMPONENT 'file://component_validate_password';" >/dev/null 2>&1 || true
  fi

  ############################################
  # 3. 기관 정책 기준 자동 설정
  ############################################
  $MYSQL -e "SET PERSIST validate_password.policy = MEDIUM;" >/dev/null 2>&1
  $MYSQL -e "SET PERSIST validate_password.length = 8;" >/dev/null 2>&1
  $MYSQL -e "SET PERSIST validate_password.mixed_case_count = 1;" >/dev/null 2>&1
  $MYSQL -e "SET PERSIST validate_password.number_count = 1;" >/dev/null 2>&1
  $MYSQL -e "SET PERSIST validate_password.special_char_count = 1;" >/dev/null 2>&1
  $MYSQL -e "SET PERSIST default_password_lifetime = 90;" >/dev/null 2>&1

  ############################################
  # 4. 적용 여부 확인
  ############################################
  LENGTH=$($MYSQL -e "SHOW VARIABLES LIKE 'validate_password.length';" | awk '{print $2}')
  POLICY=$($MYSQL -e "SHOW VARIABLES LIKE 'validate_password.policy';" | awk '{print $2}')
  MIXED=$($MYSQL -e "SHOW VARIABLES LIKE 'validate_password.mixed_case_count';" | awk '{print $2}')
  NUMBER=$($MYSQL -e "SHOW VARIABLES LIKE 'validate_password.number_count';" | awk '{print $2}')
  SPECIAL=$($MYSQL -e "SHOW VARIABLES LIKE 'validate_password.special_char_count';" | awk '{print $2}')
  LIFETIME=$($MYSQL -e "SHOW VARIABLES LIKE 'default_password_lifetime';" | awk '{print $2}')

  ############################################
  # 5. 판단 기준
  ############################################
  if [ "${LENGTH:-0}" -ge 8 ] && \
     [ "$POLICY" != "LOW" ] && \
     [ "${MIXED:-0}" -ge 1 ] && \
     [ "${NUMBER:-0}" -ge 1 ] && \
     [ "${SPECIAL:-0}" -ge 1 ] && \
     [ "${LIFETIME:-0}" -ge 90 ]; then

      CURRENT_STATUS="PASS"
      EVIDENCE="복잡도(length=$LENGTH, policy=$POLICY) 및 사용기간($LIFETIME일) 정책 적용 확인"
      ACTION_RESULT="SUCCESS"
  else
      CURRENT_STATUS="FAIL"
      EVIDENCE="일부 비밀번호 정책 미적용"
      ACTION_RESULT="PARTIAL"
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
  "guide": "SET GLOBAL validate_password.policy='MEDIUM'; length=8; mixed_case=1; number=1; special_char=1; SET GLOBAL default_password_lifetime=90;",
  "action_type": "$ACTION_TYPE",
  "action_result": "$ACTION_RESULT",
  "action_log": "$ACTION_LOG",
  "action_date": "$NOW",
  "check_date": "$NOW"
}
EOF
