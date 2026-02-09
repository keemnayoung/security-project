#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-07
# ============================================================================
# [점검 항목 상세]
# @ID          : D-01
# @Category    : DBMS (Database Management System)
# @Platform    : MySQL 8.0.44
# @IMPORTANCE  : 상
# @Title       : 비밀번호 사용 기간 및 복잡도 정책 설정
# @Description : 기관 정책에 맞게 비밀번호 사용 기간 및 복잡도 설정이 적용되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash

ID="D-01"
CATEGORY="계정관리"
TITLE="기본 계정의 비밀번호, 정책 등을 변경하여 사용"
IMPORTANCE="상"

ACTION_TYPE="manual"
ACTION_RESULT="GUIDE"
CURRENT_STATUS="PASS"
EVIDENCE=""
ACTION_LOG=""

NOW=$(date '+%Y-%m-%d %H:%M:%S')

MYSQL_CMD="mysql -uroot -N -B 2>/dev/null"

############################################
# 1. root 계정 인증 정보 확인
############################################
AUTH_INFO=$($MYSQL_CMD -e "
SELECT authentication_string, account_locked
FROM mysql.user
WHERE user='root' AND host='localhost';
")

ROOT_PASS=$(echo "$AUTH_INFO" | awk '{print $1}')
ROOT_LOCK=$(echo "$AUTH_INFO" | awk '{print $2}')

############################################
# 2. 판단 기준 적용
############################################
if [ -z "$ROOT_PASS" ] && [ "$ROOT_LOCK" != "Y" ]; then
    CURRENT_STATUS="FAIL"
    ACTION_RESULT="MANUAL_REQUIRED"
    EVIDENCE="root 계정 초기 비밀번호 미변경 및 잠금 미설정"
    ACTION_LOG="초기 비밀번호 대입 공격 위험 존재"
else
    CURRENT_STATUS="PASS"
    ACTION_RESULT="NOT_REQUIRED"
    EVIDENCE="root 계정 비밀번호 변경 또는 계정 잠금 설정 확인"
    ACTION_LOG="기본 계정 보호 정책 적용됨"
fi

############################################
# 3. JSON 출력
############################################
cat <<EOF
{
  "check_id": "$ID",
  "category": "$CATEGORY",
  "title": "$TITLE",
  "importance": "$IMPORTANCE",
  "status": "$CURRENT_STATUS",
  "evidence": "$EVIDENCE",
  "guide": "MySQL 접속 후 수행: ALTER USER 'root'@'localhost' IDENTIFIED BY '강력한비밀번호'; 또는 ALTER USER 'root'@'localhost' ACCOUNT LOCK; FLUSH PRIVILEGES;",
  "action_type": "$ACTION_TYPE",
  "action_result": "$ACTION_RESULT",
  "action_log": "$ACTION_LOG",
  "action_date": "$NOW",
  "check_date": "$NOW"
}
EOF
