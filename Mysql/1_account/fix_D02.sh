#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-07
# ============================================================================
# [점검 항목 상세]
# @ID          : D-02
# @Category    : DBMS (Database Management System)
# @Platform    : MySQL 8.0.44
# @IMPORTANCE  : 상
# @Title       : 데이터베이스의 불필요 계정 제거 또는 잠금 설정
# @Description : DB 운용에 사용하지 않는 불필요 계정 존재 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash

ID="D-02"
CATEGORY="계정관리"
TITLE="데이터베이스의 불필요 계정을 제거하거나, 잠금설정 후 사용"
IMPORTANCE="상"

ACTION_TYPE="manual"
ACTION_RESULT="GUIDE"
CURRENT_STATUS="PASS"
EVIDENCE=""
ACTION_LOG=""

NOW=$(date '+%Y-%m-%d %H:%M:%S')

MYSQL_CMD="mysql -uroot -N -B 2>/dev/null"

############################################
# 1. MySQL 접속 확인
############################################
$MYSQL_CMD -e "SELECT 1;" >/dev/null 2>&1 || {
    CURRENT_STATUS="점검불가"
    EVIDENCE="MySQL 접속 실패"
    ACTION_LOG="DB 접속 불가로 계정 점검 불가"
}

if [ "$CURRENT_STATUS" != "점검불가" ]; then

############################################
# 2. 기본 시스템 계정 제외 목록 정의
############################################
SYSTEM_ACCOUNTS="'root','mysql.sys','mysql.session','mysql.infoschema'"

############################################
# 3. 불필요 가능 계정 탐색
############################################
UNUSED_USERS=$($MYSQL_CMD -e "
SELECT user, host 
FROM mysql.user 
WHERE user NOT IN ($SYSTEM_ACCOUNTS)
AND (
      user LIKE '%test%' OR
      user LIKE '%guest%' OR
      user LIKE '%temp%' OR
      user='' OR
      account_locked='Y'
);
")

############################################
# 4. 판단
############################################
if [ -n "$UNUSED_USERS" ]; then
    CURRENT_STATUS="FAIL"
    EVIDENCE="불필요/테스트/잠금 계정 존재: $UNUSED_USERS"
    ACTION_LOG="미사용 또는 불필요 계정 발견"
else
    CURRENT_STATUS="PASS"
    EVIDENCE="불필요 계정 없음"
    ACTION_LOG="계정 관리 상태 양호"
fi
fi

############################################
# 5. 조치 가이드
############################################
GUIDE_TEXT="불필요 계정 확인 후 삭제:
1) 계정 목록 확인: SELECT user, host FROM mysql.user;
2) 삭제 수행:
   DROP USER '계정명'@'호스트';
3) 적용:
   FLUSH PRIVILEGES;"

############################################
# 6. JSON 출력
############################################
cat <<EOF
{
  "check_id": "$ID",
  "category": "$CATEGORY",
  "title": "$TITLE",
  "importance": "$IMPORTANCE",
  "status": "$CURRENT_STATUS",
  "evidence": "$EVIDENCE",
  "guide": "$GUIDE_TEXT",
  "action_type": "$ACTION_TYPE",
  "action_result": "$ACTION_RESULT",
  "action_log": "$ACTION_LOG",
  "action_date": "$NOW",
  "check_date": "$NOW"
}
EOF
