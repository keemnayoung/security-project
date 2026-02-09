#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-07
# ============================================================================
# [점검 항목 상세]
# @ID          : D-21
# @Category    : DBMS (Database Management System)
# @Platform    : MySQL 8.0.44
# @IMPORTANCE  : 중
# @Title       : 인가되지 않은 GRANT OPTION 사용 제한
# @Description : 일반 사용자에게 GRANT OPTION이 부여되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash

ID="D-21"
CATEGORY="권한관리"
TITLE="인가되지 않은 GRANT OPTION 사용 제한"
IMPORTANCE="상"

ACTION_TYPE="manual"
ACTION_RESULT="GUIDE"
CURRENT_STATUS="PASS"
EVIDENCE=""
ACTION_LOG=""

NOW=$(date '+%Y-%m-%d %H:%M:%S')

MYSQL_CMD="mysql -uroot -N -B 2>/dev/null"

############################################
# 1. 직접 GRANT OPTION 보유 사용자 탐색
############################################
DIRECT_GRANT_USERS=$($MYSQL_CMD -e "
SELECT CONCAT(user,'@',host)
FROM mysql.user
WHERE Grant_priv='Y'
AND user NOT IN ('root','mysql.sys','mysql.session');
")

COUNT=$(echo "$DIRECT_GRANT_USERS" | grep -v '^$' | wc -l)

############################################
# 2. 판단
############################################
if [ "$COUNT" -gt 0 ]; then
    CURRENT_STATUS="FAIL"
    EVIDENCE="ROLE이 아닌 일반 계정에 GRANT OPTION 직접 부여됨"
    ACTION_LOG="직접 부여된 GRANT OPTION 회수 필요"
else
    CURRENT_STATUS="PASS"
    EVIDENCE="GRANT OPTION이 ROLE 기반으로만 관리됨"
    ACTION_LOG="권한 위임 통제 정상"
fi

############################################
# 3. 조치 가이드 작성
############################################
GUIDE_TEXT="다음 계정의 GRANT OPTION 회수 필요: "

while read -r USER; do
    if [ -n "$USER" ]; then
        GUIDE_TEXT="$GUIDE_TEXT [$USER]"
    fi
done <<< "$DIRECT_GRANT_USERS"

GUIDE_TEXT="$GUIDE_TEXT MySQL 접속 후 REVOKE GRANT OPTION ON *.* FROM '<계정>'@'<host>'; FLUSH PRIVILEGES; 이후 ROLE에 권한 위임."

############################################
# 4. JSON 출력
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
