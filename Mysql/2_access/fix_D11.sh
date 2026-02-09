#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-07
# ============================================================================
# [점검 항목 상세]
# @ID          : D-11
# @Category    : DBMS (Database Management System)
# @Platform    : MySQL 8.0.44
# @IMPORTANCE  : 상
# @Title       : DBA 이외 사용자의 시스템 테이블 접근 제한
# @Description : mysql 등 시스템 스키마에 일반 사용자가 접근 불가하도록 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash

ID="D-11"
CATEGORY="접근통제"
TITLE="DBA 이외의 인가되지 않은 사용자가 시스템 테이블에 접근할 수 없도록 설정"
IMPORTANCE="상"

ACTION_TYPE="manual"
ACTION_RESULT="GUIDE"
CURRENT_STATUS="PASS"
EVIDENCE=""
ACTION_LOG=""

NOW=$(date '+%Y-%m-%d %H:%M:%S')

MYSQL_CMD="mysql -uroot -N -B 2>/dev/null"

############################################
# 1. 시스템 DB 정의
############################################
SYSTEM_DBS="'mysql','information_schema','performance_schema','sys'"

############################################
# 2. 일반 사용자 계정 중 시스템 DB 권한 보유자 탐색
############################################
RISK_USERS=$($MYSQL_CMD -e "
SELECT DISTINCT GRANTEE
FROM information_schema.SCHEMA_PRIVILEGES
WHERE TABLE_SCHEMA IN ($SYSTEM_DBS)
AND GRANTEE NOT LIKE \"'root'%\"
AND GRANTEE NOT LIKE \"'mysql.sys'%\"
AND GRANTEE NOT LIKE \"'mysql.session'%\";
")

COUNT=$(echo "$RISK_USERS" | grep -v '^$' | wc -l)

############################################
# 3. 판단
############################################
if [ "$COUNT" -gt 0 ]; then
    CURRENT_STATUS="FAIL"
    EVIDENCE="일반 계정에 시스템 DB 접근 권한 존재"
    ACTION_LOG="시스템 테이블 접근 권한 회수 필요"
else
    CURRENT_STATUS="PASS"
    EVIDENCE="DBA 계정만 시스템 DB 접근 가능"
    ACTION_LOG="시스템 테이블 접근 통제 정상"
fi

############################################
# 4. 조치 가이드 작성
############################################
GUIDE_TEXT="다음 계정의 시스템 DB 권한 회수 필요: "

while read -r USER; do
    if [ -n "$USER" ]; then
        CLEAN_USER=$(echo $USER | sed "s/'//g")
        GUIDE_TEXT="$GUIDE_TEXT [$CLEAN_USER]"
    fi
done <<< "$RISK_USERS"

GUIDE_TEXT="$GUIDE_TEXT MySQL 접속 후 필요 DB 외 권한 제거 예: REVOKE ALL PRIVILEGES ON mysql.* FROM '<계정>'@'<host>'; FLUSH PRIVILEGES;"

############################################
# 5. JSON 출력
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

