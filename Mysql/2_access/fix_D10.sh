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

#!/bin/bash

ID="D-10"
CATEGORY="접근통제"
TITLE="원격에서 DB 서버로의 접속 제한"
IMPORTANCE="상"

ACTION_TYPE="manual"
ACTION_RESULT="GUIDE"
CURRENT_STATUS="PASS"
EVIDENCE=""
ACTION_LOG=""

NOW=$(date '+%Y-%m-%d %H:%M:%S')

MYSQL_CMD="mysql -uroot -N -B 2>/dev/null"

############################################
# 허용할 IP (기관 정책에 맞게 수정)
############################################
ALLOWED_IP="192.168.0.100"

############################################
# 1. 전체 허용(%) 계정 확인
############################################
OPEN_USERS=$($MYSQL_CMD -e "
SELECT user,host 
FROM mysql.user
WHERE host='%';
")

COUNT=$(echo "$OPEN_USERS" | grep -v '^$' | wc -l)

############################################
# 2. 판단
############################################
if [ "$COUNT" -gt 0 ]; then
    CURRENT_STATUS="FAIL"
    EVIDENCE="모든 IP(%)에서 접속 가능한 계정 존재"
    ACTION_LOG="접속 IP 제한 필요 계정 발견"
else
    CURRENT_STATUS="PASS"
    EVIDENCE="모든 계정이 특정 IP 또는 localhost로 제한됨"
    ACTION_LOG="IP 접근 제한 정책 적용됨"
fi

############################################
# 3. 수동 조치 가이드 생성
############################################
GUIDE_TEXT="다음 계정들은 host='%' 상태이므로 특정 IP로 변경 필요: "

while read -r USER HOST; do
    if [ -n "$USER" ]; then
        GUIDE_TEXT="$GUIDE_TEXT [$USER@$HOST → $ALLOWED_IP]"
    fi
done <<< "$OPEN_USERS"

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
  "guide": "$GUIDE_TEXT MySQL 접속 후 다음 수행: UPDATE mysql.user SET host='$ALLOWED_IP' WHERE host='%'; FLUSH PRIVILEGES;",
  "action_type": "$ACTION_TYPE",
  "action_result": "$ACTION_RESULT",
  "action_log": "$ACTION_LOG",
  "action_date": "$NOW",
  "check_date": "$NOW"
}
EOF

