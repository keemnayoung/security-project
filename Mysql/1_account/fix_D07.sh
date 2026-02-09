#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-07
# ============================================================================
# [점검 항목 상세]
# @ID          : D-07
# @Category    : DBMS (Database Management System)
# @Platform    : MySQL 8.0.44
# @IMPORTANCE  : 중
# @Title       : root 권한으로 서비스 구동 제한
# @Description : DBMS 서비스가 root 권한이 아닌 전용 계정으로 실행되는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash

ID="D-07"
CATEGORY="계정관리"
TITLE="root 권한으로 서비스 구동 제한"
IMPORTANCE="중"

ACTION_TYPE="auto"
ACTION_RESULT="COMPLETED"
CURRENT_STATUS="PASS"
EVIDENCE="N/A"
ACTION_LOG=""

NOW=$(date '+%Y-%m-%d %H:%M:%S')

MYSQL_USER_EXPECTED="mysql"
MYCNF_PATH="/etc/my.cnf"

############################################
# 1. 실행 중인 mysqld 프로세스 계정 확인
############################################
PROC_USER=$(ps -eo user,comm | grep mysqld | grep -v grep | awk '{print $1}' | head -n1)

############################################
# 2. 설정 파일 내 user 지시자 확인
############################################
CONF_USER=$(grep -i "^[[:space:]]*user" $MYCNF_PATH 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')

############################################
# 3. 판단 로직
############################################
if [ "$PROC_USER" = "root" ]; then
    CURRENT_STATUS="FAIL"
    EVIDENCE="mysqld 프로세스가 root 권한으로 실행 중"
    ACTION_LOG="서비스 중지 후 일반 계정으로 변경 시도"

    ############################################
    # 4. 조치 수행
    ############################################
    systemctl stop mysqld 2>/dev/null

    if grep -q "user=" $MYCNF_PATH; then
        sed -i "s/^user=.*/user=$MYSQL_USER_EXPECTED/" $MYCNF_PATH
    else
        echo -e "\n[mysqld]\nuser=$MYSQL_USER_EXPECTED" >> $MYCNF_PATH
    fi

    chown -R mysql:mysql /var/lib/mysql 2>/dev/null
    systemctl start mysqld 2>/dev/null

    ACTION_LOG="$ACTION_LOG → my.cnf user=mysql 설정 후 재시작 수행"

elif [ "$CONF_USER" != "$MYSQL_USER_EXPECTED" ]; then
    CURRENT_STATUS="FAIL"
    EVIDENCE="설정 파일에 user=mysql 미설정"
    ACTION_LOG="설정 파일 수정 필요"

    sed -i "s/^user=.*/user=$MYSQL_USER_EXPECTED/" $MYCNF_PATH 2>/dev/null
    ACTION_LOG="$ACTION_LOG → my.cnf 수정 완료"

else
    CURRENT_STATUS="PASS"
    EVIDENCE="mysqld가 일반 계정(mysql)으로 실행 중"
    ACTION_LOG="보안 정책 준수 상태"
fi

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
  "guide": "mysqld 서비스는 root가 아닌 mysql 계정으로 실행되어야 함. my.cnf의 [mysqld] 섹션에 user=mysql 설정.",
  "action_type": "$ACTION_TYPE",
  "action_result": "$ACTION_RESULT",
  "action_log": "$ACTION_LOG",
  "action_date": "$NOW",
  "check_date": "$NOW"
}
EOF

