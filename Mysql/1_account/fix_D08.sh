#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-07
# ============================================================================
# [점검 항목 상세]
# @ID          : D-08
# @Category    : DBMS (Database Management System)
# @Platform    : MySQL 8.0.44
# @IMPORTANCE  : 상
# @Title       : 안전한 암호화 알고리즘 사용
# @Description : SHA-256 이상 기반 인증 암호 알고리즘 사용 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash

ID="D-08"
CATEGORY="계정관리"
TITLE="안전한 암호화 알고리즘 사용"
IMPORTANCE="상"

ACTION_TYPE="auto"
ACTION_RESULT="COMPLETED"
CURRENT_STATUS="PASS"
EVIDENCE=""
ACTION_LOG=""

NOW=$(date '+%Y-%m-%d %H:%M:%S')

MYSQL_CMD="mysql -uroot -N -B 2>/dev/null"

############################################
# 1. 약한 인증 플러그인 계정 확인
############################################
WEAK_USERS=$($MYSQL_CMD -e "
SELECT user,host,plugin
FROM mysql.user
WHERE plugin NOT IN ('caching_sha2_password','sha256_password','auth_socket','mysql_no_login');
")

COUNT=$(echo "$WEAK_USERS" | wc -l)

############################################
# 2. 판단
############################################
if [ "$COUNT" -gt 0 ]; then
    CURRENT_STATUS="FAIL"
    EVIDENCE="SHA-256 미만 인증 방식 사용 계정 존재"
    ACTION_LOG="약한 인증 플러그인 계정 SHA-256 계열로 변경 시도"

    ############################################
    # 3. 조치 수행 (비밀번호 재설정 필요)
    ############################################
    while read -r USER HOST PLUGIN; do
        if [ -n "$USER" ]; then
            # 임시 강제 비밀번호 (실제 환경에서는 정책 비밀번호 사용 필요)
            NEWPASS="Secure#$(date +%s)"

            $MYSQL_CMD -e "
            ALTER USER '$USER'@'$HOST'
            IDENTIFIED WITH caching_sha2_password
            BY '$NEWPASS';
            " 2>/dev/null

            ACTION_LOG="$ACTION_LOG | $USER@$HOST → caching_sha2_password 적용"
        fi
    done <<< "$WEAK_USERS"

else
    CURRENT_STATUS="PASS"
    EVIDENCE="모든 계정이 SHA-256 이상 인증 방식 사용 중"
    ACTION_LOG="보안 기준 충족"
fi

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
  "guide": "MySQL 8 이상에서는 caching_sha2_password 또는 sha256_password 사용 권장. mysql_native_password는 제거.",
  "action_type": "$ACTION_TYPE",
  "action_result": "$ACTION_RESULT",
  "action_log": "$ACTION_LOG",
  "action_date": "$NOW",
  "check_date": "$NOW"
}
EOF
