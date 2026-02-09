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
# @Severity    : 상
# @Title       : 데이터베이스의 불필요 계정 제거 또는 잠금 설정
# @Description : DB 운용에 사용하지 않는 불필요 계정 존재 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

set -euo pipefail

ITEM_ID="D-02"
CATEGORY="계정관리"
CHECK_ITEM="데이터베이스의 불필요 계정 제거 또는 잠금 설정"
DESCRIPTION="DB 운용에 사용하지 않는 불필요 계정 존재 여부 점검"
IMPORTANCE="상"
CHECKED_AT=$(date -Iseconds)

STATUS="양호"
RESULT_MSG=""
CHECKED=true

DB_USER="${DB_USER:-root}"
DB_PASSWORD="${DB_PASSWORD:-}"
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-3306}"

MYSQL_CMD="mysql -N -B -h${DB_HOST} -P${DB_PORT} -u${DB_USER} -p${DB_PASSWORD}"

########################################
# 1. MySQL 접속 확인
########################################
if ! $MYSQL_CMD -e "SELECT 1;" &>/dev/null; then
    STATUS="점검불가"
    RESULT_MSG="MySQL 접속 실패"
else

    ########################################
    # 2. 계정 목록 조회
    ########################################
    query="
    SELECT user, host, account_locked
    FROM mysql.user
    WHERE user NOT IN ('mysql.sys','mysql.session','mysql.infoschema','root')
    AND user != '';
    "

    accounts=$($MYSQL_CMD -e "$query" 2>/dev/null || true)

    if [ -z "$accounts" ]; then
        STATUS="양호"
        RESULT_MSG="점검 대상 계정 없음"
    else
        vulnerable=0
        msg=""

        while read -r user host locked; do

            # 잠금 계정은 정상
            if [[ "$locked" == "Y" ]]; then
                continue
            fi

            # 외부 접속 허용 계정
            if [[ "$host" == "%" ]]; then
                msg+="[$user@$host 외부접속 가능] "
                ((vulnerable++))
                continue
            fi

            # 테스트/임시 계정 패턴
            if [[ "$user" =~ test|guest|demo|temp|sample|user ]]; then
                msg+="[$user@$host 테스트계정 의심] "
                ((vulnerable++))
                continue
            fi

        done <<< "$accounts"

        if [ "$vulnerable" -gt 0 ]; then
            STATUS="취약"
            RESULT_MSG="$msg"
        else
            STATUS="양호"
            RESULT_MSG="불필요 계정 없음"
        fi
    fi
fi

########################################
# JSON 결과 출력 (필수 형식)
########################################
cat <<EOF
{
  "item_id": "$ITEM_ID",
  "category": "$CATEGORY",
  "check_item": "$CHECK_ITEM",
  "description": "$DESCRIPTION",
  "IMPORTANCE": "$IMPORTANCE",
  "checked_at": "$CHECKED_AT",
  "status": "$STATUS",
  "result": "$RESULT_MSG",
  "checked": $CHECKED
}
EOF
