#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-07
# ============================================================================
# [점검 항목 상세]
# @ID          : D-25
# @Category    : DBMS (Database Management System)
# @Platform    : MySQL 8.0.44
# @IMPORTANCE  : 상
# @Title       : 주기적 보안 패치 및 벤더 권고 사항 적용
# @Description : 안전한 버전의 데이터베이스를 사용하고 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

set -euo pipefail

ITEM_ID="D-25"
CATEGORY="패치관리"
CHECK_ITEM="주기적 보안 패치 및 벤더 권고 사항 적용"
DESCRIPTION="안전한 버전의 데이터베이스를 사용하고 있는지 점검"
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
if ! $MYSQL_CMD -e "SELECT VERSION();" &>/dev/null; then
    STATUS="점검불가"
    RESULT_MSG="MySQL 접속 실패"
else

    ########################################
    # 2. 버전 조회
    ########################################
    version=$($MYSQL_CMD -e "SELECT VERSION();" | head -n1)

    ########################################
    # 3. 메이저 버전 판별
    ########################################
    major=$(echo "$version" | cut -d. -f1)
    minor=$(echo "$version" | cut -d. -f2)

    ########################################
    # 4. 보안 기준 판단
    # 5.7 이하 = 지원 종료 → 취약
    # 8.0 = 지원 중
    ########################################
    if [[ "$major" -lt 8 ]]; then
        STATUS="취약"
        RESULT_MSG="지원 종료 버전 사용 중 (${version})"
    elif [[ "$major" -eq 8 ]]; then
        STATUS="양호"
        RESULT_MSG="지원 중 버전 사용 (${version})"
    else
        STATUS="수동확인"
        RESULT_MSG="알 수 없는 버전 (${version}) — 벤더 공지 확인 필요"
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
