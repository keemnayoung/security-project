#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 8.0.44
# @Author: 한은결
# @Last Updated: 2026-02-07
# ============================================================================
# [점검 항목 상세]
# @ID          : D-06
# @Category    : DBMS (Database Management System)
# @Platform    : MySQL 
# @IMPORTANCE  : 중
# @Title       : DB 사용자 계정을 개별적으로 부여하여 사용
# @Description : DB 접근 시 사용자별로 서로 다른 계정을 사용하여 접근하는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-06"
CATEGORY="DBMS"
TITLE="DB 사용자 계정을 개별적으로 부여하여 사용"
IMPORTANCE="중"
TARGET_FILE="mysql.user"

STATUS="FAIL"
EVIDENCE="N/A"

TIMEOUT_BIN="$(command -v timeout 2>/dev/null)"
MYSQL_TIMEOUT=5
MYSQL_CMD="mysql --connect-timeout=${MYSQL_TIMEOUT} --protocol=TCP -uroot -N -s -B -e"

# 공용 계정으로 간주할 수 있는 계정명 패턴
QUERY="
SELECT user, COUNT(DISTINCT host) AS host_count
FROM mysql.user
WHERE user NOT IN ('mysql.sys','mysql.session','mysql.infoschema')
GROUP BY user
HAVING user IN ('root','admin','dba','test','guest','user')
   OR host_count > 1;
"

if [[ -n "$TIMEOUT_BIN" ]]; then
    RESULT=$($TIMEOUT_BIN ${MYSQL_TIMEOUT}s $MYSQL_CMD "$QUERY" 2>/dev/null || echo "ERROR_TIMEOUT")
else
    RESULT=$($MYSQL_CMD "$QUERY" 2>/dev/null || echo "ERROR")
fi

if [[ "$RESULT" == "ERROR_TIMEOUT" ]]; then
    STATUS="FAIL"
    EVIDENCE="DB 사용자 계정 목록을 조회하는 과정이 제한 시간(${MYSQL_TIMEOUT}초)을 초과하여 진단에 실패했습니다. DB 응답 상태를 확인해야 합니다."
elif [[ "$RESULT" == "ERROR" ]]; then
    STATUS="FAIL"
    EVIDENCE="MySQL 접속 실패로 인해 사용자 계정의 개별 사용 여부를 확인할 수 없습니다."
else
    if [[ -z "$RESULT" ]]; then
        STATUS="PASS"
        EVIDENCE="DB 접근 시 사용자별로 구분된 계정을 사용하고 있어, 계정 공유로 인한 로그 추적 및 감사의 어려움이 발생하지 않는 상태입니다."
    else
        COUNT=$(echo "$RESULT" | wc -l | tr -d ' ')
        SAMPLE=$(echo "$RESULT" | awk 'NR==1{print $1}')
        STATUS="FAIL"
        EVIDENCE="여러 사용자가 공유했을 가능성이 있는 공용 DB 계정(${COUNT}개)이 존재하여, 계정 사용 이력 추적 및 감사에 어려움이 발생할 수 있습니다. (예: ${SAMPLE})"
    fi
fi

# 파일 해시
if [ -f "$TARGET_FILE" ]; then
    FILE_HASH=$(sha256sum "$TARGET_FILE" 2>/dev/null | awk '{print $1}')
    [[ -z "$FILE_HASH" ]] && FILE_HASH="HASH_ERROR"
else
    FILE_HASH="NOT_FOUND"
fi

cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "DB 접근 시 사용자별로 구분된 계정을 생성하여 사용하고, 공용 계정 사용은 최소화하거나 중지하세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
