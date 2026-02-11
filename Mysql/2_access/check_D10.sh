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
# @Platform    : MySQL 
# @IMPORTANCE  : 상
# @Title       : 원격에서 DB서버로의 접속 제한
# @Description : 지정된 IP주소만 DB 서버에 접근 가능하도록 설정되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-10"
CATEGORY="DBMS"
TITLE="원격에서 DB 서버로의 접속 제한"
IMPORTANCE="상"
TARGET_FILE="/etc/my.cnf"

STATUS="FAIL"
EVIDENCE="N/A"

TIMEOUT_BIN="$(command -v timeout 2>/dev/null)"
MYSQL_TIMEOUT=5
MYSQL_CMD="mysql --connect-timeout=${MYSQL_TIMEOUT} --protocol=TCP -uroot -N -s -B -e"

# 모든 IP(%)에서 접속 가능한 계정 조회
QUERY="
SELECT user, host
FROM mysql.user
WHERE host = '%'
  AND user NOT IN ('mysql.sys','mysql.session','mysql.infoschema');
"

if [[ -n "$TIMEOUT_BIN" ]]; then
    RESULT=$($TIMEOUT_BIN ${MYSQL_TIMEOUT}s $MYSQL_CMD "$QUERY" 2>/dev/null || echo "ERROR_TIMEOUT")
else
    RESULT=$($MYSQL_CMD "$QUERY" 2>/dev/null || echo "ERROR")
fi

if [[ "$RESULT" == "ERROR_TIMEOUT" ]]; then
    STATUS="FAIL"
    EVIDENCE="DB 계정의 원격 접속 허용 범위를 조회하는 과정이 제한 시간(${MYSQL_TIMEOUT}초)을 초과하여 진단에 실패했습니다. DB 응답 상태를 확인해야 합니다."
elif [[ "$RESULT" == "ERROR" ]]; then
    STATUS="FAIL"
    EVIDENCE="MySQL 접속 실패로 인해 원격 접속 제한 설정 여부를 확인할 수 없습니다."
else
    if [[ -z "$RESULT" ]]; then
        STATUS="PASS"
        EVIDENCE="DB 서버 접속이 지정된 IP에서만 가능하도록 설정되어 있어, 외부 비인가 접근 위험이 낮습니다."
    else
        COUNT=$(echo "$RESULT" | wc -l | tr -d ' ')
        SAMPLE=$(echo "$RESULT" | awk 'NR==1{print $1"@"$2}')
        STATUS="FAIL"
        EVIDENCE="모든 IP에서 접속 가능한 DB 계정(${COUNT}개)이 존재하여, 외부 위치에 관계없이 DB 서버에 접근할 수 있는 위험이 있습니다. (예: ${SAMPLE})"
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
    "guide": "DB 계정의 접속 허용 IP를 필요한 범위로 제한하세요. 예) '계정'@'192.168.1.%' 또는 '계정'@'localhost' 형태로 설정",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF