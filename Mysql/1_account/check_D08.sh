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
# @Platform    : MySQL
# @IMPORTANCE  : 상
# @Title       : 안전한 암호화 알고리즘 사용
# @Description : SHA-256 이상 기반 인증 암호 알고리즘 사용 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-08"
CATEGORY="DBMS"
TITLE="안전한 암호화 알고리즘 사용"
IMPORTANCE="상"
TARGET_FILE="mysql.user.plugin"

STATUS="FAIL"
EVIDENCE="N/A"

TIMEOUT_BIN="$(command -v timeout 2>/dev/null)"
MYSQL_TIMEOUT=5
MYSQL_CMD="mysql --connect-timeout=${MYSQL_TIMEOUT} --protocol=TCP -uroot -N -s -B -e"

# 사용자 계정의 인증 플러그인 확인
QUERY="
SELECT user, host, plugin
FROM mysql.user
WHERE user NOT IN ('mysql.sys','mysql.session','mysql.infoschema');
"

if [[ -n "$TIMEOUT_BIN" ]]; then
    RESULT=$($TIMEOUT_BIN ${MYSQL_TIMEOUT}s $MYSQL_CMD "$QUERY" 2>/dev/null || echo "ERROR_TIMEOUT")
else
    RESULT=$($MYSQL_CMD "$QUERY" 2>/dev/null || echo "ERROR")
fi

if [[ "$RESULT" == "ERROR_TIMEOUT" ]]; then
    STATUS="FAIL"
    EVIDENCE="계정의 암호화 알고리즘 정보를 조회하는 과정이 제한 시간(${MYSQL_TIMEOUT}초)을 초과하여 진단에 실패했습니다. DB 응답 상태를 확인해야 합니다."
elif [[ "$RESULT" == "ERROR" ]]; then
    STATUS="FAIL"
    EVIDENCE="MySQL 접속 실패로 인해 암호화 알고리즘 사용 여부를 확인할 수 없습니다."
else
    # SHA-256 미만 알고리즘 사용 계정 확인
    WEAK_USERS=$(echo "$RESULT" | awk '$3!="caching_sha2_password"{print $1"@"$2"("$3")"}')

    if [[ -z "$WEAK_USERS" ]]; then
        STATUS="PASS"
        EVIDENCE="모든 DB 계정이 SHA-256 기반의 안전한 암호화 알고리즘을 사용하고 있어, 비밀번호 탈취 및 무차별 대입 공격 위험이 낮습니다."
    else
        COUNT=$(echo "$WEAK_USERS" | wc -l | tr -d ' ')
        SAMPLE=$(echo "$WEAK_USERS" | head -n 1)
        STATUS="FAIL"
        EVIDENCE="SHA-256 미만의 암호화 알고리즘을 사용하는 계정(${COUNT}개)이 존재하여, 비밀번호 유출 및 계정 탈취 위험이 있습니다. (예: ${SAMPLE})"
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
    "guide": "계정의 인증 플러그인을 SHA-256 기반(caching_sha2_password)으로 변경하세요. 예) ALTER USER '계정'@'호스트' IDENTIFIED WITH caching_sha2_password BY '비밀번호';",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF