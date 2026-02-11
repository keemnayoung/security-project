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
# @Platform    : MySQL
# @IMPORTANCE  : 중
# @Title       : 인가되지 않은 GRANT OPTION 사용 제한
# @Description : 일반 사용자에게 GRANT OPTION이 부여되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-21"
CATEGORY="DBMS"
TITLE="인가되지 않은 GRANT OPTION 사용 제한"
IMPORTANCE="중"
TARGET_FILE="mysql.user.grant_priv"

STATUS="FAIL"
EVIDENCE="N/A"

TIMEOUT_BIN="$(command -v timeout 2>/dev/null)"
MYSQL_TIMEOUT=5
MYSQL_CMD="mysql --connect-timeout=${MYSQL_TIMEOUT} --protocol=TCP -uroot -N -s -B -e"

# DBA 계정(root 등) 제외, 직접 GRANT OPTION 보유 계정 조회
QUERY="
SELECT User, Host
FROM mysql.user
WHERE Grant_priv = 'Y'
  AND User NOT IN ('root','mysql.sys','mysql.session','mysql.infoschema');
"

if [[ -n "$TIMEOUT_BIN" ]]; then
    RESULT=$($TIMEOUT_BIN ${MYSQL_TIMEOUT}s $MYSQL_CMD "$QUERY" 2>/dev/null || echo "ERROR_TIMEOUT")
else
    RESULT=$($MYSQL_CMD "$QUERY" 2>/dev/null || echo "ERROR")
fi

if [[ "$RESULT" == "ERROR_TIMEOUT" ]]; then
    STATUS="FAIL"
    EVIDENCE="GRANT OPTION 부여 현황을 조회하는 과정이 제한 시간(${MYSQL_TIMEOUT}초)을 초과하여 진단에 실패했습니다. DB 응답 상태를 확인해야 합니다."
elif [[ "$RESULT" == "ERROR" ]]; then
    STATUS="FAIL"
    EVIDENCE="MySQL 접속 실패로 인해 GRANT OPTION 부여 여부를 확인할 수 없습니다."
else
    if [[ -z "$RESULT" ]]; then
        STATUS="PASS"
        EVIDENCE="일반 사용자에게 GRANT OPTION이 직접 부여되어 있지 않아, 권한이 무분별하게 확산될 위험이 낮습니다."
    else
        COUNT=$(echo "$RESULT" | wc -l | tr -d ' ')
        SAMPLE=$(echo "$RESULT" | awk 'NR==1{print $1"@"$2}')
        STATUS="FAIL"
        EVIDENCE="일반 사용자 계정(${COUNT}개)에 GRANT OPTION이 직접 부여되어 있어, 다른 사용자에게 권한이 확산될 위험이 있습니다. (예: ${SAMPLE})"
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
    "guide": "일반 사용자에게 직접 부여된 GRANT OPTION을 회수하고, 필요한 경우 ROLE을 통해 간접적으로 권한을 부여하세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
