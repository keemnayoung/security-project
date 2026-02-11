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
# @Platform    : MySQL 
# @IMPORTANCE  : 상
# @Title       : 주기적 보안 패치 및 벤더 권고 사항 적용
# @Description : 안전한 버전의 데이터베이스를 사용하고 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-25"
CATEGORY="DBMS"
TITLE="주기적 보안 패치 및 벤더 권고 사항 적용"
IMPORTANCE="상"
TARGET_FILE="mysql_binary"

STATUS="FAIL"
EVIDENCE="N/A"

TIMEOUT_BIN="$(command -v timeout 2>/dev/null)"
MYSQL_TIMEOUT=5
MYSQL_CMD="mysql --connect-timeout=${MYSQL_TIMEOUT} --protocol=TCP -uroot -N -s -B -e"

# MySQL 버전 확인
QUERY="SELECT VERSION();"

if [[ -n "$TIMEOUT_BIN" ]]; then
    VERSION_RAW=$($TIMEOUT_BIN ${MYSQL_TIMEOUT}s $MYSQL_CMD "$QUERY" 2>/dev/null || echo "ERROR_TIMEOUT")
else
    VERSION_RAW=$($MYSQL_CMD "$QUERY" 2>/dev/null || echo "ERROR")
fi

if [[ "$VERSION_RAW" == "ERROR_TIMEOUT" ]]; then
    STATUS="FAIL"
    EVIDENCE="DB 버전 정보를 조회하는 과정이 제한 시간(${MYSQL_TIMEOUT}초)을 초과하여 진단에 실패했습니다. DB 응답 상태를 확인해야 합니다."
elif [[ "$VERSION_RAW" == "ERROR" || -z "$VERSION_RAW" ]]; then
    STATUS="FAIL"
    EVIDENCE="MySQL 접속 실패로 인해 DB 버전 정보를 확인할 수 없습니다."
else
    # 버전 파싱 (예: 8.0.32)
    VERSION=$(echo "$VERSION_RAW" | cut -d'-' -f1)
    MAJOR=$(echo "$VERSION" | cut -d'.' -f1)
    MINOR=$(echo "$VERSION" | cut -d'.' -f2)
    PATCH=$(echo "$VERSION" | cut -d'.' -f3)

    # 기준 버전 (기관 정책에 맞게 조정 가능)
    BASE_MAJOR=8
    BASE_MINOR=0
    BASE_PATCH=34

    if [[ "$MAJOR" -lt "$BASE_MAJOR" ]] \
       || [[ "$MAJOR" -eq "$BASE_MAJOR" && "$MINOR" -lt "$BASE_MINOR" ]] \
       || [[ "$MAJOR" -eq "$BASE_MAJOR" && "$MINOR" -eq "$BASE_MINOR" && "$PATCH" -lt "$BASE_PATCH" ]]; then
        STATUS="FAIL"
        EVIDENCE="현재 MySQL 버전(${VERSION})이 보안 패치가 충분히 반영되지 않은 구버전으로 판단되어, 알려진 취약점을 통한 공격에 노출될 위험이 있습니다."
    else
        STATUS="PASS"
        EVIDENCE="현재 MySQL 버전(${VERSION})이 비교적 최신 보안 패치가 적용된 버전으로 확인되어, 알려진 취약점에 대한 위험이 낮습니다."
    fi
fi

# 파일 해시
if command -v mysqld >/dev/null 2>&1; then
    FILE_PATH=$(command -v mysqld)
    FILE_HASH=$(sha256sum "$FILE_PATH" 2>/dev/null | awk '{print $1}')
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
    "guide": "DB 벤더에서 제공하는 최신 보안 패치가 적용된 버전으로 주기적으로 업데이트하고, 패치 적용 전·후 서비스 영향도를 점검하세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
