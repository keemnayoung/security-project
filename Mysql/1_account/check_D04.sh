#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-07
# ============================================================================
# [점검 항목 상세]
# @ID          : D-04
# @Category    : DBMS (Database Management System)
# @Platform    : MySQL 
# @IMPORTANCE  : 상
# @Title       : 데이터베이스 관리자 권한을 꼭 필요한 계정에만 부여
# @Description : 관리자 권한이 필요한 계정 및 그룹에만 관리자 권한을 부여하였는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-04"
CATEGORY="DBMS"
TITLE="관리자 권한 최소 부여"
IMPORTANCE="상"
TARGET_FILE="mysql.user"

STATUS="FAIL"
EVIDENCE="N/A"

TIMEOUT_BIN="$(command -v timeout 2>/dev/null)"
MYSQL_TIMEOUT=5
MYSQL_CMD="mysql --connect-timeout=${MYSQL_TIMEOUT} --protocol=TCP -uroot -N -s -B -e"

# [가이드 대응] D-04는 "관리자 권한을 꼭 필요한 계정에만 부여" 여부를 확인한다.
# 따라서 일반 DML 권한(SELECT/INSERT 등)은 제외하고, 계정/서버 운영에 영향이 큰
# 관리자급 권한만 조회 대상으로 한정한다.
QUERY="
SELECT grantee
FROM information_schema.user_privileges
WHERE privilege_type IN ('SUPER','SYSTEM_USER','CREATE USER','RELOAD','SHUTDOWN','PROCESS')
GROUP BY grantee;
"

if [[ -n "$TIMEOUT_BIN" ]]; then
    RESULT=$($TIMEOUT_BIN ${MYSQL_TIMEOUT}s $MYSQL_CMD "$QUERY" 2>/dev/null || echo "ERROR_TIMEOUT")
else
    RESULT=$($MYSQL_CMD "$QUERY" 2>/dev/null || echo "ERROR")
fi

if [[ "$RESULT" == "ERROR_TIMEOUT" ]]; then
    STATUS="FAIL"
    EVIDENCE="관리자 권한이 부여된 계정 목록을 조회하는 과정이 제한 시간(${MYSQL_TIMEOUT}초)을 초과하여 진단에 실패했습니다. DB 응답 상태를 확인해야 합니다."
elif [[ "$RESULT" == "ERROR" ]]; then
    STATUS="FAIL"
    EVIDENCE="MySQL 접속 실패로 인해 관리자 권한 부여 상태를 확인할 수 없습니다."
else
    # [가이드 해석] root는 관리자 목적의 기본 계정으로 보고 예외 처리한다.
    # root 외 계정에 관리자 권한이 있으면 "최소 권한 원칙 위반 가능성"으로 판정한다.
    NON_ROOT=$(echo "$RESULT" | grep -v "root@" || true)

    if [[ -z "$NON_ROOT" ]]; then
        # 관리자 권한 보유 계정이 root만 존재 -> D-04 요구 충족(PASS)
        STATUS="PASS"
        EVIDENCE="관리자 권한이 필요한 계정에만 권한이 부여되어 있어, 권한 남용으로 인한 계정 탈취 위험이 낮습니다."
    else
        # root 외 관리자 권한 계정이 존재 -> D-04 요구 미충족(FAIL)
        COUNT=$(echo "$NON_ROOT" | wc -l | tr -d ' ')
        SAMPLE=$(echo "$NON_ROOT" | head -n 1 | tr -d "'")
        STATUS="FAIL"
        EVIDENCE="관리자 권한이 필요하지 않은 계정(${COUNT}개)에 관리자 권한이 부여되어 있어, 계정 유출 시 DB 전체가 위험에 노출될 수 있습니다. (예: ${SAMPLE})"
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
    "guide": "관리자 권한이 필요하지 않은 계정에서는 SUPER, SYSTEM_USER 등 관리자 권한을 회수하고, 최소 권한 원칙에 따라 필요한 권한만 부여하세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
