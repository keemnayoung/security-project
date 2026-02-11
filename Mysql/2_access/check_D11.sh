#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-07
# ============================================================================
# [점검 항목 상세]
# @ID          : D-11
# @Category    : DBMS (Database Management System)
# @Platform    : MySQL
# @Severity    : 상
# @Title       : DBA 이외 사용자의 시스템 테이블 접근 제한
# @Description : mysql 등 시스템 스키마에 일반 사용자가 접근 불가하도록 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-11"
CATEGORY="DBMS"
TITLE="DBA 이외 사용자의 시스템 테이블 접근 제한"
IMPORTANCE="상"
TARGET_FILE="information_schema"

STATUS="FAIL"
EVIDENCE="N/A"
ACTION_LOG="N/A"

TIMEOUT_BIN="$(command -v timeout 2>/dev/null)"
MYSQL_TIMEOUT=5
MYSQL_CMD="mysql --connect-timeout=${MYSQL_TIMEOUT} --protocol=TCP -uroot -N -s -B -e"

# DBA 제외 시스템 DB 접근 계정 조회
QUERY="
SELECT Db, User, Host
FROM mysql.db
WHERE Db IN ('mysql','performance_schema','sys')
  AND User NOT IN ('root','mysql.sys','mysql.session','mysql.infoschema');
"

if [[ -n "$TIMEOUT_BIN" ]]; then
    LIST=$($TIMEOUT_BIN ${MYSQL_TIMEOUT}s $MYSQL_CMD "$QUERY" 2>/dev/null || echo "ERROR_TIMEOUT")
else
    LIST=$($MYSQL_CMD "$QUERY" 2>/dev/null || echo "ERROR")
fi

MODIFIED_COUNT=0

if [[ "$LIST" == "ERROR_TIMEOUT" ]]; then
    STATUS="FAIL"
    EVIDENCE="시스템 테이블 접근 권한을 조회하는 과정이 제한 시간(${MYSQL_TIMEOUT}초)을 초과하여 조치를 수행하지 못했습니다."
    ACTION_LOG="DB 응답 지연으로 인해 시스템 테이블 접근 권한 회수 조치를 수행하지 못했습니다."
elif [[ "$LIST" == "ERROR" ]]; then
    STATUS="FAIL"
    EVIDENCE="MySQL 접속 실패로 인해 시스템 테이블 접근 권한 회수 조치를 수행할 수 없습니다."
    ACTION_LOG="MySQL 접속 실패로 시스템 테이블 접근 권한 회수 조치를 수행하지 못했습니다."
else
    if [[ -z "$LIST" ]]; then
        STATUS="PASS"
        EVIDENCE="일반 사용자에게 시스템 테이블 접근 권한이 부여되어 있지 않아 추가 조치가 필요하지 않습니다."
        ACTION_LOG="시스템 테이블 접근 권한이 DBA 계정으로만 제한되어 있어 별도의 조치를 수행하지 않았습니다."
    else
        while IFS=$'\t' read -r db user host; do
            [[ -z "$user" ]] && continue
            SQL="
REVOKE ALL PRIVILEGES ON ${db}.* FROM '${user}'@'${host}';
"
            if [[ -n "$TIMEOUT_BIN" ]]; then
                $TIMEOUT_BIN ${MYSQL_TIMEOUT}s $MYSQL_CMD "$SQL" >/dev/null 2>&1 && MODIFIED_COUNT=$((MODIFIED_COUNT + 1))
            else
                $MYSQL_CMD "$SQL" >/dev/null 2>&1 && MODIFIED_COUNT=$((MODIFIED_COUNT + 1))
            fi
        done <<< "$LIST"

        if [[ "$MODIFIED_COUNT" -gt 0 ]]; then
            STATUS="PASS"
            EVIDENCE="일반 사용자 계정에서 시스템 테이블 접근 권한을 회수하여, 사용자·권한·시스템 정보 노출 위험을 줄였습니다."
            ACTION_LOG="DBA가 아닌 계정(${MODIFIED_COUNT}개)에서 시스템 테이블 접근 권한을 회수하여 보안 정책을 적용했습니다."
        else
            STATUS="FAIL"
            EVIDENCE="시스템 테이블 접근 권한 회수를 시도했으나 정상적으로 적용되지 않았습니다."
            ACTION_LOG="시스템 테이블 접근 권한 회수 조치를 시도했으나 권한 또는 설정 문제로 완료하지 못했습니다."
        fi
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
    "action_log": "$ACTION_LOG",
    "guide": "시스템 테이블(mysql, performance_schema, sys)은 DBA 계정만 접근 가능하도록 권한을 최소화하고, 일반 사용자 권한은 업무 DB로만 제한하세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
