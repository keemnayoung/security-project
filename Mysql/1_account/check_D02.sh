#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-11
# ============================================================================
# [점검 항목 상세]
# @ID          : D-02
# @Category    : DBMS (Database Management System)
# @Platform    : MySQL
# @Severity    : 상
# @Title       : 데이터베이스의 불필요 계정 제거 또는 잠금 설정
# @Description : DB 운용에 사용하지 않는 불필요 계정 존재 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-02"
CATEGORY="DBMS"
TITLE="불필요한 계정 제거 또는 잠금 설정"
IMPORTANCE="상"
TARGET_FILE="mysql.user(table)"

# 기본 결과값: 점검 전 FAIL, 양호 조건 충족 시 PASS로 변경
STATUS="FAIL"
EVIDENCE="N/A"

# 실행 안정성: DB 응답 지연 시 무한 대기를 막기 위한 timeout/접속 옵션
TIMEOUT_BIN="$(command -v timeout 2>/dev/null)"
MYSQL_TIMEOUT=5
MYSQL_CMD="mysql --connect-timeout=${MYSQL_TIMEOUT} --protocol=TCP -uroot -N -s -B -e"

# 점검 제외 대상: DB 엔진 내부 계정(시스템 계정)
SYSTEM_USERS_CSV="'root','mysql.sys','mysql.session','mysql.infoschema','mysqlxsys','mariadb.sys'"

# [가이드 7p 대응] 잠금되지 않은 "시스템 외 계정" 조회 = 불필요 계정 후보
QUERY_PRIMARY="
SELECT user, host
FROM mysql.user
WHERE user NOT IN (${SYSTEM_USERS_CSV})
  AND IFNULL(account_locked,'N') != 'Y';
"

# 구버전 호환: account_locked 미지원 환경에서는 시스템 외 계정 존재 여부로 판정
QUERY_FALLBACK="
SELECT user, host
FROM mysql.user
WHERE user NOT IN (${SYSTEM_USERS_CSV});
"

# 공통 실행 함수: timeout 적용 + 오류 토큰(ERROR/ERROR_TIMEOUT) 표준화
run_mysql_query() {
    local query="$1"
    if [[ -n "$TIMEOUT_BIN" ]]; then
        $TIMEOUT_BIN "${MYSQL_TIMEOUT}s" $MYSQL_CMD "$query" 2>/dev/null || echo "ERROR_TIMEOUT"
    else
        $MYSQL_CMD "$query" 2>/dev/null || echo "ERROR"
    fi
}

# 1차 조회 실패 시 2차(구버전 호환) 조회로 재시도
RESULT="$(run_mysql_query "$QUERY_PRIMARY")"
QUERY_MODE="PRIMARY"
if [[ "$RESULT" == "ERROR" ]]; then
    RESULT="$(run_mysql_query "$QUERY_FALLBACK")"
    QUERY_MODE="FALLBACK"
fi

# 점검 불가 상황(시간초과/접속실패) 처리
if [[ "$RESULT" == "ERROR_TIMEOUT" ]]; then
    STATUS="FAIL"
    EVIDENCE="MySQL 계정 목록을 조회하는 과정이 제한 시간(${MYSQL_TIMEOUT}초)을 초과하여 진단에 실패했습니다. DB 응답 지연 또는 접속 설정을 확인해야 합니다."
elif [[ "$RESULT" == "ERROR" ]]; then
    STATUS="FAIL"
    EVIDENCE="MySQL 접속에 실패하여 계정 잠금 상태를 확인할 수 없습니다. 진단 계정 권한 또는 접속 정보를 점검해야 합니다."
else
    # [가이드 7p 대응] 시스템 외 계정이 없거나 잠금 처리되어 있으면 양호
    if [[ -z "$RESULT" ]]; then
        STATUS="PASS"
        EVIDENCE="D-02 양호: 시스템 계정 외 추가 계정이 없거나 잠금 처리되어 불필요 계정 위험이 낮습니다."
    else
        # [가이드 7p 대응] 시스템 외 계정 존재 시 취약(삭제/잠금 필요)
        COUNT=$(echo "$RESULT" | wc -l | tr -d ' ')
        SAMPLE=$(echo "$RESULT" | awk 'NR==1{print $1"@"$2}')
        STATUS="FAIL"
        if [[ "$QUERY_MODE" == "FALLBACK" ]]; then
            EVIDENCE="D-02 취약(구버전 호환 점검): 시스템 계정 외 추가 계정(${COUNT}개)이 존재합니다. account_locked 미지원 환경이므로 계정 사용 목적을 확인해 불필요 계정 삭제가 필요합니다. (예: ${SAMPLE})"
        else
            EVIDENCE="D-02 취약: 잠금되지 않은 시스템 외 계정(${COUNT}개)이 존재합니다. 불필요 계정은 삭제 또는 잠금이 필요합니다. (예: ${SAMPLE})"
        fi
    fi
fi

# 시스템 테이블 점검이므로 파일 해시는 N/A 처리
FILE_HASH="N/A(TABLE_CHECK)"

# 표준 JSON 결과 출력 (수집 파이프라인 연계 포맷)
cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "계정 목록 점검 후 불필요 계정은 삭제 또는 잠금하세요. 예) 삭제: DROP USER '계정'@'호스트'; 잠금: ALTER USER '계정'@'호스트' ACCOUNT LOCK;",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
