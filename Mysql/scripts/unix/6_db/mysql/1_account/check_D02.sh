#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-11
# ============================================================================
# [점검 항목 상세]
# @ID          : D-02
# @Category    : 계정 관리
# @Platform    : MySQL
# @Severity    : 상
# @Title       : 데이터베이스의 불필요 계정 제거 또는 잠금 설정
# @Description : DB 운용에 사용하지 않는 불필요 계정 존재 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-02"
STATUS="FAIL"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="mysql.user(table)"

# 실행 안정성: DB 응답 지연 시 무한 대기를 막기 위한 timeout/접속 옵션
TIMEOUT_BIN="$(command -v timeout 2>/dev/null || true)"
MYSQL_TIMEOUT=5
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"
export MYSQL_PWD="${MYSQL_PASSWORD}"
MYSQL_CMD="mysql --protocol=TCP -u${MYSQL_USER} -N -s -B -e"

# 점검 제외 대상: DB 엔진 내부 계정(시스템 계정)
SYSTEM_USERS_CSV="'root','mysql.sys','mysql.session','mysql.infoschema','mysqlxsys','mariadb.sys'"

# 오탐 최소화 정책:
# - 기본 모드: 명백한 불필요 계정(데모/테스트/익명)만 취약 판정
# - 기관 계정 기준이 제공된 경우(AUTHORIZED_USERS_CSV): 허용 목록 외 계정도 취약 판정
AUTHORIZED_USERS_CSV="${AUTHORIZED_USERS_CSV:-}"
DEMO_USERS_CSV="${DEMO_USERS_CSV:-scott,pm,adams,clark,test,guest,demo,sample}"

QUERY_PRIMARY="
SELECT user, host, IFNULL(account_locked,'N') AS account_locked
FROM mysql.user
WHERE user NOT IN (${SYSTEM_USERS_CSV});
"

QUERY_FALLBACK="
SELECT user, host, 'N' AS account_locked
FROM mysql.user
WHERE user NOT IN (${SYSTEM_USERS_CSV});
"

run_mysql_query() {
    local query="$1"
    if [[ -n "$TIMEOUT_BIN" ]]; then
        $TIMEOUT_BIN "${MYSQL_TIMEOUT}s" $MYSQL_CMD "$query" 2>/dev/null || echo "ERROR_TIMEOUT"
    else
        $MYSQL_CMD "$query" 2>/dev/null || echo "ERROR"
    fi
}

in_csv() {
    local needle="$1"
    local csv="$2"
    IFS=',' read -r -a arr <<< "$csv"
    for item in "${arr[@]}"; do
        [[ "$needle" == "$item" ]] && return 0
    done
    return 1
}

RESULT="$(run_mysql_query "$QUERY_PRIMARY")"
QUERY_MODE="PRIMARY"
if [[ "$RESULT" == "ERROR" ]]; then
    RESULT="$(run_mysql_query "$QUERY_FALLBACK")"
    QUERY_MODE="FALLBACK"
fi

REASON_LINE=""
DETAIL_CONTENT=""

if [[ "$RESULT" == "ERROR_TIMEOUT" ]]; then
    STATUS="FAIL"
    REASON_LINE="MySQL 계정 목록을 조회하는 과정이 제한 시간(${MYSQL_TIMEOUT}초)을 초과하여 진단에 실패했습니다. DB 응답 지연 또는 접속 설정을 확인해야 합니다."
    DETAIL_CONTENT="result=ERROR_TIMEOUT"
elif [[ "$RESULT" == "ERROR" ]]; then
    STATUS="FAIL"
    REASON_LINE="MySQL 접속에 실패하여 계정 잠금 상태를 확인할 수 없습니다. 진단 계정 권한 또는 접속 정보를 점검해야 합니다."
    DETAIL_CONTENT="result=ERROR"
else
    VULN_COUNT=0
    SAMPLE="N/A"
    REASON=""

    while IFS=$'\t' read -r user host locked; do
        [[ -z "$user" && -z "$host" ]] && continue
        [[ "$locked" == "Y" ]] && continue

        # 익명 계정은 대표적인 불필요 계정
        if [[ -z "$user" ]]; then
            VULN_COUNT=$((VULN_COUNT + 1))
            [[ "$SAMPLE" == "N/A" ]] && SAMPLE="anonymous@${host}"
            [[ -z "$REASON" ]] && REASON="익명 계정 잠금/삭제 미적용"
            continue
        fi

        # 데모/테스트 계정명은 불필요 계정으로 간주
        if in_csv "$user" "$DEMO_USERS_CSV"; then
            VULN_COUNT=$((VULN_COUNT + 1))
            [[ "$SAMPLE" == "N/A" ]] && SAMPLE="${user}@${host}"
            [[ -z "$REASON" ]] && REASON="데모/테스트 계정(${user}) 활성 상태"
            continue
        fi

        # 기관 승인 계정 목록이 주어진 경우: 목록 외 계정은 취약
        if [[ -n "$AUTHORIZED_USERS_CSV" ]] && ! in_csv "$user" "$AUTHORIZED_USERS_CSV"; then
            VULN_COUNT=$((VULN_COUNT + 1))
            [[ "$SAMPLE" == "N/A" ]] && SAMPLE="${user}@${host}"
            [[ -z "$REASON" ]] && REASON="기관 허용 목록 외 계정 활성 상태"
            continue
        fi
    done <<< "$RESULT"

    if [[ "$VULN_COUNT" -eq 0 ]]; then
        STATUS="PASS"
        if [[ -n "$AUTHORIZED_USERS_CSV" ]]; then
            REASON_LINE="D-02 양호: 허용 계정 목록 기준으로 불필요 계정이 확인되지 않았습니다."
        elif [[ "$QUERY_MODE" == "FALLBACK" ]]; then
            REASON_LINE="D-02 양호(구버전 호환 점검): 명백한 불필요 계정(익명/데모/테스트) 활성 상태가 확인되지 않았습니다."
        else
            REASON_LINE="D-02 양호: 명백한 불필요 계정(익명/데모/테스트) 활성 상태가 확인되지 않았습니다."
        fi
        DETAIL_CONTENT="vuln_count=0"
    else
        STATUS="FAIL"
        REASON_LINE="D-02 취약: 불필요 계정으로 판단되는 활성 계정이 확인되었습니다."
        DETAIL_CONTENT="vuln_count=${VULN_COUNT}, reason=${REASON}, sample=${SAMPLE}"
    fi
fi

CHECK_COMMAND="$MYSQL_CMD \"$QUERY_PRIMARY\" (fallback: \"$QUERY_FALLBACK\")"

RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/"/\\"/g' \
  | sed ':a;N;$!ba;s/\n/\\n/g')

echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF
