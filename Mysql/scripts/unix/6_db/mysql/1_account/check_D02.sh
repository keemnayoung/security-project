#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.1
# @Author: 한은결
# @Last Updated: 2026-02-16
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

TIMEOUT_BIN="$(command -v timeout 2>/dev/null || true)"
MYSQL_TIMEOUT=5
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"
export MYSQL_PWD="${MYSQL_PASSWORD}"
MYSQL_CMD="mysql --protocol=TCP -u${MYSQL_USER} -N -s -B -e"

SYSTEM_USERS_CSV="'root','mysql.sys','mysql.session','mysql.infoschema','mysqlxsys','mariadb.sys'"

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
    REASON_LINE="MySQL 계정 목록을 조회하는 과정이 제한 시간(${MYSQL_TIMEOUT}초)을 초과하여 진단에 실패했습니다. DB 응답 지연 또는 접속 설정을 확인해주시기 바랍니다.\n조치 방법은 DB 상태/부하 및 접속 옵션을 점검하신 후 재시도해주시기 바랍니다."
    DETAIL_CONTENT="조회 결과는 ERROR_TIMEOUT 입니다."
elif [[ "$RESULT" == "ERROR" ]]; then
    STATUS="FAIL"
    REASON_LINE="MySQL 접속에 실패하여 계정 잠금 상태를 확인할 수 없습니다. 진단 계정 권한 또는 접속 정보를 점검해주시기 바랍니다.\n조치 방법은 진단 계정의 권한(예: mysql.user 조회 권한)과 인증 정보를 확인해주시기 바랍니다."
    DETAIL_CONTENT="조회 결과는 ERROR 입니다."
else
    VULN_COUNT=0
    SAMPLE="N/A"
    REASON=""

    while IFS=$'\t' read -r user host locked; do
        [[ -z "$user" && -z "$host" ]] && continue
        [[ "$locked" == "Y" ]] && continue

        if [[ -z "$user" ]]; then
            VULN_COUNT=$((VULN_COUNT + 1))
            [[ "$SAMPLE" == "N/A" ]] && SAMPLE="anonymous@${host}"
            [[ -z "$REASON" ]] && REASON="익명 계정에 대한 잠금 또는 삭제가 적용되지 않았습니다."
            continue
        fi

        if in_csv "$user" "$DEMO_USERS_CSV"; then
            VULN_COUNT=$((VULN_COUNT + 1))
            [[ "$SAMPLE" == "N/A" ]] && SAMPLE="${user}@${host}"
            [[ -z "$REASON" ]] && REASON="데모 또는 테스트 계정(${user})이 활성 상태입니다."
            continue
        fi

        if [[ -n "$AUTHORIZED_USERS_CSV" ]] && ! in_csv "$user" "$AUTHORIZED_USERS_CSV"; then
            VULN_COUNT=$((VULN_COUNT + 1))
            [[ "$SAMPLE" == "N/A" ]] && SAMPLE="${user}@${host}"
            [[ -z "$REASON" ]] && REASON="기관 허용 목록 외 계정이 활성 상태입니다."
            continue
        fi
    done <<< "$RESULT"

    if [[ "$VULN_COUNT" -eq 0 ]]; then
        STATUS="PASS"
        if [[ -n "$AUTHORIZED_USERS_CSV" ]]; then
            REASON_LINE="허용 계정 목록 기준으로 불필요 계정이 확인되지 않아 이 항목에 대한 보안 위협이 없습니다."
        elif [[ "$QUERY_MODE" == "FALLBACK" ]]; then
            REASON_LINE="구버전 호환 점검 기준으로도 명백한 불필요 계정(익명/데모/테스트) 활성 상태가 확인되지 않아 이 항목에 대한 보안 위협이 없습니다."
        else
            REASON_LINE="명백한 불필요 계정(익명/데모/테스트) 활성 상태가 확인되지 않아 이 항목에 대한 보안 위협이 없습니다."
        fi
        DETAIL_CONTENT="취약 계정 수는 0건입니다."
    else
        STATUS="FAIL"
        REASON_LINE="불필요 계정으로 판단되는 활성 계정이 확인되었습니다. ${REASON}\n조치 방법은 익명 계정은 삭제하거나 잠금 처리해주시기 바라며, 데모/테스트 계정은 삭제 또는 잠금 처리해주시기 바랍니다. 또한 기관 허용 목록을 사용하는 경우 허용 목록을 최신화하고, 목록 외 계정은 정리(삭제/잠금)해주시기 바랍니다."
        DETAIL_CONTENT="취약 계정 수는 ${VULN_COUNT}건이며, 예시는 ${SAMPLE} 입니다."
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