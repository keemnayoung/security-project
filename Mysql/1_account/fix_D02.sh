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
# @IMPORTANCE  : 상
# @Title       : 데이터베이스의 불필요 계정 제거 또는 잠금 설정
# @Description : DB 운용에 사용하지 않는 불필요 계정을 삭제 또는 잠금
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-02"
CATEGORY="계정관리"
TITLE="데이터베이스의 불필요 계정을 제거하거나, 잠금설정 후 사용"
IMPORTANCE="상"

STATUS="FAIL"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
EVIDENCE="N/A"

ACTION="${ACTION:-DROP}"
TARGET_USER="${TARGET_USER:-}"
TARGET_HOST="${TARGET_HOST:-}"
TARGET_ACCOUNTS_CSV="${TARGET_ACCOUNTS_CSV:-}"
AUTHORIZED_USERS_CSV="${AUTHORIZED_USERS_CSV:-}"
DEMO_USERS_CSV="${DEMO_USERS_CSV:-scott,pm,adams,clark,test,guest,demo,sample}"
SYSTEM_USERS_CSV="${SYSTEM_USERS_CSV:-root,mysql.sys,mysql.session,mysql.infoschema,mysqlxsys,mariadb.sys}"

TIMEOUT_BIN=""
MYSQL_TIMEOUT_SEC=5
MYSQL_CMD="mysql --protocol=TCP -uroot -N -s -B -e"

run_mysql_query() {
    local sql="$1"
    if [[ -n "$TIMEOUT_BIN" ]]; then
        $TIMEOUT_BIN "${MYSQL_TIMEOUT_SEC}s" $MYSQL_CMD "$sql" >/dev/null 2>&1
        return $?
    fi
    $MYSQL_CMD "$sql" >/dev/null 2>&1
    return $?
}

run_mysql_rows() {
    local sql="$1"
    if [[ -n "$TIMEOUT_BIN" ]]; then
        $TIMEOUT_BIN "${MYSQL_TIMEOUT_SEC}s" $MYSQL_CMD "$sql" 2>/dev/null
        return $?
    fi
    $MYSQL_CMD "$sql" 2>/dev/null
    return $?
}

sql_escape_literal() {
    local s="$1"
    s="${s//\'/\'\'}"
    printf "%s" "$s"
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

add_candidate() {
    local user="$1"
    local host="$2"
    local row
    row="${user}"$'\t'"${host}"
    if ! printf "%s\n" "$CANDIDATES" | grep -Fqx "$row"; then
        if [[ -z "$CANDIDATES" ]]; then
            CANDIDATES="$row"
        else
            CANDIDATES="${CANDIDATES}"$'\n'"${row}"
        fi
    fi
}

ACTION="$(echo "$ACTION" | tr '[:lower:]' '[:upper:]')"
case "$ACTION" in
    DROP)
        ACTION_DESC="불필요한 계정을 삭제"
        ;;
    LOCK)
        ACTION_DESC="불필요한 계정을 잠금 처리"
        ;;
    *)
        ACTION_LOG="조치가 수행되지 않았습니다. ACTION 값이 유효하지 않습니다."
        EVIDENCE="ACTION 값은 DROP 또는 LOCK 중 하나여야 합니다."
        ;;
esac

if [[ "$ACTION" == "DROP" || "$ACTION" == "LOCK" ]]; then
    CANDIDATES=""

    # 운영자가 특정 계정을 지정한 경우 해당 계정부터 우선 조치한다.
    if [[ -n "$TARGET_USER" && -n "$TARGET_HOST" ]]; then
        add_candidate "$TARGET_USER" "$TARGET_HOST"
    elif [[ -n "$TARGET_ACCOUNTS_CSV" ]]; then
        # 복수 대상 입력(user@host,...)을 받아 일괄 조치 대상을 구성한다.
        IFS=',' read -r -a entries <<< "$TARGET_ACCOUNTS_CSV"
        for entry in "${entries[@]}"; do
            [[ -z "$entry" ]] && continue
            user="${entry%@*}"
            host="${entry#*@}"
            [[ -z "$user" || -z "$host" || "$entry" == "$host" ]] && continue
            add_candidate "$user" "$host"
        done
    else
        # D-02 핵심: 전체 계정을 조회해 불필요 계정(익명/데모/인가외)을 자동 식별한다.
        ROWS="$(run_mysql_rows "SELECT user, host FROM mysql.user;")"
        RC=$?

        if [[ "$RC" -eq 124 ]]; then
            ACTION_LOG="조치가 수행되지 않았습니다. 계정 목록 조회가 제한 시간 내 완료되지 않아 중단하였습니다."
            EVIDENCE="MySQL 명령 실행이 ${MYSQL_TIMEOUT_SEC}초 내에 완료되지 않아 불필요 계정 식별을 중단하였습니다."
        elif [[ "$RC" -ne 0 ]]; then
            ACTION_LOG="조치가 수행되지 않았습니다. MySQL 접속 오류 또는 권한 부족으로 계정 목록 조회에 실패하였습니다."
            EVIDENCE="mysql.user 조회 실패로 불필요 계정을 식별할 수 없습니다."
        else
            while IFS=$'\t' read -r user host; do
                [[ -z "$host" && -z "$user" ]] && continue

                if in_csv "$user" "$SYSTEM_USERS_CSV"; then
                    continue
                fi

                if [[ -z "$user" ]]; then
                    add_candidate "$user" "$host"
                    continue
                fi

                if in_csv "$user" "$DEMO_USERS_CSV"; then
                    add_candidate "$user" "$host"
                    continue
                fi

                if [[ -n "$AUTHORIZED_USERS_CSV" ]] && ! in_csv "$user" "$AUTHORIZED_USERS_CSV"; then
                    add_candidate "$user" "$host"
                    continue
                fi
            done <<< "$ROWS"
        fi
    fi

    if [[ -z "$ACTION_LOG" || "$ACTION_LOG" == "N/A" ]]; then
        if [[ -z "$CANDIDATES" ]]; then
            STATUS="PASS"
            ACTION_RESULT="SUCCESS"
            ACTION_LOG="불필요 계정(데모/테스트/익명 및 인가 목록 외 계정)을 점검했으며 조치 대상이 확인되지 않았습니다."
            EVIDENCE="D-02 기준에 따라 불필요 계정이 확인되지 않아 추가 조치가 필요하지 않습니다."
        else
            TARGET_COUNT=0
            SUCCESS_COUNT=0
            FAIL_COUNT=0
            FAIL_SAMPLE="N/A"

            # D-02 조치: 식별된 불필요 계정을 삭제(DROP) 또는 잠금(LOCK) 처리한다.
            while IFS=$'\t' read -r user host; do
                [[ -z "$host" && -z "$user" ]] && continue
                TARGET_COUNT=$((TARGET_COUNT + 1))

                esc_user="$(sql_escape_literal "$user")"
                esc_host="$(sql_escape_literal "$host")"

                if [[ "$ACTION" == "DROP" ]]; then
                    run_mysql_query "DROP USER IF EXISTS '${esc_user}'@'${esc_host}';"
                else
                    run_mysql_query "ALTER USER '${esc_user}'@'${esc_host}' ACCOUNT LOCK;"
                fi
                RC=$?

                if [[ "$RC" -eq 0 ]]; then
                    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
                else
                    FAIL_COUNT=$((FAIL_COUNT + 1))
                    [[ "$FAIL_SAMPLE" == "N/A" ]] && FAIL_SAMPLE="${user}@${host}"
                fi
            done <<< "$CANDIDATES"

            # MySQL 조치 예시와 동일하게 DROP 후 권한 캐시를 반영한다.
            if [[ "$ACTION" == "DROP" && "$SUCCESS_COUNT" -gt 0 ]]; then
                run_mysql_query "FLUSH PRIVILEGES;"
                RC_FLUSH=$?
                if [[ "$RC_FLUSH" -ne 0 ]]; then
                    FAIL_COUNT=$((FAIL_COUNT + 1))
                    [[ "$FAIL_SAMPLE" == "N/A" ]] && FAIL_SAMPLE="FLUSH PRIVILEGES"
                fi
            fi

            if [[ "$FAIL_COUNT" -eq 0 ]]; then
                STATUS="PASS"
                ACTION_RESULT="SUCCESS"
                ACTION_LOG="계정별 용도를 검토한 후 불필요 계정 ${TARGET_COUNT}건에 대해 ${ACTION_DESC} 조치를 완료했습니다."
                if [[ "$ACTION" == "DROP" ]]; then
                    EVIDENCE="불필요 계정 삭제(${SUCCESS_COUNT}건) 및 FLUSH PRIVILEGES가 정상 수행되었습니다."
                else
                    EVIDENCE="불필요 계정 잠금 조치가 정상 수행되었습니다. (성공 ${SUCCESS_COUNT}건)"
                fi
            else
                STATUS="FAIL"
                ACTION_RESULT="FAIL"
                ACTION_LOG="조치가 부분 실패했습니다. 불필요 계정 조치 중 일부 계정 처리에 실패했습니다."
                EVIDENCE="대상 ${TARGET_COUNT}건 중 성공 ${SUCCESS_COUNT}건, 실패 ${FAIL_COUNT}건 (예: ${FAIL_SAMPLE})."
            fi
        fi
    fi
fi

cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "KISA 가이드라인 기준 보안 설정 조치 완료",
    "action_result": "$ACTION_RESULT",
    "action_log": "$ACTION_LOG",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
