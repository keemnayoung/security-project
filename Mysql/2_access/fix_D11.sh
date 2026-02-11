#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-11
# ============================================================================
# [점검 항목 상세]
# @ID          : D-11
# @Category    : DBMS (Database Management System)
# @Platform    : MySQL 8.0.44
# @IMPORTANCE  : 상
# @Title       : DBA 이외 사용자의 시스템 테이블 접근 제한
# @Description : mysql 등 시스템 스키마에 일반 사용자가 접근 불가하도록 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-11"
CATEGORY="접근통제"
TITLE="DBA 이외의 인가되지 않은 사용자가 시스템 테이블에 접근할 수 없도록 설정"
IMPORTANCE="상"

STATUS="FAIL"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
EVIDENCE="N/A"

TIMEOUT_BIN=""
MYSQL_TIMEOUT_SEC=5
MYSQL_CMD_BASE="mysql --protocol=TCP -uroot -N -s -B -e"

run_mysql() {
    local sql="$1"
    if [[ -n "$TIMEOUT_BIN" ]]; then
        $TIMEOUT_BIN ${MYSQL_TIMEOUT_SEC}s $MYSQL_CMD_BASE "$sql" 2>/dev/null
    else
        $MYSQL_CMD_BASE "$sql" 2>/dev/null
    fi
    return $?
}

sql_escape_literal() {
    local s="$1"
    s="${s//\'/\'\'}"
    printf "%s" "$s"
}

ident_escape() {
    local s="$1"
    s="${s//\`/\`\`}"
    printf "%s" "$s"
}

TARGET_USER="${TARGET_USER:-}"
TARGET_HOST="${TARGET_HOST:-}"

# TABLE | DB | NONE
KEEP_SCOPE="${KEEP_SCOPE:-}"
KEEP_DB="${KEEP_DB:-}"
KEEP_TABLE="${KEEP_TABLE:-}"
KEEP_PRIV_LIST="${KEEP_PRIV_LIST:-}"

KEEP_SCOPE="$(echo "$KEEP_SCOPE" | tr '[:lower:]' '[:upper:]')"

if [[ -z "$TARGET_USER" || -z "$TARGET_HOST" || -z "$KEEP_SCOPE" ]]; then
    STATUS="FAIL"
    ACTION_RESULT="FAIL"
    ACTION_LOG="조치가 수행되지 않았습니다. 대상 계정/권한 유지 범위 정보가 누락되었습니다."
    EVIDENCE="TARGET_USER, TARGET_HOST, KEEP_SCOPE 값이 필요합니다."
elif [[ "$TARGET_USER" == *"'"* || "$TARGET_HOST" == *"'"* ]]; then
    STATUS="FAIL"
    ACTION_RESULT="FAIL"
    ACTION_LOG="조치가 수행되지 않았습니다. 입력값 검증에 실패했습니다."
    EVIDENCE="TARGET_USER 또는 TARGET_HOST에 작은따옴표(')가 포함되어 조치를 중단합니다."
elif [[ "$KEEP_SCOPE" == "TABLE" && ( -z "$KEEP_DB" || -z "$KEEP_TABLE" || -z "$KEEP_PRIV_LIST" ) ]]; then
    STATUS="FAIL"
    ACTION_RESULT="FAIL"
    ACTION_LOG="조치가 수행되지 않았습니다. 테이블 단위 재부여 정보가 부족합니다."
    EVIDENCE="KEEP_SCOPE=TABLE 설정 시 KEEP_DB, KEEP_TABLE, KEEP_PRIV_LIST가 필요합니다."
elif [[ "$KEEP_SCOPE" == "DB" && ( -z "$KEEP_DB" || -z "$KEEP_PRIV_LIST" ) ]]; then
    STATUS="FAIL"
    ACTION_RESULT="FAIL"
    ACTION_LOG="조치가 수행되지 않았습니다. DB 단위 재부여 정보가 부족합니다."
    EVIDENCE="KEEP_SCOPE=DB 설정 시 KEEP_DB, KEEP_PRIV_LIST가 필요합니다."
elif [[ "$KEEP_SCOPE" != "TABLE" && "$KEEP_SCOPE" != "DB" && "$KEEP_SCOPE" != "NONE" ]]; then
    STATUS="FAIL"
    ACTION_RESULT="FAIL"
    ACTION_LOG="조치가 수행되지 않았습니다. KEEP_SCOPE 값이 유효하지 않습니다."
    EVIDENCE="KEEP_SCOPE 값은 TABLE, DB, NONE 중 하나여야 합니다."
else
    esc_user="$(sql_escape_literal "$TARGET_USER")"
    esc_host="$(sql_escape_literal "$TARGET_HOST")"
    GRANTEE="'${esc_user}'@'${esc_host}'"

    # D-11 핵심: 대상 계정 권한을 확인해 조치 대상을 검증한다.
    CHECK_SQL="SHOW GRANTS FOR ${GRANTEE};"
    CHECK_OUT="$(run_mysql "$CHECK_SQL")"
    RC0=$?

    if [[ $RC0 -eq 124 ]]; then
        STATUS="FAIL"
        ACTION_RESULT="FAIL"
        ACTION_LOG="조치가 수행되지 않았습니다. 대상 계정 권한 조회가 제한 시간 내 완료되지 않았습니다."
        EVIDENCE="SHOW GRANTS 실행이 ${MYSQL_TIMEOUT_SEC}초를 초과했습니다."
    elif [[ $RC0 -ne 0 || -z "$CHECK_OUT" ]]; then
        STATUS="FAIL"
        ACTION_RESULT="FAIL"
        ACTION_LOG="조치가 수행되지 않았습니다. 대상 계정 권한을 조회할 수 없습니다."
        EVIDENCE="SHOW GRANTS 실패: 대상 계정 존재 여부 또는 권한을 확인하세요."
    else
        # D-11 핵심: 일반 계정의 시스템 테이블 접근 가능성을 제거하기 위해 권한을 최소 상태로 초기화한다.
        RESET_SQL="REVOKE ALL PRIVILEGES, GRANT OPTION FROM ${GRANTEE};"
        run_mysql "$RESET_SQL" >/dev/null
        RC1=$?

        if [[ $RC1 -eq 124 ]]; then
            STATUS="FAIL"
            ACTION_RESULT="FAIL"
            ACTION_LOG="조치가 수행되지 않았습니다. 권한 초기화 명령이 제한 시간을 초과했습니다."
            EVIDENCE="권한 초기화 명령이 ${MYSQL_TIMEOUT_SEC}초 내 완료되지 않았습니다."
        elif [[ $RC1 -ne 0 ]]; then
            STATUS="FAIL"
            ACTION_RESULT="FAIL"
            ACTION_LOG="조치가 수행되지 않았습니다. 권한 초기화에 실패했습니다."
            EVIDENCE="REVOKE ALL PRIVILEGES, GRANT OPTION 수행에 실패하여 최소 권한 상태로 전환하지 못했습니다."
        else
            # D-11 핵심: 역할(Role)을 통한 간접 접근도 차단하기 위해 계정에 부여된 역할을 회수한다.
            ROLE_SQL="
SELECT FROM_USER, FROM_HOST
FROM mysql.role_edges
WHERE TO_USER='${esc_user}' AND TO_HOST='${esc_host}';
"
            ROLE_ROWS="$(run_mysql "$ROLE_SQL")"
            RC2=$?

            if [[ $RC2 -eq 124 ]]; then
                STATUS="FAIL"
                ACTION_RESULT="FAIL"
                ACTION_LOG="조치가 수행되지 않았습니다. 역할 권한 조회가 제한 시간을 초과했습니다."
                EVIDENCE="mysql.role_edges 조회가 ${MYSQL_TIMEOUT_SEC}초 내 완료되지 않았습니다."
            elif [[ $RC2 -ne 0 ]]; then
                STATUS="FAIL"
                ACTION_RESULT="FAIL"
                ACTION_LOG="조치가 수행되지 않았습니다. 역할 권한 조회에 실패했습니다."
                EVIDENCE="간접 권한(ROLE) 회수를 위한 대상 조회에 실패했습니다."
            else
                ROLE_FAIL=0
                ROLE_FAIL_SAMPLE="N/A"
                ROLE_REVOKE_COUNT=0

                while IFS=$'\t' read -r role_user role_host; do
                    [[ -z "$role_user" || -z "$role_host" ]] && continue
                    esc_role_user="$(sql_escape_literal "$role_user")"
                    esc_role_host="$(sql_escape_literal "$role_host")"
                    REVOKE_ROLE_SQL="REVOKE '${esc_role_user}'@'${esc_role_host}' FROM ${GRANTEE};"
                    run_mysql "$REVOKE_ROLE_SQL" >/dev/null
                    rc_role=$?
                    ROLE_REVOKE_COUNT=$((ROLE_REVOKE_COUNT + 1))
                    if [[ $rc_role -ne 0 ]]; then
                        ROLE_FAIL=1
                        [[ "$ROLE_FAIL_SAMPLE" == "N/A" ]] && ROLE_FAIL_SAMPLE="${role_user}@${role_host}"
                    fi
                done <<< "$ROLE_ROWS"

                if [[ "$ROLE_FAIL" -eq 1 ]]; then
                    STATUS="FAIL"
                    ACTION_RESULT="FAIL"
                    ACTION_LOG="조치가 부분 실패했습니다. 일부 역할 권한 회수에 실패했습니다."
                    EVIDENCE="역할 권한 회수 중 실패가 발생했습니다. (예: ${ROLE_FAIL_SAMPLE})"
                else
                    # D-11 핵심: 접근이 필요한 업무 DB/테이블 범위에만 최소 권한을 재부여한다.
                    if [[ "$KEEP_SCOPE" == "TABLE" ]]; then
                        esc_keep_db="$(ident_escape "$KEEP_DB")"
                        esc_keep_table="$(ident_escape "$KEEP_TABLE")"
                        GRANT_SQL="GRANT ${KEEP_PRIV_LIST} ON \`${esc_keep_db}\`.\`${esc_keep_table}\` TO ${GRANTEE};"
                        KEEP_DESC="${KEEP_DB}.${KEEP_TABLE}"
                        run_mysql "$GRANT_SQL" >/dev/null
                        RC3=$?
                    elif [[ "$KEEP_SCOPE" == "DB" ]]; then
                        esc_keep_db="$(ident_escape "$KEEP_DB")"
                        GRANT_SQL="GRANT ${KEEP_PRIV_LIST} ON \`${esc_keep_db}\`.* TO ${GRANTEE};"
                        KEEP_DESC="${KEEP_DB}.*"
                        run_mysql "$GRANT_SQL" >/dev/null
                        RC3=$?
                    else
                        KEEP_DESC="NONE"
                        RC3=0
                    fi

                    if [[ $RC3 -eq 0 ]]; then
                        run_mysql "FLUSH PRIVILEGES;" >/dev/null
                        RC4=$?
                        if [[ $RC4 -ne 0 ]]; then
                            STATUS="FAIL"
                            ACTION_RESULT="FAIL"
                            ACTION_LOG="조치가 부분 실패했습니다. 권한 반영에 실패했습니다."
                            EVIDENCE="권한 조정은 수행했으나 FLUSH PRIVILEGES 실행에 실패했습니다."
                        elif [[ "$KEEP_SCOPE" == "NONE" ]]; then
                            STATUS="PASS"
                            ACTION_RESULT="SUCCESS"
                            ACTION_LOG="시스템 테이블 접근 권한을 제거하고 불필요한 역할 권한을 회수했습니다."
                            EVIDENCE="대상 계정(${TARGET_USER}@${TARGET_HOST})을 최소 권한 상태로 조정했습니다. (회수 역할 ${ROLE_REVOKE_COUNT}건)"
                        else
                            STATUS="PASS"
                            ACTION_RESULT="SUCCESS"
                            ACTION_LOG="시스템 테이블 접근 권한 제거 후 업무 범위 최소 권한만 재부여했습니다."
                            EVIDENCE="대상 계정(${TARGET_USER}@${TARGET_HOST})에 ${KEEP_DESC} 범위 ${KEEP_PRIV_LIST}만 재부여했습니다. (회수 역할 ${ROLE_REVOKE_COUNT}건)"
                        fi
                    else
                        STATUS="FAIL"
                        ACTION_RESULT="FAIL"
                        ACTION_LOG="조치가 부분 실패했습니다. 업무 권한 재부여에 실패했습니다."
                        EVIDENCE="최소 권한 상태로 초기화는 완료했으나 업무 권한 재부여(${KEEP_DESC})에 실패했습니다."
                    fi
                fi
            fi
        fi
    fi
fi

echo ""
cat << EOF_JSON
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
EOF_JSON
