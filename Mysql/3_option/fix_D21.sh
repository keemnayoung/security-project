#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-11
# ============================================================================
# [점검 항목 상세]
# @ID          : D-21
# @Category    : DBMS (Database Management System)
# @Platform    : MySQL 8.0.44
# @IMPORTANCE  : 중
# @Title       : 인가되지 않은 GRANT OPTION 사용 제한
# @Description : 일반 사용자에게 GRANT OPTION이 부여되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-21"
CATEGORY="권한관리"
TITLE="인가되지 않은 GRANT OPTION 사용 제한"
IMPORTANCE="중"

STATUS="FAIL"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
EVIDENCE="N/A"

TIMEOUT_BIN=""
MYSQL_TIMEOUT_SEC=5
MYSQL_CMD_BASE="mysql --protocol=TCP -uroot -N -s -B -e"

# 제외 계정(기관 정책으로 확장 가능)
EXCLUDE_USERS_CSV="${EXCLUDE_USERS_CSV:-root,mysql.session,mysql.sys,mysql.infoschema,mysqlxsys,mariadb.sys}"

# 선택: ROLE 기반으로 WITH GRANT OPTION을 이관
MIGRATE_TO_ROLE="${MIGRATE_TO_ROLE:-N}"     # Y|N
ROLE_NAME="${ROLE_NAME:-security_grant_role}"
ROLE_HOST="${ROLE_HOST:-%}"
GRANT_ROLE_TO_USERS="${GRANT_ROLE_TO_USERS:-Y}"  # Y|N

run_mysql() {
    local sql="$1"
    if [[ -n "$TIMEOUT_BIN" ]]; then
        $TIMEOUT_BIN ${MYSQL_TIMEOUT_SEC}s $MYSQL_CMD_BASE "$sql" 2>/dev/null
    else
        $MYSQL_CMD_BASE "$sql" 2>/dev/null
    fi
    return $?
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

extract_user() {
    echo "$1" | sed -E "s/^'([^']+)'.*$/\1/"
}

extract_host() {
    echo "$1" | sed -E "s/^'[^']+'@'([^']+)'$/\1/"
}

sql_escape_literal() {
    local s="$1"
    s="${s//\'/\'\'}"
    printf "%s" "$s"
}

MIGRATE_TO_ROLE="$(echo "$MIGRATE_TO_ROLE" | tr '[:lower:]' '[:upper:]')"
GRANT_ROLE_TO_USERS="$(echo "$GRANT_ROLE_TO_USERS" | tr '[:lower:]' '[:upper:]')"
if [[ "$MIGRATE_TO_ROLE" != "Y" && "$MIGRATE_TO_ROLE" != "N" ]]; then
    MIGRATE_TO_ROLE="N"
fi
if [[ "$GRANT_ROLE_TO_USERS" != "Y" && "$GRANT_ROLE_TO_USERS" != "N" ]]; then
    GRANT_ROLE_TO_USERS="Y"
fi

# 직접 부여된 WITH GRANT OPTION 권한 조회(전역/스키마/테이블/컬럼)
CHECK_SQL="
SELECT GRANTEE, 'GLOBAL' AS scope, PRIVILEGE_TYPE, '*.*' AS db_name, '*' AS tbl_name, '*' AS col_name
FROM information_schema.user_privileges
WHERE IS_GRANTABLE='YES'
UNION ALL
SELECT GRANTEE, 'SCHEMA' AS scope, PRIVILEGE_TYPE, TABLE_SCHEMA AS db_name, '*' AS tbl_name, '*' AS col_name
FROM information_schema.schema_privileges
WHERE IS_GRANTABLE='YES'
UNION ALL
SELECT GRANTEE, 'TABLE' AS scope, PRIVILEGE_TYPE, TABLE_SCHEMA AS db_name, TABLE_NAME AS tbl_name, '*' AS col_name
FROM information_schema.table_privileges
WHERE IS_GRANTABLE='YES'
UNION ALL
SELECT GRANTEE, 'COLUMN' AS scope, PRIVILEGE_TYPE, TABLE_SCHEMA AS db_name, TABLE_NAME AS tbl_name, COLUMN_NAME AS col_name
FROM information_schema.column_privileges
WHERE IS_GRANTABLE='YES'
ORDER BY GRANTEE, scope, db_name, tbl_name, col_name, PRIVILEGE_TYPE;
"

ROWS="$(run_mysql "$CHECK_SQL")"
RC=$?

if [[ $RC -eq 124 ]]; then
    STATUS="FAIL"
    ACTION_RESULT="FAIL"
    ACTION_LOG="조치가 수행되지 않았습니다. WITH GRANT OPTION 조회 명령이 제한 시간 내 완료되지 않았습니다."
    EVIDENCE="권한 조회가 ${MYSQL_TIMEOUT_SEC}초를 초과했습니다."
elif [[ $RC -ne 0 ]]; then
    STATUS="FAIL"
    ACTION_RESULT="FAIL"
    ACTION_LOG="조치가 수행되지 않았습니다. WITH GRANT OPTION 조회에 실패했습니다."
    EVIDENCE="information_schema 권한 조회 실패로 회수 대상 식별이 불가능합니다."
else
    # D-21 핵심: 필요 시 WITH GRANT OPTION을 ROLE 기반으로 운영할 수 있도록 역할을 준비한다.
    ROLE_GRANTEE="'$(sql_escape_literal "$ROLE_NAME")'@'$(sql_escape_literal "$ROLE_HOST")'"
    ROLE_READY=1
    if [[ "$MIGRATE_TO_ROLE" == "Y" ]]; then
        CREATE_ROLE_SQL="CREATE ROLE IF NOT EXISTS ${ROLE_GRANTEE};"
        run_mysql "$CREATE_ROLE_SQL" >/dev/null
        RC_ROLE=$?
        if [[ $RC_ROLE -ne 0 ]]; then
            ROLE_READY=0
        fi
    fi

    TARGET_COUNT=0
    MODIFIED_COUNT=0
    FAILED_COUNT=0
    FAIL_SAMPLE="N/A"
    ROLE_APPLY_COUNT=0
    ROLE_APPLY_FAIL=0
    ROLE_APPLY_FAIL_SAMPLE="N/A"
    AFFECTED_USERS=""

    # D-21 핵심: 일반 사용자에게 직접 부여된 WITH GRANT OPTION을 회수한다.
    while IFS=$'\t' read -r grantee scope priv db tbl col; do
        [[ -z "$grantee" || -z "$scope" || -z "$priv" ]] && continue

        user="$(extract_user "$grantee")"
        host="$(extract_host "$grantee")"
        if in_csv "$user" "$EXCLUDE_USERS_CSV"; then
            continue
        fi

        TARGET_COUNT=$((TARGET_COUNT + 1))

        case "$scope" in
            GLOBAL)
                REVOKE_SQL="REVOKE ${priv} ON *.* FROM ${grantee};"
                ;;
            SCHEMA)
                REVOKE_SQL="REVOKE ${priv} ON \`${db}\`.* FROM ${grantee};"
                ;;
            TABLE)
                REVOKE_SQL="REVOKE ${priv} ON \`${db}\`.\`${tbl}\` FROM ${grantee};"
                ;;
            COLUMN)
                REVOKE_SQL="REVOKE ${priv} (\`${col}\`) ON \`${db}\`.\`${tbl}\` FROM ${grantee};"
                ;;
            *)
                REVOKE_SQL=""
                ;;
        esac

        # ROLE 이관 모드에서는 동일 권한을 ROLE에 WITH GRANT OPTION으로 부여한다.
        ROLE_GRANT_SQL=""
        if [[ "$MIGRATE_TO_ROLE" == "Y" && "$ROLE_READY" -eq 1 ]]; then
            case "$scope" in
                GLOBAL)
                    ROLE_GRANT_SQL="GRANT ${priv} ON *.* TO ${ROLE_GRANTEE} WITH GRANT OPTION;"
                    ;;
                SCHEMA)
                    ROLE_GRANT_SQL="GRANT ${priv} ON \`${db}\`.* TO ${ROLE_GRANTEE} WITH GRANT OPTION;"
                    ;;
                TABLE)
                    ROLE_GRANT_SQL="GRANT ${priv} ON \`${db}\`.\`${tbl}\` TO ${ROLE_GRANTEE} WITH GRANT OPTION;"
                    ;;
                COLUMN)
                    ROLE_GRANT_SQL="GRANT ${priv} (\`${col}\`) ON \`${db}\`.\`${tbl}\` TO ${ROLE_GRANTEE} WITH GRANT OPTION;"
                    ;;
            esac
        fi

        if [[ -z "$REVOKE_SQL" ]]; then
            FAILED_COUNT=$((FAILED_COUNT + 1))
            [[ "$FAIL_SAMPLE" == "N/A" ]] && FAIL_SAMPLE="${grantee}:${scope}:${priv}"
            continue
        fi

        run_mysql "$REVOKE_SQL" >/dev/null
        rc2=$?
        if [[ $rc2 -eq 0 ]]; then
            MODIFIED_COUNT=$((MODIFIED_COUNT + 1))

            if [[ "$MIGRATE_TO_ROLE" == "Y" && "$ROLE_READY" -eq 1 && -n "$ROLE_GRANT_SQL" ]]; then
                run_mysql "$ROLE_GRANT_SQL" >/dev/null
                rc_role_apply=$?
                if [[ $rc_role_apply -eq 0 ]]; then
                    ROLE_APPLY_COUNT=$((ROLE_APPLY_COUNT + 1))
                    if [[ "$GRANT_ROLE_TO_USERS" == "Y" ]]; then
                        user_host="${user}@${host}"
                        if ! printf "%s\n" "$AFFECTED_USERS" | grep -Fqx "$user_host"; then
                            if [[ -z "$AFFECTED_USERS" ]]; then
                                AFFECTED_USERS="$user_host"
                            else
                                AFFECTED_USERS="${AFFECTED_USERS}"$'\n'"${user_host}"
                            fi
                        fi
                    fi
                else
                    ROLE_APPLY_FAIL=1
                    [[ "$ROLE_APPLY_FAIL_SAMPLE" == "N/A" ]] && ROLE_APPLY_FAIL_SAMPLE="${scope}:${db}.${tbl}.${col}:${priv}"
                fi
            fi
        else
            FAILED_COUNT=$((FAILED_COUNT + 1))
            [[ "$FAIL_SAMPLE" == "N/A" ]] && FAIL_SAMPLE="${grantee}:${scope}:${db}.${tbl}.${col}:${priv}"
        fi
    done <<< "$ROWS"

    # ROLE 이관 모드에서 필요 사용자에게 ROLE을 부여한다.
    ROLE_BIND_FAIL=0
    ROLE_BIND_FAIL_SAMPLE="N/A"
    ROLE_BIND_COUNT=0
    if [[ "$MIGRATE_TO_ROLE" == "Y" && "$ROLE_READY" -eq 1 && "$GRANT_ROLE_TO_USERS" == "Y" && -n "$AFFECTED_USERS" ]]; then
        while IFS= read -r user_host; do
            [[ -z "$user_host" ]] && continue
            u="${user_host%@*}"
            h="${user_host#*@}"
            esc_u="$(sql_escape_literal "$u")"
            esc_h="$(sql_escape_literal "$h")"
            GRANT_ROLE_SQL="GRANT ${ROLE_GRANTEE} TO '$(sql_escape_literal "$esc_u")'@'$(sql_escape_literal "$esc_h")';"
            run_mysql "$GRANT_ROLE_SQL" >/dev/null
            rc_bind=$?
            if [[ $rc_bind -eq 0 ]]; then
                ROLE_BIND_COUNT=$((ROLE_BIND_COUNT + 1))
            else
                ROLE_BIND_FAIL=1
                [[ "$ROLE_BIND_FAIL_SAMPLE" == "N/A" ]] && ROLE_BIND_FAIL_SAMPLE="${u}@${h}"
            fi
        done <<< "$AFFECTED_USERS"
    fi

    run_mysql "FLUSH PRIVILEGES;" >/dev/null
    RC_FLUSH=$?

    if [[ "$TARGET_COUNT" -eq 0 ]]; then
        STATUS="PASS"
        ACTION_RESULT="SUCCESS"
        ACTION_LOG="직접 부여된 WITH GRANT OPTION 권한이 확인되지 않아 추가 조치 없이 기준을 충족합니다."
        EVIDENCE="회수 대상이 없습니다."
    elif [[ "$MIGRATE_TO_ROLE" == "Y" && "$ROLE_READY" -eq 0 ]]; then
        STATUS="FAIL"
        ACTION_RESULT="FAIL"
        ACTION_LOG="조치가 부분 실패했습니다. 직접 권한 회수는 수행했으나 ROLE 생성에 실패했습니다."
        EVIDENCE="ROLE 기반 전환을 요청했지만 ROLE 생성에 실패하여 권한 이관을 완료하지 못했습니다."
    elif [[ "$FAILED_COUNT" -eq 0 ]]; then
        if [[ "$RC_FLUSH" -ne 0 ]]; then
            STATUS="FAIL"
            ACTION_RESULT="FAIL"
            ACTION_LOG="조치가 부분 실패했습니다. 권한 회수 후 FLUSH PRIVILEGES에 실패했습니다."
            EVIDENCE="권한 회수는 완료했으나 권한 반영에 실패했습니다."
        elif [[ "$MIGRATE_TO_ROLE" == "Y" && ( "$ROLE_APPLY_FAIL" -eq 1 || "$ROLE_BIND_FAIL" -eq 1 ) ]]; then
            STATUS="FAIL"
            ACTION_RESULT="FAIL"
            ACTION_LOG="조치가 부분 실패했습니다. 권한 회수는 완료했으나 ROLE 이관/부여 일부가 실패했습니다."
            EVIDENCE="회수 ${MODIFIED_COUNT}건 완료, ROLE 권한 이관 실패 예: ${ROLE_APPLY_FAIL_SAMPLE}, ROLE 부여 실패 예: ${ROLE_BIND_FAIL_SAMPLE}."
        elif [[ "$MIGRATE_TO_ROLE" == "Y" ]]; then
            STATUS="PASS"
            ACTION_RESULT="SUCCESS"
            ACTION_LOG="직접 부여된 WITH GRANT OPTION을 회수하고 ROLE 기반 권한으로 전환했습니다."
            EVIDENCE="권한 회수 ${MODIFIED_COUNT}건, ROLE 권한 이관 ${ROLE_APPLY_COUNT}건, ROLE 부여 ${ROLE_BIND_COUNT}건 완료."
        else
            STATUS="PASS"
            ACTION_RESULT="SUCCESS"
            ACTION_LOG="일반 계정에 직접 부여된 WITH GRANT OPTION 권한을 회수했습니다."
            EVIDENCE="권한 회수 완료: 대상 ${TARGET_COUNT}건, 성공 ${MODIFIED_COUNT}건."
        fi
    else
        STATUS="FAIL"
        ACTION_RESULT="FAIL"
        ACTION_LOG="조치가 부분 실패했습니다. 일부 WITH GRANT OPTION 권한 회수에 실패했습니다."
        EVIDENCE="권한 회수 결과: 대상 ${TARGET_COUNT}건 중 성공 ${MODIFIED_COUNT}건, 실패 ${FAILED_COUNT}건 (예: ${FAIL_SAMPLE})."
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
