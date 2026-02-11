#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-11
# ============================================================================
# [점검 항목 상세]
# @ID          : D-04
# @Category    : DBMS (Database Management System)
# @Platform    : MySQL 8.0.44
# @IMPORTANCE  : 상
# @Title       : 데이터베이스 관리자 권한을 꼭 필요한 계정에만 부여
# @Description : 관리자 권한이 필요한 계정 및 그룹에만 관리자 권한을 부여하였는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-04"
CATEGORY="계정관리"
TITLE="관리자 권한이 꼭 필요한 계정 및 그룹에 대해서만 관리자 권한 허용"
IMPORTANCE="상"

STATUS="FAIL"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
EVIDENCE="N/A"

TIMEOUT_BIN=""
MYSQL_TIMEOUT_SEC=5
MYSQL_CMD_BASE="mysql -uroot -N -s -B -e"

# 인가 관리자 계정 목록(기관 정책으로 확장)
ALLOWED_ADMIN_USERS_CSV="${ALLOWED_ADMIN_USERS_CSV:-root,mysql.sys,mysql.session,mysql.infoschema,mysqlxsys,mariadb.sys}"
ALLOWED_ADMIN_PRINCIPALS_CSV="${ALLOWED_ADMIN_PRINCIPALS_CSV:-root@localhost,root@127.0.0.1,root@::1}"

# 선택 옵션: 필요한 경우 최소 관리자 권한만 재부여
GRANT_MINIMAL_ADMIN="${GRANT_MINIMAL_ADMIN:-N}"
TARGET_USER="${TARGET_USER:-}"
TARGET_HOST="${TARGET_HOST:-}"
MINIMAL_PRIV_LIST="${MINIMAL_PRIV_LIST:-BINLOG_ADMIN,SYSTEM_VARIABLES_ADMIN}"

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

# D-04(MySQL) 핵심: SUPER 권한이 부여된 계정을 점검한다.
CHECK_SQL="
SELECT grantee
FROM information_schema.user_privileges
WHERE privilege_type = 'SUPER'
ORDER BY grantee;
"

LIST="$(run_mysql "$CHECK_SQL")"
RC=$?

if [[ $RC -eq 124 ]]; then
    STATUS="FAIL"
    ACTION_RESULT="FAIL"
    ACTION_LOG="조치가 수행되지 않았습니다. 관리자 권한 조회 명령이 제한 시간 내 완료되지 않아 중단하였습니다."
    EVIDENCE="관리자 권한 조회 명령 실행이 ${MYSQL_TIMEOUT_SEC}초 내에 완료되지 않아 조치를 중단하였습니다."
elif [[ $RC -ne 0 ]]; then
    STATUS="FAIL"
    ACTION_RESULT="FAIL"
    ACTION_LOG="조치가 수행되지 않았습니다. 관리자 권한 조회에 실패하였습니다."
    EVIDENCE="information_schema.user_privileges 조회 실패로 권한 회수 대상을 확인할 수 없습니다."
else
    TARGET_COUNT=0
    MODIFIED_COUNT=0
    FAILED_COUNT=0
    FAIL_SAMPLE="N/A"

    # D-04(MySQL) 핵심: 인가되지 않은 계정의 SUPER 권한을 회수한다.
    while IFS=$'\t' read -r grantee; do
        [[ -z "$grantee" ]] && continue

        user="$(extract_user "$grantee")"
        host="$(extract_host "$grantee")"
        principal="${user}@${host}"

        if in_csv "$user" "$ALLOWED_ADMIN_USERS_CSV"; then
            continue
        fi
        if in_csv "$principal" "$ALLOWED_ADMIN_PRINCIPALS_CSV"; then
            continue
        fi

        TARGET_COUNT=$((TARGET_COUNT + 1))
        REVOKE_SQL="REVOKE SUPER ON *.* FROM ${grantee};"
        run_mysql "$REVOKE_SQL" >/dev/null
        RC2=$?

        if [[ $RC2 -eq 0 ]]; then
            MODIFIED_COUNT=$((MODIFIED_COUNT + 1))
        else
            FAILED_COUNT=$((FAILED_COUNT + 1))
            [[ "$FAIL_SAMPLE" == "N/A" ]] && FAIL_SAMPLE="${principal}:SUPER"
        fi
    done <<< "$LIST"

    if [[ "$TARGET_COUNT" -eq 0 ]]; then
        STATUS="PASS"
        ACTION_RESULT="SUCCESS"
        ACTION_LOG="인가되지 않은 관리자 권한 부여 계정이 확인되지 않아 추가 조치 없이 기준을 충족합니다."
        EVIDENCE="권한 회수 대상 계정이 없습니다."
    elif [[ "$FAILED_COUNT" -eq 0 ]]; then
        # D-04(MySQL) 핵심: 권한 회수 후 FLUSH PRIVILEGES로 반영 상태를 보장한다.
        run_mysql "FLUSH PRIVILEGES;" >/dev/null
        RC_FLUSH=$?
        if [[ $RC_FLUSH -eq 0 ]]; then
            STATUS="PASS"
            ACTION_RESULT="SUCCESS"
            ACTION_LOG="인가되지 않은 계정의 SUPER 권한을 회수하여 최소 권한 원칙을 적용하였습니다."
            EVIDENCE="SUPER 권한 회수 완료: 대상 ${TARGET_COUNT}건, 성공 ${MODIFIED_COUNT}건. FLUSH PRIVILEGES 반영까지 완료했습니다."
        else
            STATUS="FAIL"
            ACTION_RESULT="FAIL"
            ACTION_LOG="조치가 부분 실패했습니다. SUPER 권한 회수 후 권한 반영(FLUSH PRIVILEGES)에 실패했습니다."
            EVIDENCE="SUPER 권한 회수는 완료했으나 FLUSH PRIVILEGES 실행에 실패했습니다."
        fi
    else
        STATUS="FAIL"
        ACTION_RESULT="FAIL"
        ACTION_LOG="조치가 부분 실패했습니다. 일부 SUPER 권한 회수에 실패하여 추가 확인이 필요합니다."
        EVIDENCE="SUPER 권한 회수 결과: 대상 ${TARGET_COUNT}건 중 성공 ${MODIFIED_COUNT}건, 실패 ${FAILED_COUNT}건 (예: ${FAIL_SAMPLE})."
    fi

    # D-04(MySQL) 권고: 필요한 경우에만 최소 관리자 권한으로 제한하여 재부여한다.
    if [[ "$GRANT_MINIMAL_ADMIN" == "Y" && -n "$TARGET_USER" && -n "$TARGET_HOST" ]]; then
        if [[ "$STATUS" != "FAIL" ]]; then
            esc_user="${TARGET_USER//\'/\'\'}"
            esc_host="${TARGET_HOST//\'/\'\'}"
            GRANT_SQL="GRANT ${MINIMAL_PRIV_LIST} ON *.* TO '${esc_user}'@'${esc_host}';"
            run_mysql "$GRANT_SQL" >/dev/null
            RC3=$?
            if [[ $RC3 -eq 0 ]]; then
                run_mysql "FLUSH PRIVILEGES;" >/dev/null
                ACTION_LOG="인가되지 않은 SUPER 권한을 회수하고, 필요한 계정에 최소 관리자 권한만 재부여했습니다."
                EVIDENCE="SUPER 권한 회수 완료 후 최소 권한(${MINIMAL_PRIV_LIST})을 ${TARGET_USER}@${TARGET_HOST}에 부여했습니다."
            else
                STATUS="FAIL"
                ACTION_RESULT="FAIL"
                ACTION_LOG="조치가 부분 실패했습니다. 최소 관리자 권한 재부여에 실패했습니다."
                EVIDENCE="기존 권한 회수는 수행했으나 최소 권한 재부여(${TARGET_USER}@${TARGET_HOST})에 실패했습니다."
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
