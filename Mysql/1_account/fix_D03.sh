#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-11
# ============================================================================
# [점검 항목 상세]
# @ID          : D-03
# @Category    : DBMS (Database Management System)
# @Platform    : MySQL
# @IMPORTANCE  : 상
# @Title       : 비밀번호 사용 기간 및 복잡도 정책 설정
# @Description : 비밀번호 복잡도 및 사용 기간 정책 적용
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-03"
CATEGORY="계정관리"
TITLE="비밀번호 사용 기간 및 복잡도를 기관의 정책에 맞도록 설정"
IMPORTANCE="중"

STATUS="FAIL"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
EVIDENCE="N/A"

TIMEOUT_BIN=""
MYSQL_TIMEOUT_SEC=5
MYSQL_CMD="mysql --protocol=TCP -uroot -N -s -B -e"

# 기관 정책 기본값(필요 시 환경변수로 조정)
PW_POLICY="${PW_POLICY:-MEDIUM}"
PW_LENGTH="${PW_LENGTH:-8}"
PW_MIXED_CASE_COUNT="${PW_MIXED_CASE_COUNT:-1}"
PW_NUMBER_COUNT="${PW_NUMBER_COUNT:-1}"
PW_SPECIAL_CHAR_COUNT="${PW_SPECIAL_CHAR_COUNT:-1}"
PW_LIFETIME_DAYS="${PW_LIFETIME_DAYS:-90}"
EXISTING_USERS_EXPIRE_DAYS="${EXISTING_USERS_EXPIRE_DAYS:-91}"
EXCLUDE_USERS_CSV="${EXCLUDE_USERS_CSV:-root,mysql.sys,mysql.session,mysql.infoschema,mysqlxsys,mariadb.sys}"

run_sql() {
    local sql="$1"
    if [[ -n "$TIMEOUT_BIN" ]]; then
        $TIMEOUT_BIN "${MYSQL_TIMEOUT_SEC}s" $MYSQL_CMD "$sql" 2>/dev/null
    else
        $MYSQL_CMD "$sql" 2>/dev/null
    fi
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

# D-03 핵심: validate_password 설정 가능 여부(컴포넌트 설치 여부) 확인
CHECK_SQL="SHOW VARIABLES LIKE 'validate_password%';"
CHECK_OUT="$(run_sql "$CHECK_SQL")"
RC=$?

if [[ $RC -eq 124 ]]; then
    ACTION_LOG="조치가 수행되지 않았습니다. MySQL 명령 실행이 제한 시간 내 완료되지 않아 중단하였습니다."
    EVIDENCE="MySQL 명령 실행이 ${MYSQL_TIMEOUT_SEC}초 내에 완료되지 않아 대기 또는 지연이 발생하였으며, 무한 로딩 방지를 위해 처리를 중단하였습니다."
elif [[ $RC -ne 0 ]]; then
    ACTION_LOG="조치가 수행되지 않았습니다. MySQL 접속 실패 또는 권한 부족으로 정책 확인에 실패하였습니다."
    EVIDENCE="비밀번호 정책 조회 명령 수행에 실패하여 validate_password 설정 상태를 확인할 수 없습니다."
else
    if [[ -z "$CHECK_OUT" ]]; then
        run_sql "INSTALL COMPONENT 'file://component_validate_password';"
        RC=$?
        if [[ $RC -eq 124 ]]; then
            ACTION_LOG="조치가 수행되지 않았습니다. 컴포넌트 설치 명령이 제한 시간 내 완료되지 않아 중단하였습니다."
            EVIDENCE="컴포넌트 설치 명령 실행이 ${MYSQL_TIMEOUT_SEC}초 내에 완료되지 않아 무한 로딩 방지를 위해 처리를 중단하였습니다."
        elif [[ $RC -ne 0 ]]; then
            ACTION_LOG="조치가 수행되지 않았습니다. 비밀번호 정책 컴포넌트 설치에 실패하였습니다."
            EVIDENCE="component_validate_password 설치 명령 수행에 실패하여 비밀번호 복잡도 정책을 적용할 수 없습니다."
        fi
    fi

    if [[ "$EVIDENCE" == "N/A" ]]; then
        # D-03 핵심: 기관 기준 비밀번호 복잡도 정책과 비밀번호 사용기간 정책을 적용
        SET_SQL="
SET GLOBAL validate_password.policy = '$(sql_escape_literal "$PW_POLICY")';
SET GLOBAL validate_password.length = ${PW_LENGTH};
SET GLOBAL validate_password.mixed_case_count = ${PW_MIXED_CASE_COUNT};
SET GLOBAL validate_password.number_count = ${PW_NUMBER_COUNT};
SET GLOBAL validate_password.special_char_count = ${PW_SPECIAL_CHAR_COUNT};
SET GLOBAL default_password_lifetime = ${PW_LIFETIME_DAYS};
"
        run_sql "$SET_SQL"
        RC=$?
        if [[ $RC -eq 0 ]]; then
            # D-03 핵심: 정책 적용 이전에 생성된 계정에도 만료 주기 적용
            USERS_SQL="SELECT user, host FROM mysql.user;"
            USER_ROWS="$(run_sql "$USERS_SQL")"
            RC_USERS=$?

            if [[ $RC_USERS -eq 124 ]]; then
                ACTION_LOG="조치가 수행되지 않았습니다. 기존 계정 목록 조회가 제한 시간 내 완료되지 않아 중단하였습니다."
                EVIDENCE="기존 계정의 PASSWORD EXPIRE INTERVAL 적용을 위한 계정 목록 조회가 시간 초과되었습니다."
            elif [[ $RC_USERS -ne 0 ]]; then
                ACTION_LOG="조치가 수행되지 않았습니다. 기존 계정 목록 조회에 실패하였습니다."
                EVIDENCE="mysql.user 조회 실패로 기존 계정 만료 주기 적용을 완료하지 못했습니다."
            else
                APPLY_FAIL=0
                APPLY_FAIL_SAMPLE="N/A"
                APPLY_COUNT=0

                while IFS=$'\t' read -r user host; do
                    [[ -z "$user" && -z "$host" ]] && continue
                    if in_csv "$user" "$EXCLUDE_USERS_CSV"; then
                        continue
                    fi

                    esc_user="$(sql_escape_literal "$user")"
                    esc_host="$(sql_escape_literal "$host")"
                    run_sql "ALTER USER '${esc_user}'@'${esc_host}' PASSWORD EXPIRE INTERVAL ${EXISTING_USERS_EXPIRE_DAYS} DAY;"
                    RC_APPLY=$?
                    APPLY_COUNT=$((APPLY_COUNT + 1))

                    if [[ $RC_APPLY -ne 0 ]]; then
                        APPLY_FAIL=1
                        [[ "$APPLY_FAIL_SAMPLE" == "N/A" ]] && APPLY_FAIL_SAMPLE="${user}@${host}"
                    fi
                done <<< "$USER_ROWS"

                if [[ $APPLY_FAIL -eq 0 ]]; then
                    STATUS="PASS"
                    ACTION_RESULT="SUCCESS"
                    ACTION_LOG="비밀번호 복잡도/사용기간 정책을 적용하고 기존 계정의 만료 주기까지 설정했습니다."
                    EVIDENCE="validate_password 정책, default_password_lifetime(${PW_LIFETIME_DAYS}), 기존 계정 PASSWORD EXPIRE INTERVAL(${EXISTING_USERS_EXPIRE_DAYS}) 적용이 완료되었습니다."
                else
                    ACTION_LOG="조치가 부분 실패했습니다. 기존 계정 일부에 만료 주기 적용이 실패했습니다."
                    EVIDENCE="정책 설정은 완료했으나 기존 계정 만료 주기 적용 중 실패 계정이 있습니다. (예: ${APPLY_FAIL_SAMPLE})"
                fi
            fi
        elif [[ $RC -eq 124 ]]; then
            ACTION_LOG="조치가 수행되지 않았습니다. 정책 설정 명령 실행이 제한 시간 내 완료되지 않아 중단하였습니다."
            EVIDENCE="정책 설정 명령 실행이 ${MYSQL_TIMEOUT_SEC}초 내에 완료되지 않아 무한 로딩 방지를 위해 처리를 중단하였습니다."
        else
            ACTION_LOG="조치가 수행되지 않았습니다. 비밀번호 정책 설정에 실패하였습니다."
            EVIDENCE="validate_password/default_password_lifetime 설정 명령 수행에 실패하였습니다."
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
