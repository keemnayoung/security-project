#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 8.0.44
# @Author: 한은결
# @Last Updated: 2026-02-07
# ============================================================================
# [점검 항목 상세]
# @ID          : D-06
# @Category    : DBMS (Database Management System)
# @Platform    : MySQL 8.0.44
# @IMPORTANCE  : 중
# @Title       : DB 사용자 계정을 개별적으로 부여하여 사용
# @Description : DB 접근 시 사용자별로 서로 다른 계정을 사용하여 접근하는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-06"
CATEGORY="계정관리"
TITLE="DB 사용자 계정을 개별적으로 부여하여 사용"
IMPORTANCE="중"

# 조치 결과 변수
STATUS="FAIL"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
EVIDENCE="N/A"

# 무한 로딩 방지
TIMEOUT_BIN=""
MYSQL_TIMEOUT_SEC=5
MYSQL_CMD_BASE="mysql --protocol=TCP -uroot -N -s -B -e"

run_mysql() {
    local sql="$1"
    if [[ -n "$TIMEOUT_BIN" ]]; then
        $TIMEOUT_BIN ${MYSQL_TIMEOUT_SEC}s $MYSQL_CMD_BASE "$sql" 2>/dev/null
        return $?
    else
        $MYSQL_CMD_BASE "$sql" 2>/dev/null
        return $?
    fi
}

# 0) 입력값(환경변수) 확인
COMMON_USER="${COMMON_USER:-}"
COMMON_HOST="${COMMON_HOST:-}"

NEW_USER="${NEW_USER:-}"
NEW_HOST="${NEW_HOST:-}"
NEW_PASS="${NEW_PASS:-}"

PRIV_SCOPE="${PRIV_SCOPE:-}"      # TABLE | DB
DB_NAME="${DB_NAME:-}"
TABLE_NAME="${TABLE_NAME:-}"
PRIV_LIST="${PRIV_LIST:-}"        # 예: SELECT,INSERT  또는 ALL PRIVILEGES
RUN_FLUSH="${RUN_FLUSH:-Y}"       # D-06 MySQL 예시에 맞게 기본값은 Y

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

# 최소 입력값 체크
if [[ -z "$COMMON_USER" || -z "$COMMON_HOST" || -z "$NEW_USER" || -z "$NEW_HOST" || -z "$NEW_PASS" || -z "$PRIV_SCOPE" || -z "$DB_NAME" || -z "$PRIV_LIST" ]]; then
    STATUS="FAIL"
    ACTION_RESULT="FAIL"
    ACTION_LOG="조치가 수행되지 않았습니다. 공용 계정 및 신규 계정/권한 설정에 필요한 입력값이 제공되지 않았습니다."
    EVIDENCE="COMMON_USER, COMMON_HOST, NEW_USER, NEW_HOST, NEW_PASS, PRIV_SCOPE, DB_NAME, PRIV_LIST 값이 누락되어 조치를 수행할 수 없습니다."
else
    PRIV_SCOPE="$(echo "$PRIV_SCOPE" | tr '[:lower:]' '[:upper:]')"
    if [[ "$PRIV_SCOPE" == "TABLE" && -z "$TABLE_NAME" ]]; then
        STATUS="FAIL"
        ACTION_RESULT="FAIL"
        ACTION_LOG="조치가 수행되지 않았습니다. 테이블 단위 권한 부여를 위해 테이블명이 제공되지 않았습니다."
        EVIDENCE="PRIV_SCOPE=TABLE 설정 시 TABLE_NAME 값이 필요합니다."
    elif [[ "$PRIV_SCOPE" != "TABLE" && "$PRIV_SCOPE" != "DB" ]]; then
        STATUS="FAIL"
        ACTION_RESULT="FAIL"
        ACTION_LOG="조치가 수행되지 않았습니다. 권한 범위(PRIV_SCOPE) 값이 유효하지 않습니다."
        EVIDENCE="PRIV_SCOPE 값은 TABLE 또는 DB 중 하나여야 합니다."
    else
        esc_common_user="$(sql_escape_literal "$COMMON_USER")"
        esc_common_host="$(sql_escape_literal "$COMMON_HOST")"
        esc_new_user="$(sql_escape_literal "$NEW_USER")"
        esc_new_host="$(sql_escape_literal "$NEW_HOST")"
        esc_new_pass="$(sql_escape_literal "$NEW_PASS")"
        esc_db_name="$(ident_escape "$DB_NAME")"
        esc_table_name="$(ident_escape "$TABLE_NAME")"

        # D-06 핵심: 공용 계정을 삭제해 계정 공유 사용을 제거한다.

        DROP_SQL="DROP USER IF EXISTS '${esc_common_user}'@'${esc_common_host}';"
        run_mysql "$DROP_SQL"
        RC1=$?

        if [[ $RC1 -eq 124 ]]; then
            STATUS="FAIL"
            ACTION_RESULT="FAIL"
            ACTION_LOG="조치가 수행되지 않았습니다. 공용 계정 삭제 명령이 제한 시간 내 완료되지 않아 중단하였습니다."
            EVIDENCE="MySQL 명령 실행이 ${MYSQL_TIMEOUT_SEC}초 내에 완료되지 않아 무한 로딩 방지를 위해 처리를 중단하였습니다."
        elif [[ $RC1 -ne 0 ]]; then
            STATUS="FAIL"
            ACTION_RESULT="FAIL"
            ACTION_LOG="조치가 수행되지 않았습니다. 공용 계정 삭제에 실패하였습니다."
            EVIDENCE="공용 계정 삭제(DROP USER) 명령 수행에 실패하여 조치를 진행할 수 없습니다."
        else

            # D-06 핵심: 사용자/응용프로그램별 개별 계정을 생성한다.

            CREATE_SQL="CREATE USER IF NOT EXISTS '${esc_new_user}'@'${esc_new_host}' IDENTIFIED BY '${esc_new_pass}';"
            run_mysql "$CREATE_SQL"
            RC2=$?

            if [[ $RC2 -eq 124 ]]; then
                STATUS="FAIL"
                ACTION_RESULT="FAIL"
                ACTION_LOG="조치가 수행되지 않았습니다. 신규 계정 생성 명령이 제한 시간 내 완료되지 않아 중단하였습니다."
                EVIDENCE="신규 계정 생성 명령 실행이 ${MYSQL_TIMEOUT_SEC}초 내에 완료되지 않아 무한 로딩 방지를 위해 처리를 중단하였습니다."
            elif [[ $RC2 -ne 0 ]]; then
                STATUS="FAIL"
                ACTION_RESULT="FAIL"
                ACTION_LOG="조치가 수행되지 않았습니다. 사용자별 계정 생성에 실패하였습니다."
                EVIDENCE="CREATE USER 명령 수행에 실패하여 사용자별 계정을 생성할 수 없습니다."
            else

                # D-06 핵심: 목적에 맞는 범위로 권한을 부여한다(최소 권한 원칙).

                if [[ "$PRIV_SCOPE" == "TABLE" ]]; then
                    GRANT_SQL="GRANT ${PRIV_LIST} ON \`${esc_db_name}\`.\`${esc_table_name}\` TO '${esc_new_user}'@'${esc_new_host}';"
                else
                    GRANT_SQL="GRANT ${PRIV_LIST} ON \`${esc_db_name}\`.* TO '${esc_new_user}'@'${esc_new_host}';"
                fi

                run_mysql "$GRANT_SQL"
                RC3=$?

                if [[ $RC3 -eq 124 ]]; then
                    STATUS="FAIL"
                    ACTION_RESULT="FAIL"
                    ACTION_LOG="조치가 수행되지 않았습니다. 권한 부여 명령이 제한 시간 내 완료되지 않아 중단하였습니다."
                    EVIDENCE="권한 부여 명령 실행이 ${MYSQL_TIMEOUT_SEC}초 내에 완료되지 않아 무한 로딩 방지를 위해 처리를 중단하였습니다."
                elif [[ $RC3 -ne 0 ]]; then
                    STATUS="FAIL"
                    ACTION_RESULT="FAIL"
                    ACTION_LOG="조치가 수행되지 않았습니다. 사용자별 계정에 대한 권한 부여에 실패하였습니다."
                    EVIDENCE="GRANT 명령 수행에 실패하여 최소 권한 정책을 적용할 수 없습니다."
                else
                    # D-06 핵심: 권한 변경 사항을 즉시 반영하기 위해 FLUSH PRIVILEGES를 수행한다.

                    if [[ "$RUN_FLUSH" == "Y" ]]; then
                        FLUSH_SQL="FLUSH PRIVILEGES;"
                        run_mysql "$FLUSH_SQL" >/dev/null 2>&1
                        RC4=$?
                        if [[ $RC4 -eq 124 ]]; then
                            STATUS="FAIL"
                            ACTION_RESULT="FAIL"
                            ACTION_LOG="조치가 수행되지 않았습니다. 권한 반영 명령이 제한 시간 내 완료되지 않아 중단하였습니다."
                            EVIDENCE="FLUSH PRIVILEGES 실행이 ${MYSQL_TIMEOUT_SEC}초 내 완료되지 않아 조치를 완료하지 못했습니다."
                        elif [[ $RC4 -ne 0 ]]; then
                            STATUS="FAIL"
                            ACTION_RESULT="FAIL"
                            ACTION_LOG="조치가 부분 실패했습니다. 계정 생성 및 권한 부여는 수행했으나 권한 반영에 실패했습니다."
                            EVIDENCE="DROP/CREATE/GRANT 수행 후 FLUSH PRIVILEGES 실행에 실패했습니다."
                        fi
                    fi

                    if [[ "$STATUS" != "FAIL" ]]; then
                        STATUS="PASS"
                        ACTION_RESULT="SUCCESS"
                        ACTION_LOG="공용 계정을 삭제하고 사용자별·응용프로그램별 계정을 생성한 후 필요한 권한만 부여하여 계정 공유 사용을 방지하였습니다."
                        EVIDENCE="공용 계정 삭제, 신규 계정 생성, 권한 부여 및 FLUSH PRIVILEGES까지 정상 수행되었습니다."
                    fi
                fi
            fi
        fi
    fi
fi

# JSON 표준 출력 (고정 구조)
echo ""
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
