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
IMPACT_LEVEL="LOW"
ACTION_IMPACT="이 조치를 적용하면 일반 사용자 계정은 시스템 테이블에 접근할 수 없게 되지만, 지정된 데이터베이스 및 테이블에 대한 권한은 그대로 유지됩니다. 따라서 일반적인 시스템 운영 및 애플리케이션 동작에는 영향이 없으며, 권한 범위를 벗어난 작업 시에만 접근이 제한됩니다."

# 조치 결과 변수
STATUS="FAIL"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
EVIDENCE="N/A"

# 무한 로딩 방지
TIMEOUT_BIN="$(command -v timeout 2>/dev/null)"
MYSQL_TIMEOUT_SEC=5
MYSQL_CMD_BASE="mysql --connect-timeout=${MYSQL_TIMEOUT_SEC} -uroot -N -s -B -e"

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

# 예1) 특정 테이블에만 최소 권한 부여
#   TARGET_USER='appuser' TARGET_HOST='10.0.0.%' \
#   KEEP_SCOPE='TABLE' KEEP_DB='appdb' KEEP_TABLE='orders' KEEP_PRIV_LIST='SELECT,INSERT' \
#   ./FIX_D11.sh
#
# 예2) 특정 DB 전체 테이블에 권한 부여(필요 최소 권한 권장)
#   TARGET_USER='appuser' TARGET_HOST='10.0.0.%' \
#   KEEP_SCOPE='DB' KEEP_DB='appdb' KEEP_PRIV_LIST='SELECT,INSERT,UPDATE' \
#   ./FIX_D11.sh
#
# 예3) 시스템 테이블 권한 회수만 수행(권한 부여 생략)
#   TARGET_USER='appuser' TARGET_HOST='10.0.0.%' \
#   KEEP_SCOPE='NONE' \
#   ./FIX_D11.sh

TARGET_USER="${TARGET_USER:-}"
TARGET_HOST="${TARGET_HOST:-}"

KEEP_SCOPE="${KEEP_SCOPE:-}"          # TABLE | DB | NONE
KEEP_DB="${KEEP_DB:-}"
KEEP_TABLE="${KEEP_TABLE:-}"
KEEP_PRIV_LIST="${KEEP_PRIV_LIST:-}"  # 예: SELECT,INSERT

if [[ -z "$TARGET_USER" || -z "$TARGET_HOST" || -z "$KEEP_SCOPE" ]]; then
    STATUS="FAIL"
    ACTION_RESULT="FAIL"
    ACTION_LOG="조치가 수행되지 않았습니다. 대상 계정 또는 권한 유지 범위 정보가 제공되지 않았습니다."
    EVIDENCE="TARGET_USER, TARGET_HOST, KEEP_SCOPE 값이 누락되어 시스템 테이블 접근 제한 조치를 수행할 수 없습니다."
else
    if [[ "$KEEP_SCOPE" == "TABLE" && ( -z "$KEEP_DB" || -z "$KEEP_TABLE" || -z "$KEEP_PRIV_LIST" ) ]]; then
        STATUS="FAIL"
        ACTION_RESULT="FAIL"
        ACTION_LOG="조치가 수행되지 않았습니다. 테이블 단위 권한 부여에 필요한 정보가 제공되지 않았습니다."
        EVIDENCE="KEEP_SCOPE=TABLE 설정 시 KEEP_DB, KEEP_TABLE, KEEP_PRIV_LIST 값이 필요합니다."
    elif [[ "$KEEP_SCOPE" == "DB" && ( -z "$KEEP_DB" || -z "$KEEP_PRIV_LIST" ) ]]; then
        STATUS="FAIL"
        ACTION_RESULT="FAIL"
        ACTION_LOG="조치가 수행되지 않았습니다. DB 단위 권한 부여에 필요한 정보가 제공되지 않았습니다."
        EVIDENCE="KEEP_SCOPE=DB 설정 시 KEEP_DB, KEEP_PRIV_LIST 값이 필요합니다."
    else

        # 1) 기존 권한 확인 (SHOW GRANTS)

        GRANTS_SQL="SHOW GRANTS FOR '${TARGET_USER}'@'${TARGET_HOST}';"
        GRANTS_OUT="$(run_mysql "$GRANTS_SQL")"
        RC1=$?

        if [[ $RC1 -eq 124 ]]; then
            STATUS="FAIL"
            ACTION_RESULT="FAIL"
            ACTION_LOG="조치가 수행되지 않았습니다. 권한 확인 명령이 제한 시간 내 완료되지 않아 중단하였습니다."
            EVIDENCE="MySQL 명령 실행이 ${MYSQL_TIMEOUT_SEC}초 내에 완료되지 않아 대기 또는 지연이 발생하였으며, 무한 로딩 방지를 위해 처리를 중단하였습니다."
        elif [[ $RC1 -ne 0 || -z "$GRANTS_OUT" ]]; then
            STATUS="FAIL"
            ACTION_RESULT="FAIL"
            ACTION_LOG="조치가 수행되지 않았습니다. 대상 계정의 권한을 확인할 수 없어 조치를 진행하지 못하였습니다."
            EVIDENCE="SHOW GRANTS 수행에 실패하여 시스템 테이블 접근 권한 회수 여부를 판단할 수 없습니다."
        else

            # 2) 시스템 스키마 접근 권한 회수

            # 시스템 스키마 목록(MySQL 8.0 기준)
            SYS_SCHEMAS=("mysql" "information_schema" "performance_schema" "sys")

            REVOKE_FAIL=0
            for schema in "${SYS_SCHEMAS[@]}"; do
                # 스키마 단위로 가능한 권한을 회수 (ALL, GRANT OPTION 포함)
                # - 실제로 부여되어 있지 않으면 에러가 날 수 있으므로, 실패해도 계속 진행하되 최종 결과에 반영
                REVOKE_SQL="REVOKE ALL PRIVILEGES, GRANT OPTION ON \`${schema}\`.* FROM '${TARGET_USER}'@'${TARGET_HOST}';"
                run_mysql "$REVOKE_SQL" >/dev/null
                RC2=$?
                if [[ $RC2 -eq 124 ]]; then
                    REVOKE_FAIL=1
                    break
                fi
            done

            if [[ $REVOKE_FAIL -eq 1 ]]; then
                STATUS="FAIL"
                ACTION_RESULT="FAIL"
                ACTION_LOG="조치가 수행되지 않았습니다. 시스템 테이블 권한 회수 명령이 제한 시간 내 완료되지 않아 중단하였습니다."
                EVIDENCE="시스템 스키마 권한 회수 명령 실행이 ${MYSQL_TIMEOUT_SEC}초 내에 완료되지 않아 무한 로딩 방지를 위해 처리를 중단하였습니다."
            else

                # 3) 필요한 DB/테이블에만 최소 권한 부여(선택)
  
                if [[ "$KEEP_SCOPE" == "NONE" ]]; then
                    STATUS="PASS"
                    ACTION_RESULT="SUCCESS"
                    ACTION_LOG="시스템 테이블에 대한 불필요한 접근 권한을 회수하여 일반 계정의 시스템 테이블 접근을 제한하였습니다."
                    EVIDENCE="대상 계정(${TARGET_USER}@${TARGET_HOST})에서 시스템 스키마(mysql, information_schema, performance_schema, sys) 접근 권한 회수를 수행하였습니다."
                else
                    if [[ "$KEEP_SCOPE" == "TABLE" ]]; then
                        GRANT_SQL="GRANT ${KEEP_PRIV_LIST} ON \`${KEEP_DB}\`.\`${KEEP_TABLE}\` TO '${TARGET_USER}'@'${TARGET_HOST}';"
                        KEEP_DESC="필요한 테이블(${KEEP_DB}.${KEEP_TABLE})에만 권한을 부여"
                    else
                        GRANT_SQL="GRANT ${KEEP_PRIV_LIST} ON \`${KEEP_DB}\`.* TO '${TARGET_USER}'@'${TARGET_HOST}';"
                        KEEP_DESC="필요한 데이터베이스(${KEEP_DB}) 범위 내에서만 권한을 부여"
                    fi

                    run_mysql "$GRANT_SQL" >/dev/null
                    RC3=$?

                    if [[ $RC3 -eq 124 ]]; then
                        STATUS="FAIL"
                        ACTION_RESULT="FAIL"
                        ACTION_LOG="조치가 수행되지 않았습니다. 필요 권한 부여 명령이 제한 시간 내 완료되지 않아 중단하였습니다."
                        EVIDENCE="권한 부여 명령 실행이 ${MYSQL_TIMEOUT_SEC}초 내에 완료되지 않아 무한 로딩 방지를 위해 처리를 중단하였습니다."
                    elif [[ $RC3 -ne 0 ]]; then
                        STATUS="FAIL"
                        ACTION_RESULT="FAIL"
                        ACTION_LOG="조치가 수행되지 않았습니다. 필요한 데이터베이스/테이블 권한 부여에 실패하였습니다."
                        EVIDENCE="시스템 스키마 권한 회수는 수행되었으나, 업무에 필요한 권한 부여에 실패하여 정상 동작을 보장할 수 없습니다."
                    else
                        STATUS="PASS"
                        ACTION_RESULT="SUCCESS"
                        ACTION_LOG="시스템 테이블 접근 권한을 회수하고, ${KEEP_DESC}하여 일반 사용자 계정의 접근 범위를 최소화하였습니다."
                        EVIDENCE="대상 계정(${TARGET_USER}@${TARGET_HOST})의 시스템 스키마 접근 권한을 제한하고, 지정된 범위에 필요한 권한만 부여하였습니다."
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
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "KISA 가이드라인 기준 보안 설정 조치 완료",
    "action_result": "$ACTION_RESULT",
    "action_log": "$ACTION_LOG",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF