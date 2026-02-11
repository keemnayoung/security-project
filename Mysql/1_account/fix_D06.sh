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
IMPACT_LEVEL="LOW"
ACTION_IMPACT="이 조치를 적용하면 공용 계정이 삭제되고, 사용자별·응용 프로그램별 계정으로 대체됩니다. 일반적인 시스템 운영에는 영향이 없으며, 각 계정에 적절한 권한이 부여되어 있어 정상적인 데이터베이스 접근과 작업 수행이 가능합니다. 다만, 모든 권한을 부여한 계정은 보안 위험이 증가할 수 있으므로 최소 권한 원칙을 준수하여 설정해야 합니다."

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
COMMON_USER="${COMMON_USER:-}"
COMMON_HOST="${COMMON_HOST:-}"

NEW_USER="${NEW_USER:-}"
NEW_HOST="${NEW_HOST:-}"
NEW_PASS="${NEW_PASS:-}"

PRIV_SCOPE="${PRIV_SCOPE:-}"      # TABLE | DB
DB_NAME="${DB_NAME:-}"
TABLE_NAME="${TABLE_NAME:-}"
PRIV_LIST="${PRIV_LIST:-}"        # 예: SELECT,INSERT  또는 ALL PRIVILEGES
RUN_FLUSH="${RUN_FLUSH:-N}"       # Y면 flush privileges 실행

# 최소 입력값 체크
if [[ -z "$COMMON_USER" || -z "$COMMON_HOST" || -z "$NEW_USER" || -z "$NEW_HOST" || -z "$NEW_PASS" || -z "$PRIV_SCOPE" || -z "$DB_NAME" || -z "$PRIV_LIST" ]]; then
    STATUS="FAIL"
    ACTION_RESULT="FAIL"
    ACTION_LOG="조치가 수행되지 않았습니다. 공용 계정 및 신규 계정/권한 설정에 필요한 입력값이 제공되지 않았습니다."
    EVIDENCE="COMMON_USER, COMMON_HOST, NEW_USER, NEW_HOST, NEW_PASS, PRIV_SCOPE, DB_NAME, PRIV_LIST 값이 누락되어 조치를 수행할 수 없습니다."
else
    if [[ "$PRIV_SCOPE" == "TABLE" && -z "$TABLE_NAME" ]]; then
        STATUS="FAIL"
        ACTION_RESULT="FAIL"
        ACTION_LOG="조치가 수행되지 않았습니다. 테이블 단위 권한 부여를 위해 테이블명이 제공되지 않았습니다."
        EVIDENCE="PRIV_SCOPE=TABLE 설정 시 TABLE_NAME 값이 필요합니다."
    else

        # 1) 공용 계정 삭제

        DROP_SQL="DROP USER IF EXISTS '${COMMON_USER}'@'${COMMON_HOST}';"
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

            # 2) 사용자/응용프로그램별 계정 생성

            CREATE_SQL="CREATE USER IF NOT EXISTS '${NEW_USER}'@'${NEW_HOST}' IDENTIFIED BY '${NEW_PASS}';"
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

                # 3) 권한 설정(최소 권한 원칙 권장)

                if [[ "$PRIV_SCOPE" == "TABLE" ]]; then
                    GRANT_SQL="GRANT ${PRIV_LIST} ON \`${DB_NAME}\`.\`${TABLE_NAME}\` TO '${NEW_USER}'@'${NEW_HOST}';"
                else
                    GRANT_SQL="GRANT ${PRIV_LIST} ON \`${DB_NAME}\`.* TO '${NEW_USER}'@'${NEW_HOST}';"
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
                    # 4) (선택) FLUSH PRIVILEGES

                    if [[ "$RUN_FLUSH" == "Y" ]]; then
                        FLUSH_SQL="FLUSH PRIVILEGES;"
                        run_mysql "$FLUSH_SQL" >/dev/null 2>&1
                        # MySQL 8.0에서 필수는 아니므로 실패해도 조치 자체는 완료로 처리
                    fi

                    STATUS="PASS"
                    ACTION_RESULT="SUCCESS"
                    ACTION_LOG="공용 계정을 삭제하고 사용자별·응용프로그램별 계정을 생성한 후 필요한 권한만 부여하여 계정 공유 사용을 방지하였습니다."
                    EVIDENCE="공용 계정 삭제 및 신규 계정 생성과 권한 부여가 정상 수행되어 개별 계정 사용 체계가 적용되었습니다."
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

