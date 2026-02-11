#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-07
# ============================================================================
# [점검 항목 상세]
# @ID          : D-10
# @Category    : DBMS (Database Management System)
# @Platform    : MySQL 8.0.44
# @IMPORTANCE  : 상
# @Title       : 원격에서 DB서버로의 접속 제한
# @Description : 지정된 IP주소만 DB 서버에 접근 가능하도록 설정되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-10"
CATEGORY="DBMS"
TITLE="원격에서 DB 서버로의 접속 제한"
IMPORTANCE="상"
IMPACT_LEVEL="MEDIUM"
ACTION_IMPACT="이 조치를 적용하면 허용되지 않은 IP에서의 접속이 차단되어, 기존에 모든 IP에서 접속 가능했던 계정은 지정된 IP에서만 접속할 수 있습니다. 이에 따라 기존 스크립트, 애플리케이션, 원격 관리 도구 등이 변경된 IP 외부에서 접속하려고 하면 실패할 수 있으므로, 적용 전에 영향 범위를 확인하고 필요한 IP를 사전에 반영해야 합니다."

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

# 예)
#   TARGET_USER='appuser' ALLOW_HOST='10.0.0.%' NEW_PASS='Strong!234' ./FIX_D10.sh
#   TARGET_USER='appuser' ALLOW_HOST='203.0.113.10' NEW_PASS='Strong!234' ./FIX_D10.sh
TARGET_USER="${TARGET_USER:-}"
ALLOW_HOST="${ALLOW_HOST:-}"     # 허용 IP 또는 대역(예: 10.0.0.%)
NEW_PASS="${NEW_PASS:-}"         # 새로 생성되는 '<user>'@'<ALLOW_HOST>' 계정 비밀번호
MODE="${MODE:-DROP}"             # DROP 또는 LOCK : 기존 '<user>'@'%' 처리 방식
# LOCK 모드 사용 예: MODE=LOCK ./FIX_D10.sh

if [[ -z "$TARGET_USER" || -z "$ALLOW_HOST" || -z "$NEW_PASS" ]]; then
    STATUS="FAIL"
    ACTION_RESULT="FAIL"
    ACTION_LOG="조치가 수행되지 않았습니다. 대상 계정 또는 허용 IP 정보가 제공되지 않았습니다."
    EVIDENCE="TARGET_USER, ALLOW_HOST, NEW_PASS 값이 누락되어 원격 접속 제한 조치를 수행할 수 없습니다."
else
    
    # 1) '<user>'@'%' 존재 여부 확인
    
    CHECK_WILD_SQL="SELECT COUNT(*) FROM mysql.user WHERE user='${TARGET_USER}' AND host='%';"
    WILD_CNT="$(run_mysql "$CHECK_WILD_SQL")"
    RC1=$?

    if [[ $RC1 -eq 124 ]]; then
        STATUS="FAIL"
        ACTION_RESULT="FAIL"
        ACTION_LOG="조치가 수행되지 않았습니다. 계정 조회 명령이 제한 시간 내 완료되지 않아 중단하였습니다."
        EVIDENCE="MySQL 명령 실행이 ${MYSQL_TIMEOUT_SEC}초 내에 완료되지 않아 대기 또는 지연이 발생하였으며, 무한 로딩 방지를 위해 처리를 중단하였습니다."
    elif [[ $RC1 -ne 0 || -z "$WILD_CNT" ]]; then
        STATUS="FAIL"
        ACTION_RESULT="FAIL"
        ACTION_LOG="조치가 수행되지 않았습니다. 대상 계정의 원격 허용 상태를 확인할 수 없습니다."
        EVIDENCE="mysql.user 조회에 실패하여 host='%' 계정 존재 여부를 확인할 수 없습니다."
    elif [[ "$WILD_CNT" -eq 0 ]]; then
        STATUS="PASS"
        ACTION_RESULT="SUCCESS"
        ACTION_LOG="대상 계정은 모든 IP(host='%')에서 접속 가능하도록 설정되어 있지 않아 추가 조치 없이 원격 접속 제한 상태를 유지하였습니다."
        EVIDENCE="mysql.user에서 ${TARGET_USER}@'%' 계정이 확인되지 않았습니다."
    else
        
        # 2) 허용 IP 전용 계정 생성(없으면 생성)
        
        CHECK_ALLOW_SQL="SELECT COUNT(*) FROM mysql.user WHERE user='${TARGET_USER}' AND host='${ALLOW_HOST}';"
        ALLOW_CNT="$(run_mysql "$CHECK_ALLOW_SQL")"
        RC2=$?

        if [[ $RC2 -eq 124 ]]; then
            STATUS="FAIL"
            ACTION_RESULT="FAIL"
            ACTION_LOG="조치가 수행되지 않았습니다. 허용 IP 계정 확인 명령이 제한 시간 내 완료되지 않아 중단하였습니다."
            EVIDENCE="허용 IP 계정 확인 명령 실행이 ${MYSQL_TIMEOUT_SEC}초 내에 완료되지 않아 무한 로딩 방지를 위해 처리를 중단하였습니다."
        elif [[ $RC2 -ne 0 || -z "$ALLOW_CNT" ]]; then
            STATUS="FAIL"
            ACTION_RESULT="FAIL"
            ACTION_LOG="조치가 수행되지 않았습니다. 허용 IP 계정 존재 여부를 확인할 수 없습니다."
            EVIDENCE="허용 IP 계정 조회에 실패하여 조치를 진행할 수 없습니다."
        else
            if [[ "$ALLOW_CNT" -eq 0 ]]; then
                CREATE_SQL="CREATE USER '${TARGET_USER}'@'${ALLOW_HOST}' IDENTIFIED BY '${NEW_PASS}';"
                run_mysql "$CREATE_SQL" >/dev/null
                RC3=$?

                if [[ $RC3 -eq 124 ]]; then
                    STATUS="FAIL"
                    ACTION_RESULT="FAIL"
                    ACTION_LOG="조치가 수행되지 않았습니다. 허용 IP 계정 생성 명령이 제한 시간 내 완료되지 않아 중단하였습니다."
                    EVIDENCE="허용 IP 계정 생성 명령 실행이 ${MYSQL_TIMEOUT_SEC}초 내에 완료되지 않아 무한 로딩 방지를 위해 처리를 중단하였습니다."
                elif [[ $RC3 -ne 0 ]]; then
                    STATUS="FAIL"
                    ACTION_RESULT="FAIL"
                    ACTION_LOG="조치가 수행되지 않았습니다. 허용 IP 전용 계정 생성에 실패하였습니다."
                    EVIDENCE="CREATE USER 명령 수행에 실패하여 ${TARGET_USER}@${ALLOW_HOST} 계정을 생성할 수 없습니다."
                fi
            fi

            
            # 3) 권한 복제: '<user>'@'%'의 권한을 '<user>'@'<ALLOW_HOST>'로 복사
            #    - SHOW GRANTS로 추출 후 실행
        
            if [[ "$STATUS" != "FAIL" ]]; then
                GRANTS_SQL="SHOW GRANTS FOR '${TARGET_USER}'@'%' ;"
                GRANTS_OUT="$(run_mysql "$GRANTS_SQL")"
                RC4=$?

                if [[ $RC4 -eq 124 ]]; then
                    STATUS="FAIL"
                    ACTION_RESULT="FAIL"
                    ACTION_LOG="조치가 수행되지 않았습니다. 권한 조회 명령이 제한 시간 내 완료되지 않아 중단하였습니다."
                    EVIDENCE="권한 조회 명령 실행이 ${MYSQL_TIMEOUT_SEC}초 내에 완료되지 않아 무한 로딩 방지를 위해 처리를 중단하였습니다."
                elif [[ $RC4 -ne 0 || -z "$GRANTS_OUT" ]]; then
                    STATUS="FAIL"
                    ACTION_RESULT="FAIL"
                    ACTION_LOG="조치가 수행되지 않았습니다. 기존 계정 권한을 조회할 수 없어 권한 복제를 수행하지 못하였습니다."
                    EVIDENCE="SHOW GRANTS 수행에 실패하여 권한 복제 절차를 진행할 수 없습니다."
                else
                    # GRANT 문장을 허용 호스트로 치환하여 실행
                    APPLY_FAIL=0
                    while read -r line; do
                        [[ -z "$line" ]] && continue
                        # GRANT ... TO 'user'@'%'  형태를 'user'@'ALLOW_HOST' 로 변경
                        NEW_LINE="$(echo "$line" | sed "s/'${TARGET_USER}'@'%'\$/'${TARGET_USER}'@'${ALLOW_HOST}'/")"
                        run_mysql "$NEW_LINE" >/dev/null
                        if [[ $? -ne 0 ]]; then
                            APPLY_FAIL=1
                        fi
                    done <<< "$GRANTS_OUT"

                    if [[ $APPLY_FAIL -eq 1 ]]; then
                        STATUS="FAIL"
                        ACTION_RESULT="FAIL"
                        ACTION_LOG="조치가 수행되지 않았습니다. 권한 복제 과정에서 일부 권한 적용에 실패하였습니다."
                        EVIDENCE="기존 계정의 권한을 허용 IP 계정에 복제하는 과정에서 오류가 발생하여 조치를 완료할 수 없습니다."
                    else
                        
                        # 4) 기존 '<user>'@'%' 제거 또는 잠금
                        
                        if [[ "$MODE" == "LOCK" ]]; then
                            # 계정 잠금(로그인 차단)
                            DISABLE_SQL="ALTER USER '${TARGET_USER}'@'%' ACCOUNT LOCK;"
                        else
                            # 계정 삭제(권한 포함 제거)
                            DISABLE_SQL="DROP USER '${TARGET_USER}'@'%';"
                        fi

                        run_mysql "$DISABLE_SQL" >/dev/null
                        RC5=$?

                        if [[ $RC5 -eq 124 ]]; then
                            STATUS="FAIL"
                            ACTION_RESULT="FAIL"
                            ACTION_LOG="조치가 수행되지 않았습니다. 기존 원격 허용 계정 처리 명령이 제한 시간 내 완료되지 않아 중단하였습니다."
                            EVIDENCE="기존 계정 처리 명령 실행이 ${MYSQL_TIMEOUT_SEC}초 내에 완료되지 않아 무한 로딩 방지를 위해 처리를 중단하였습니다."
                        elif [[ $RC5 -ne 0 ]]; then
                            STATUS="FAIL"
                            ACTION_RESULT="FAIL"
                            ACTION_LOG="조치가 수행되지 않았습니다. 기존 host='%' 계정 제거 또는 잠금에 실패하였습니다."
                            EVIDENCE="기존 원격 허용 계정(${TARGET_USER}@'%')을 처리하지 못하여 원격 접속 제한을 완료할 수 없습니다."
                        else
                            STATUS="PASS"
                            ACTION_RESULT="SUCCESS"
                            ACTION_LOG="모든 IP에서 접속 가능했던 계정을 허용된 IP에서만 접속 가능하도록 변경하여 원격 접속을 제한하였습니다."
                            if [[ "$MODE" == "LOCK" ]]; then
                                EVIDENCE="기존 ${TARGET_USER}@'%' 계정을 잠금 처리하고, ${TARGET_USER}@'${ALLOW_HOST}' 계정을 생성하여 권한을 복제하였습니다."
                            else
                                EVIDENCE="기존 ${TARGET_USER}@'%' 계정을 삭제하고, ${TARGET_USER}@'${ALLOW_HOST}' 계정을 생성하여 권한을 복제하였습니다."
                            fi
                        fi
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