#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-11
# ============================================================================
# [점검 항목 상세]
# @ID          : D-01
# @Category    : DBMS (Database Management System)
# @Platform    : MySQL
# @IMPORTANCE  : 상
# @Title       : 기본 계정의 비밀번호, 정책 등을 변경하여 사용
# @Description : 기본 root 계정의 비밀번호를 변경하여 초기/약한 비밀번호 사용을 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-01"
CATEGORY="계정관리"
TITLE="기본 계정의 비밀번호, 정책 등을 변경하여 사용"
IMPORTANCE="상"
IMPACT_LEVEL="MEDIUM"
ACTION_IMPACT="이 조치를 적용하면 root 계정 비밀번호가 변경되어 기존에 저장되어 있던 자동화 스크립트, 애플리케이션 설정 파일, 배치 작업, 모니터링 도구 등에서 사용 중이던 기존 비밀번호로는 더 이상 접속이 불가능해집니다. 이로 인해 DB 연동 서비스 또는 관리 작업이 일시적으로 실패할 수 있으며, 관련 시스템 전반에 비밀번호 변경 사항을 반영해야 정상 운영이 가능합니다."

STATUS="FAIL"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
EVIDENCE="N/A"

TIMEOUT_BIN="$(command -v timeout 2>/dev/null)"
MYSQL_TIMEOUT_SEC=5
MYSQL_CMD="mysql --connect-timeout=${MYSQL_TIMEOUT_SEC} --protocol=TCP -uroot -N -s -B -e"

run_mysql_query() {
    local sql="$1"
    if [[ -n "$TIMEOUT_BIN" ]]; then
        $TIMEOUT_BIN "${MYSQL_TIMEOUT_SEC}s" $MYSQL_CMD "$sql" 2>/dev/null
        return $?
    fi
    $MYSQL_CMD "$sql" 2>/dev/null
    return $?
}

if [[ -z "${NEW_PASS:-}" ]]; then
    ACTION_LOG="조치가 수행되지 않았습니다. 변경할 신규 비밀번호(NEW_PASS)가 제공되지 않았습니다."
    EVIDENCE="환경변수 NEW_PASS가 설정되지 않아 root 계정 비밀번호 변경을 수행할 수 없습니다."
elif [[ "$NEW_PASS" == *"'"* ]]; then
    ACTION_LOG="조치가 수행되지 않았습니다. 신규 비밀번호에 작은따옴표(')가 포함되어 SQL 실행이 안전하지 않습니다."
    EVIDENCE="NEW_PASS 값 검증에 실패하여 조치를 중단하였습니다."
elif [[ ${#NEW_PASS} -lt 8 ]]; then
    ACTION_LOG="조치가 수행되지 않았습니다. 신규 비밀번호 길이가 기준(8자 이상)에 부합하지 않습니다."
    EVIDENCE="NEW_PASS 길이가 8자 미만이므로 비밀번호 변경을 중단하였습니다."
else
    ROOT_ROWS="$(run_mysql_query "SELECT user, host FROM mysql.user WHERE user='root';")"
    RC=$?

    if [[ $RC -eq 124 ]]; then
        ACTION_LOG="조치가 수행되지 않았습니다. root 계정 목록 조회가 제한 시간 내 완료되지 않아 중단하였습니다."
        EVIDENCE="MySQL 명령 실행이 ${MYSQL_TIMEOUT_SEC}초 내에 완료되지 않아 대기 또는 지연이 발생하였으며, 무한 로딩 방지를 위해 처리를 중단하였습니다."
    elif [[ $RC -ne 0 ]]; then
        ACTION_LOG="조치가 수행되지 않았습니다. MySQL 접속 실패 또는 권한 부족으로 root 계정 목록 조회에 실패하였습니다."
        EVIDENCE="mysql.user 조회에 실패하여 기본 계정 조치를 수행할 수 없습니다."
    elif [[ -z "$ROOT_ROWS" ]]; then
        ACTION_LOG="조치가 수행되지 않았습니다. root 계정을 찾을 수 없어 조치를 적용하지 못했습니다."
        EVIDENCE="root 기본 계정이 조회되지 않아 비밀번호 변경 조치를 중단하였습니다."
    else
        FAIL_REASON=""

        while IFS=$'\t' read -r user host; do
            [[ -z "$user" && -z "$host" ]] && continue

            run_mysql_query "ALTER USER '${user}'@'${host}' IDENTIFIED BY '${NEW_PASS}';" >/dev/null
            RC=$?
            if [[ $RC -eq 124 ]]; then
                FAIL_REASON="root@${host} 비밀번호 변경 명령이 시간 초과되었습니다."
                break
            elif [[ $RC -ne 0 ]]; then
                FAIL_REASON="root@${host} 비밀번호 변경에 실패했습니다."
                break
            fi

            case "$host" in
                localhost|127.0.0.1|::1)
                    ;;
                *)
                    run_mysql_query "ALTER USER '${user}'@'${host}' ACCOUNT LOCK;" >/dev/null
                    RC=$?
                    if [[ $RC -eq 124 ]]; then
                        FAIL_REASON="root@${host} 잠금 명령이 시간 초과되었습니다."
                        break
                    elif [[ $RC -ne 0 ]]; then
                        FAIL_REASON="root@${host} 잠금 처리에 실패했습니다."
                        break
                    fi
                    ;;
            esac
        done <<< "$ROOT_ROWS"

        if [[ -z "$FAIL_REASON" ]]; then
            ANON_ROWS="$(run_mysql_query "SELECT host FROM mysql.user WHERE user='';")"
            RC=$?

            if [[ $RC -eq 124 ]]; then
                FAIL_REASON="익명 계정 목록 조회가 시간 초과되었습니다."
            elif [[ $RC -ne 0 ]]; then
                FAIL_REASON="익명 계정 목록 조회에 실패했습니다."
            elif [[ -n "$ANON_ROWS" ]]; then
                while IFS= read -r host; do
                    [[ -z "$host" ]] && continue
                    run_mysql_query "ALTER USER ''@'${host}' ACCOUNT LOCK;" >/dev/null
                    RC=$?
                    if [[ $RC -eq 124 ]]; then
                        FAIL_REASON="익명 계정(''@${host}) 잠금 명령이 시간 초과되었습니다."
                        break
                    elif [[ $RC -ne 0 ]]; then
                        FAIL_REASON="익명 계정(''@${host}) 잠금 처리에 실패했습니다."
                        break
                    fi
                done <<< "$ANON_ROWS"
            fi
        fi

        if [[ -z "$FAIL_REASON" ]]; then
            STATUS="PASS"
            ACTION_RESULT="SUCCESS"
            ACTION_LOG="root 계정 비밀번호 변경을 완료했고, 원격 root/익명 계정은 잠금하여 기본 계정 정책을 적용했습니다."
            EVIDENCE="기본 계정 조치 완료: root 비밀번호 변경 및 불필요 기본 계정(원격 root/익명) 잠금이 정상 수행되었습니다."
        else
            ACTION_LOG="조치가 수행되지 않았습니다. ${FAIL_REASON}"
            EVIDENCE="기본 계정 조치 중 오류가 발생하여 전체 정책 적용을 완료하지 못했습니다."
        fi
    fi
fi

cat << EOF
{
    "check_id": "$ID",
    "action_impact": "$ACTION_IMPACT",
    "impact_level": "$IMPACT_LEVEL",
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
