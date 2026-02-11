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
IMPACT_LEVEL="LOW"
ACTION_IMPACT="이 조치를 적용하면 MySQL의 비밀번호 복잡도 정책이 강화되어 이후 생성되거나 변경되는 계정의 비밀번호가 정책에 맞게 설정되어야 합니다. 기존 계정의 비밀번호에는 즉각적인 영향이 없으나, 정책에 맞지 않는 비밀번호로 변경 시에는 거부되므로 비밀번호 변경 작업 시 주의가 필요합니다. 일반적인 시스템 운영에는 직접적인 영향이 없습니다."

STATUS="FAIL"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
EVIDENCE="N/A"

TIMEOUT_BIN="$(command -v timeout 2>/dev/null)"
MYSQL_TIMEOUT_SEC=5
MYSQL_CMD="mysql --connect-timeout=${MYSQL_TIMEOUT_SEC} -uroot -N -s -B -e"

run_sql() {
    local sql="$1"
    if [[ -n "$TIMEOUT_BIN" ]]; then
        $TIMEOUT_BIN "${MYSQL_TIMEOUT_SEC}s" $MYSQL_CMD "$sql" 2>/dev/null
    else
        $MYSQL_CMD "$sql" 2>/dev/null
    fi
    return $?
}

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
        SET_SQL="
SET GLOBAL validate_password.policy = 'MEDIUM';
SET GLOBAL validate_password.length = 8;
SET GLOBAL validate_password.mixed_case_count = 1;
SET GLOBAL validate_password.number_count = 1;
SET GLOBAL validate_password.special_char_count = 1;
SET GLOBAL default_password_lifetime = 90;
"
        run_sql "$SET_SQL"
        RC=$?
        if [[ $RC -eq 0 ]]; then
            STATUS="PASS"
            ACTION_RESULT="SUCCESS"
            ACTION_LOG="비밀번호 복잡도 및 사용 기간 정책을 기관 기준에 맞게 설정하였습니다."
            EVIDENCE="validate_password 정책 및 default_password_lifetime 설정이 적용되었습니다."
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
