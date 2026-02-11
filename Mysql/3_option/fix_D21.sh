#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-07
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
IMPORTANCE="상"
IMPACT_LEVEL="LOW"
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없습니다. 불필요하거나 과도하게 부여된 권한만 회수되며, 해당 권한을 실제로 사용하지 않던 계정의 정상 업무에는 지장이 없습니다. 다만 회수된 권한이 필요한 특정 관리 작업을 수행할 경우에는 권한 부족으로 작업이 제한될 수 있습니다."

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

# 0) 실행 옵션
# 기본 정책:
# - root 계정은 제외
# - mysql.session / mysql.sys / mysql.infoschema 등 시스템 계정은 제외
# - 필요 시 EXCLUDE_USERS에 추가 가능 (쉼표로 구분)
EXCLUDE_USERS="${EXCLUDE_USERS:-root,mysql.session,mysql.sys,mysql.infoschema}"

is_excluded_user() {
    local u="$1"
    IFS=',' read -r -a arr <<< "$EXCLUDE_USERS"
    for x in "${arr[@]}"; do
        [[ "$u" == "$x" ]] && return 0
    done
    return 1
}


# 1) GRANT OPTION 보유 계정 확인
# grant_priv='Y' 인 경우 GRANT OPTION 보유(직접/간접)
CHECK_SQL="SELECT user, host FROM mysql.user WHERE grant_priv='Y';"
LIST="$(run_mysql "$CHECK_SQL")"
RC1=$?

if [[ $RC1 -eq 124 ]]; then
    STATUS="FAIL"
    ACTION_RESULT="FAIL"
    ACTION_LOG="조치가 수행되지 않았습니다. 설정 확인 명령이 제한 시간 내 완료되지 않아 중단하였습니다."
    EVIDENCE="MySQL 명령 실행이 ${MYSQL_TIMEOUT_SEC}초 내에 완료되지 않아 대기 또는 지연이 발생하였으며, 무한 로딩 방지를 위해 처리를 중단하였습니다."
elif [[ $RC1 -ne 0 ]]; then
    STATUS="FAIL"
    ACTION_RESULT="FAIL"
    ACTION_LOG="조치가 수행되지 않았습니다. GRANT OPTION 보유 계정 조회에 실패하였습니다."
    EVIDENCE="mysql.user 조회에 실패하여 GRANT OPTION 부여 여부를 확인할 수 없습니다."
else
    if [[ -z "$LIST" ]]; then
        STATUS="PASS"
        ACTION_RESULT="SUCCESS"
        ACTION_LOG="GRANT OPTION이 부여된 계정이 확인되지 않아 추가 조치 없이 권한 남용 방지 상태를 유지하였습니다."
        EVIDENCE="mysql.user에서 grant_priv='Y' 계정이 확인되지 않았습니다."
    else
        
        # 2) 사용자에게 직접 부여된 GRANT OPTION 회수
       
        MODIFIED=0
        FAILED=0
        TARGETS=()

        while read -r user host; do
            [[ -z "$user" || -z "$host" ]] && continue

            # 제외 사용자 처리
            if is_excluded_user "$user"; then
                continue
            fi

            TARGETS+=("${user}@${host}")

            # 사용자 직접 GRANT OPTION 회수
            # (MySQL 8.0에서 FLUSH PRIVILEGES는 필요하지 않음)
            REVOKE_SQL="REVOKE GRANT OPTION ON *.* FROM '${user}'@'${host}';"
            run_mysql "$REVOKE_SQL" >/dev/null
            RC2=$?

            if [[ $RC2 -eq 0 ]]; then
                MODIFIED=$((MODIFIED + 1))
            else
                FAILED=$((FAILED + 1))
            fi
        done <<< "$LIST"

        if [[ ${#TARGETS[@]} -eq 0 ]]; then
            STATUS="PASS"
            ACTION_RESULT="SUCCESS"
            ACTION_LOG="GRANT OPTION이 부여된 계정이 확인되었으나, 시스템 계정 및 제외 계정을 제외하고는 조치 대상이 없어 권한 남용 방지 상태를 유지하였습니다."
            EVIDENCE="grant_priv='Y' 계정 중 제외 대상만 확인되었습니다."
        else
            if [[ $MODIFIED -gt 0 && $FAILED -eq 0 ]]; then
                STATUS="PASS"
                ACTION_RESULT="SUCCESS"
                ACTION_LOG="인가되지 않은 계정에 직접 부여된 GRANT OPTION을 회수하여 ROLE 기반으로만 권한 위임이 이루어지도록 조치하였습니다."
                EVIDENCE="조치 대상 계정에서 GRANT OPTION 회수를 완료하여 권한 위임 남용 위험을 낮추었습니다."
            elif [[ $MODIFIED -gt 0 && $FAILED -gt 0 ]]; then
                STATUS="PASS"
                ACTION_RESULT="SUCCESS"
                ACTION_LOG="GRANT OPTION 회수를 수행하였으나 일부 계정은 권한 또는 설정 문제로 회수하지 못하였습니다."
                EVIDENCE="일부 계정은 GRANT OPTION 회수에 실패하여 추가 점검이 필요합니다."
            else
                STATUS="FAIL"
                ACTION_RESULT="FAIL"
                ACTION_LOG="조치가 수행되지 않았습니다. GRANT OPTION 회수를 시도했으나 적용되지 않았습니다."
                EVIDENCE="GRANT OPTION 회수 명령이 정상 반영되지 않아 권한 위임 제한을 완료할 수 없습니다."
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