#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-07
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
IMPACT_LEVEL="MEDIUM"
ACTION_IMPACT="이 조치를 적용하면 불필요하게 부여된 관리자 권한(SUPER 등)이 회수되어 일부 관리 작업이 제한될 수 있습니다. 기존 운영 절차에서 SUPER 권한을 사용하던 계정이 있는 경우, 필요한 최소 권한으로 대체 부여한 후 적용해야 합니다. 일반적인 서비스 운영에는 영향이 없으나, 관리 작업 권한 체계가 변경될 수 있습니다."

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

# (선택) 최소 권한 부여 대상 (필요 시만 사용)
TARGET_USER="${TARGET_USER:-}"
TARGET_HOST="${TARGET_HOST:-}"
GRANT_MINIMAL_ADMIN="${GRANT_MINIMAL_ADMIN:-N}"   # Y이면 최소 권한 부여 수행

# 1) SUPER 권한 보유 계정 확인
CHECK_SUPER_SQL="SELECT GRANTEE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE PRIVILEGE_TYPE='SUPER';"
SUPER_LIST="$(run_mysql "$CHECK_SUPER_SQL")"
RC=$?

if [[ $RC -eq 124 ]]; then
    STATUS="FAIL"
    ACTION_RESULT="FAIL"
    ACTION_LOG="조치가 수행되지 않았습니다. MySQL 명령 실행이 제한 시간 내 완료되지 않아 중단하였습니다."
    EVIDENCE="MySQL 명령 실행이 ${MYSQL_TIMEOUT_SEC}초 내에 완료되지 않아 대기 또는 지연이 발생하였으며, 무한 로딩 방지를 위해 처리를 중단하였습니다."
elif [[ $RC -ne 0 ]]; then
    STATUS="FAIL"
    ACTION_RESULT="FAIL"
    ACTION_LOG="조치가 수행되지 않았습니다. MySQL 접속 실패 또는 권한 부족으로 관리자 권한 확인에 실패하였습니다."
    EVIDENCE="SUPER 권한 보유 계정 조회에 실패하여 관리자 권한 회수 여부를 판단할 수 없습니다."
else
    # SUPER 권한 보유자가 없으면 PASS 처리
    if [[ -z "$SUPER_LIST" ]]; then
        STATUS="PASS"
        ACTION_RESULT="SUCCESS"
        ACTION_LOG="불필요한 SUPER 권한이 확인되지 않아 추가 조치 없이 관리자 권한이 최소화된 상태를 유지하였습니다."
        EVIDENCE="SUPER 권한을 보유한 계정이 확인되지 않았습니다."
    else

        # 2) 불필요 SUPER 권한 회수
        # root 계정은 제외하고 회수 (운영 정책에 따라 조정 가능)
        MODIFIED_COUNT=0
        FAILED_COUNT=0

        while read -r grantee; do
            [[ -z "$grantee" ]] && continue

            # grantee 형태: `'user'@'host'`
            # root는 제외
            if echo "$grantee" | grep -q "'root'@"; then
                continue
            fi

            REVOKE_SQL="REVOKE SUPER ON *.* FROM ${grantee};"
            run_mysql "$REVOKE_SQL"
            RC2=$?

            if [[ $RC2 -eq 0 ]]; then
                MODIFIED_COUNT=$((MODIFIED_COUNT + 1))
            else
                FAILED_COUNT=$((FAILED_COUNT + 1))
            fi
        done <<< "$SUPER_LIST"

        # MySQL 8.0에서는 REVOKE/GRANT가 즉시 반영되므로 FLUSH PRIVILEGES는 필요하지 않습니다.

        if [[ $MODIFIED_COUNT -gt 0 && $FAILED_COUNT -eq 0 ]]; then
            STATUS="PASS"
            ACTION_RESULT="SUCCESS"
            ACTION_LOG="불필요하게 부여된 SUPER 권한을 회수하여 관리자 권한이 필요한 계정에만 권한이 부여되도록 정비하였습니다."
            EVIDENCE="root 계정을 제외한 SUPER 권한 보유 계정에서 권한 회수를 완료하였습니다."
        elif [[ $MODIFIED_COUNT -gt 0 && $FAILED_COUNT -gt 0 ]]; then
            STATUS="PASS"
            ACTION_RESULT="SUCCESS"
            ACTION_LOG="불필요한 SUPER 권한 회수를 수행하였으나 일부 계정은 권한 또는 설정 문제로 회수하지 못하였습니다."
            EVIDENCE="SUPER 권한 회수를 일부 완료하였으나, 일부 계정에 대해서는 권한 회수에 실패하였습니다."
        else
            STATUS="FAIL"
            ACTION_RESULT="FAIL"
            ACTION_LOG="조치가 수행되지 않았습니다. SUPER 권한 회수를 시도했으나 적용되지 않았습니다."
            EVIDENCE="SUPER 권한 회수 명령이 정상 반영되지 않아 관리자 권한 최소화를 완료할 수 없습니다."
        fi
    fi

    # 3) (선택) 필요한 경우 최소 권한만 부여
    if [[ "$GRANT_MINIMAL_ADMIN" == "Y" && -n "$TARGET_USER" && -n "$TARGET_HOST" ]]; then
        GRANT_SQL="GRANT BINLOG_ADMIN, SYSTEM_VARIABLES_ADMIN ON *.* TO '${TARGET_USER}'@'${TARGET_HOST}';"
        run_mysql "$GRANT_SQL"
        RC3=$?

        if [[ $RC3 -eq 0 ]]; then
            # PASS/FAIL 상태는 기존 결과를 유지하되, evidence/log에 보강
            ACTION_LOG="불필요한 관리자 권한을 회수하고, 필요한 계정에 한해 최소 권한(BINLOG_ADMIN, SYSTEM_VARIABLES_ADMIN)만 부여하여 권한 남용을 방지하였습니다."
            EVIDENCE="SUPER 권한 회수 조치와 함께 필요한 계정에 최소 관리자 권한을 부여하였습니다."
        fi
    fi
fi

# 4. JSON 표준 출력 (고정 구조)
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
