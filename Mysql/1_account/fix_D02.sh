#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-11
# ============================================================================
# [점검 항목 상세]
# @ID          : D-02
# @Category    : DBMS (Database Management System)
# @Platform    : MySQL
# @IMPORTANCE  : 상
# @Title       : 데이터베이스의 불필요 계정 제거 또는 잠금 설정
# @Description : DB 운용에 사용하지 않는 불필요 계정을 삭제 또는 잠금
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-02"
CATEGORY="계정관리"
TITLE="데이터베이스의 불필요 계정을 제거하거나, 잠금설정 후 사용"
IMPORTANCE="상"
IMPACT_LEVEL="MEDIUM"
ACTION_IMPACT="이 조치를 적용하면 불필요한 계정이 삭제되어 해당 계정으로의 접속 및 관련 권한이 모두 사라집니다. 삭제된 계정을 사용하던 자동화 작업, 테스트 스크립트, 애플리케이션 연결 등에서 접속 실패가 발생할 수 있으므로, 사전에 영향 범위를 확인하고 필요한 대체 계정이나 권한을 준비한 후 적용해야 합니다."

STATUS="FAIL"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
EVIDENCE="N/A"

ACTION="${ACTION:-}"
TARGET_USER="${TARGET_USER:-}"
TARGET_HOST="${TARGET_HOST:-}"

TIMEOUT_BIN="$(command -v timeout 2>/dev/null)"
MYSQL_TIMEOUT_SEC=5
MYSQL_CMD="mysql --connect-timeout=${MYSQL_TIMEOUT_SEC} -uroot -e"

if [[ -z "$ACTION" || -z "$TARGET_USER" || -z "$TARGET_HOST" ]]; then
    ACTION_LOG="조치가 수행되지 않았습니다. 삭제 또는 잠금할 계정 정보가 제공되지 않았습니다."
    EVIDENCE="ACTION, TARGET_USER, TARGET_HOST 환경변수가 설정되지 않아 불필요 계정 조치를 수행할 수 없습니다."
else
    case "$ACTION" in
        DROP)
            SQL="DROP USER '${TARGET_USER}'@'${TARGET_HOST}';"
            ACTION_DESC="불필요한 계정을 삭제"
            ;;
        LOCK)
            SQL="ALTER USER '${TARGET_USER}'@'${TARGET_HOST}' ACCOUNT LOCK;"
            ACTION_DESC="불필요한 계정을 잠금 처리"
            ;;
        *)
            SQL=""
            ACTION_LOG="조치가 수행되지 않았습니다. ACTION 값이 유효하지 않습니다."
            EVIDENCE="ACTION 값은 DROP 또는 LOCK 중 하나여야 합니다."
            ;;
    esac

    if [[ -n "$SQL" ]]; then
        if [[ -n "$TIMEOUT_BIN" ]]; then
            $TIMEOUT_BIN "${MYSQL_TIMEOUT_SEC}s" $MYSQL_CMD "$SQL" >/dev/null 2>&1
        else
            $MYSQL_CMD "$SQL" >/dev/null 2>&1
        fi
        RC=$?

        if [[ "$RC" -eq 0 ]]; then
            STATUS="PASS"
            ACTION_RESULT="SUCCESS"
            ACTION_LOG="계정 용도를 검토한 후 ${ACTION_DESC}하여 불필요한 DB 계정 사용을 제한하였습니다."
            EVIDENCE="MySQL 명령이 정상 수행되어 ${TARGET_USER}@${TARGET_HOST} 계정에 대한 조치가 완료되었습니다."
        elif [[ "$RC" -eq 124 ]]; then
            ACTION_LOG="조치가 수행되지 않았습니다. MySQL 명령 실행이 제한 시간 내 완료되지 않아 중단하였습니다."
            EVIDENCE="MySQL 명령 실행이 ${MYSQL_TIMEOUT_SEC}초 내에 완료되지 않아 무한 로딩 방지를 위해 처리를 중단하였습니다."
        else
            ACTION_LOG="조치가 수행되지 않았습니다. MySQL 접속 오류 또는 권한 부족으로 계정 조치에 실패하였습니다."
            EVIDENCE="계정 삭제 또는 잠금 명령 실행에 실패하였습니다."
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
