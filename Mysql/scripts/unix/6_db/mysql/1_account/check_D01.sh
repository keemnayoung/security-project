#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-11
# ============================================================================
# [점검 항목 상세]
# @ID          : D-01
# @Category    : 계정 관리
# @Platform    : MySQL
# @Severity    : 상
# @Title       : 기본 계정의 비밀번호, 정책 등을 변경하여 사용
# @Description : 기본 계정의 초기 비밀번호 사용 또는 사용 제한 미적용 상태를 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-01"
CATEGORY="계정 관리"
TITLE="기본 계정의 비밀번호, 정책 등을 변경하여 사용"
IMPORTANCE="상"
TARGET_FILE="mysql.user"

# 기본 결과값: 점검 전에는 FAIL로 두고, 조건 충족 시 PASS로 변경
STATUS="FAIL"
EVIDENCE="N/A"

# 실행 안정성: DB 지연 시 무한 대기를 막기 위한 timeout/접속 옵션
TIMEOUT_BIN="$(command -v timeout 2>/dev/null || true)"
MYSQL_TIMEOUT_SEC=5
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"
export MYSQL_PWD="${MYSQL_PASSWORD}"
MYSQL_CMD_BASE="mysql --protocol=TCP -u${MYSQL_USER} -N -s -B -e"

# [가이드 D-01(MySQL) 대응] 기본 계정(root/익명) 비밀번호/잠금 상태 조회
# - authentication_string: MySQL 5.7/8.0 계열
# - password: 구버전 호환(있는 경우)
QUERY_PRIMARY="SELECT user, host, COALESCE(authentication_string,''), COALESCE(account_locked,'N') FROM mysql.user WHERE user='root' OR user='';"
QUERY_FALLBACK1="SELECT user, host, COALESCE(authentication_string,''), 'N' AS account_locked FROM mysql.user WHERE user='root' OR user='';"
QUERY_FALLBACK2="SELECT user, host, COALESCE(password,''), 'N' AS account_locked FROM mysql.user WHERE user='root' OR user='';"

# 공통 실행 함수: timeout 적용 + 오류 토큰(ERROR/ERROR_TIMEOUT) 표준화
run_mysql_query() {
    local query="$1"
    if [[ -n "$TIMEOUT_BIN" ]]; then
        $TIMEOUT_BIN "${MYSQL_TIMEOUT_SEC}s" $MYSQL_CMD_BASE "$query" 2>/dev/null || echo "ERROR_TIMEOUT"
    else
        $MYSQL_CMD_BASE "$query" 2>/dev/null || echo "ERROR"
    fi
}

# 1차 조회(신규버전) 후 실패 시 2차 조회(구버전)로 재시도
ACCOUNT_INFO="$(run_mysql_query "$QUERY_PRIMARY")"
if [[ "$ACCOUNT_INFO" == "ERROR" ]]; then ACCOUNT_INFO="$(run_mysql_query "$QUERY_FALLBACK1")"; fi
if [[ "$ACCOUNT_INFO" == "ERROR" ]]; then ACCOUNT_INFO="$(run_mysql_query "$QUERY_FALLBACK2")"; fi

# 점검 불가 상황(시간초과/접속실패) 처리
if [[ "$ACCOUNT_INFO" == "ERROR_TIMEOUT" ]]; then
    STATUS="FAIL"
    EVIDENCE="MySQL 명령 실행이 ${MYSQL_TIMEOUT_SEC}초 내에 완료되지 않아 대기 또는 지연이 발생하였으며, 무한 로딩 방지를 위해 처리를 중단하였습니다."
elif [[ "$ACCOUNT_INFO" == "ERROR" ]]; then
    STATUS="FAIL"
    EVIDENCE="MySQL 접속에 실패했거나 mysql.user 조회 권한이 없어 D-01 점검을 수행할 수 없습니다."
else
    VULN_COUNT=0
    ROOT_COUNT=0
    ANON_COUNT=0
    REASONS=()

    # 조회 결과를 1행씩 판정
    while IFS=$'\t' read -r user host auth locked; do
        [[ -z "$user" && -z "$host" ]] && continue
        [[ "$locked" == "Y" ]] && is_locked="Y" || is_locked="N"

        # 익명 기본 계정은 잠금(또는 삭제)되어야 안전
        if [[ -z "$user" ]]; then
            ANON_COUNT=$((ANON_COUNT + 1))
            if [[ "$is_locked" != "Y" ]]; then
                VULN_COUNT=$((VULN_COUNT + 1))
                REASONS+=("anonymous@${host}: 기본(익명) 계정이 활성 상태(잠금/삭제 필요)")
            fi
            continue
        fi

        # root 계정: 초기 비밀번호(공란) 사용 여부 + 사용 정책(원격 root 제한)
        if [[ "$user" == "root" ]]; then
            ROOT_COUNT=$((ROOT_COUNT + 1))

            # root 비밀번호가 공란(초기값)이고 미잠금이면 취약
            if [[ "$is_locked" != "Y" && -z "$auth" ]]; then
                VULN_COUNT=$((VULN_COUNT + 1))
                REASONS+=("root@${host}: 비밀번호 미설정(초기/공란) 상태")
                continue
            fi

            # 권한/접근 정책 관점: 원격(root@'%' 등) 기본 계정이 활성화되어 있으면 위험(운영 기준에 따라 D-10과 중복될 수 있음)
            if [[ "$is_locked" != "Y" ]]; then
                case "$host" in
                    "localhost"|"127.0.0.1"|"::1") : ;;
                    *) VULN_COUNT=$((VULN_COUNT + 1)); REASONS+=("root@${host}: 원격 root 계정 활성(로컬 제한/잠금/삭제 필요)") ;;
                esac
            fi
        fi
    done <<< "$ACCOUNT_INFO"

    # root 계정 자체가 조회되지 않으면 점검 불가로 FAIL
    if [[ "$ROOT_COUNT" -eq 0 ]]; then
        STATUS="FAIL"
        EVIDENCE="root 기본 계정을 확인할 수 없어 D-01 판정 불가"
    else
        # 취약 사유가 없으면 양호(PASS), 있으면 취약(FAIL)
        if [[ "$VULN_COUNT" -eq 0 ]]; then
            STATUS="PASS"
            EVIDENCE="D-01 양호: 기본 계정의 초기 비밀번호 사용이 확인되지 않고, 불필요한 기본 계정이 제한되어 있습니다."
        else
            STATUS="FAIL"
            EVIDENCE="D-01 취약: ${REASONS[*]}"
        fi
    fi
fi

# 시스템 테이블 점검이므로 파일 해시는 N/A 처리
FILE_HASH="N/A(TABLE_CHECK)"

IMPACT_LEVEL="MEDIUM"
ACTION_IMPACT="이 조치를 적용하면 root 계정 비밀번호가 변경되어 기존에 저장되어 있던 자동화 스크립트, 애플리케이션 설정 파일, 배치 작업, 모니터링 도구 등에서 사용 중이던 기존 비밀번호로는 더 이상 접속이 불가능해집니다. 이로 인해 DB 연동 서비스 또는 관리 작업이 일시적으로 실패할 수 있으며, 관련 시스템 전반에 비밀번호 변경 사항을 반영해야 정상 운영이 가능합니다."

# 표준 JSON 결과 출력 (수집 파이프라인 연계 포맷)
cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "MySQL D-01 조치로 기본 관리자 계정(root)의 초기 비밀번호를 ALTER USER 등으로 정책에 맞게 변경하고, 불필요한 원격 root 계정과 익명 계정은 잠금 또는 삭제하며, 비밀번호는 복잡도 기준을 충족하고 시스템별로 다르게 설정·주기적으로 변경하되 변경 시 애플리케이션·배치·모니터링 설정에도 동일하게 반영해야 합니다.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
