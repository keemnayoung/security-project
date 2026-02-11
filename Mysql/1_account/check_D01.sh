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
# @Severity    : 상
# @Title       : 기본 계정의 비밀번호, 정책 등을 변경하여 사용
# @Description : 기본 계정(root/익명)의 비밀번호 미변경(공란) 또는 잠금 미적용 상태를 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-01"
CATEGORY="DBMS"
TITLE="기본 계정의 비밀번호, 정책 등을 변경하여 사용"
IMPORTANCE="상"
TARGET_FILE="mysql.user(table)"

# 기본 결과값: 점검 전에는 FAIL로 두고, 조건 충족 시 PASS로 변경
STATUS="FAIL"
EVIDENCE="N/A"

# 실행 안정성: DB 지연 시 무한 대기를 막기 위한 timeout/접속 옵션
TIMEOUT_BIN="$(command -v timeout 2>/dev/null)"
MYSQL_TIMEOUT_SEC=5
MYSQL_CMD_BASE="mysql --connect-timeout=${MYSQL_TIMEOUT_SEC} --protocol=TCP -uroot -N -s -B -e"

# [가이드 3~5p 대응] 기본 계정(root) + 익명 계정(user='')의 비밀번호/잠금 상태 조회
QUERY_PRIMARY="SELECT user, host, COALESCE(authentication_string,''), COALESCE(account_locked,'N') FROM mysql.user WHERE user='root' OR user='';"
# 구버전 호환: account_locked 컬럼이 없을 때 대체 조회
QUERY_FALLBACK="SELECT user, host, COALESCE(authentication_string,''), 'N' AS account_locked FROM mysql.user WHERE user='root' OR user='';"

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
if [[ "$ACCOUNT_INFO" == "ERROR" ]]; then
    ACCOUNT_INFO="$(run_mysql_query "$QUERY_FALLBACK")"
fi

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
    REASONS=()

    # 조회 결과를 1행씩 판정
    while IFS=$'\t' read -r user host auth locked; do
        [[ -z "$user" && -z "$host" ]] && continue
        [[ "$locked" == "Y" ]] && is_locked="Y" || is_locked="N"

        # [가이드 3~5p 대응] 익명 기본 계정은 잠금되어야 양호
        if [[ -z "$user" ]]; then
            if [[ "$is_locked" != "Y" ]]; then
                VULN_COUNT=$((VULN_COUNT + 1))
                REASONS+=("anonymous@${host}: 기본(익명) 계정이 잠금되지 않음")
            fi
            continue
        fi

        # root 계정만 대상으로 비밀번호/원격접속 정책 점검
        if [[ "$user" == "root" ]]; then
            ROOT_COUNT=$((ROOT_COUNT + 1))

            # [가이드 3~5p 대응] root 비밀번호가 공란(초기값)이고 미잠금이면 취약
            if [[ "$is_locked" != "Y" && -z "$auth" ]]; then
                VULN_COUNT=$((VULN_COUNT + 1))
                REASONS+=("root@${host}: 비밀번호 미설정(초기/공란) 상태")
                continue
            fi

            # [가이드 3~5p 대응] root 원격접속 허용 계정은 잠금/제거 필요
            if [[ "$is_locked" != "Y" ]]; then
                case "$host" in
                    "localhost"|"127.0.0.1"|"::1")
                        : ;;
                    *)
                        VULN_COUNT=$((VULN_COUNT + 1))
                        REASONS+=("root@${host}: 원격 접속 허용 상태(로컬 제한/잠금 필요)")
                        ;;
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
            EVIDENCE="D-01 양호: root 계정은 비밀번호가 설정되어 있고(공란 아님), 원격 접속이 제한되었거나 계정 잠금 상태이며, 익명 계정은 잠금되어 있습니다."
        else
            STATUS="FAIL"
            EVIDENCE="D-01 취약: ${REASONS[*]}"
        fi
    fi
fi

# 시스템 테이블 점검이므로 파일 해시는 N/A 처리
FILE_HASH="N/A(TABLE_CHECK)"

# 표준 JSON 결과 출력 (수집 파이프라인 연계 포맷)
cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "1) root 비밀번호 변경: ALTER USER 'root'@'localhost' IDENTIFIED BY '신규비밀번호'; 2) 원격 root 제거/잠금: DROP USER 'root'@'%'; 또는 ALTER USER 'root'@'원격호스트' ACCOUNT LOCK; 3) 익명 계정 잠금/삭제: ALTER USER ''@'localhost' ACCOUNT LOCK; 또는 DROP USER ''@'localhost';",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
