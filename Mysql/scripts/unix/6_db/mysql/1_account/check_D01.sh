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
STATUS="FAIL"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="mysql.user"

# 실행 안정성: DB 지연 시 무한 대기를 막기 위한 timeout/접속 옵션
TIMEOUT_BIN="$(command -v timeout 2>/dev/null || true)"
MYSQL_TIMEOUT_SEC=5
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"
export MYSQL_PWD="${MYSQL_PASSWORD}"
MYSQL_CMD_BASE="mysql --protocol=TCP -u${MYSQL_USER} -N -s -B -e"

# [가이드 D-01(MySQL) 대응] 기본 계정(root/익명) 비밀번호/잠금 상태 조회
QUERY_PRIMARY="SELECT user, host, COALESCE(authentication_string,''), COALESCE(account_locked,'N') FROM mysql.user WHERE user='root' OR user='';"
QUERY_FALLBACK1="SELECT user, host, COALESCE(authentication_string,''), 'N' AS account_locked FROM mysql.user WHERE user='root' OR user='';"
QUERY_FALLBACK2="SELECT user, host, COALESCE(password,''), 'N' AS account_locked FROM mysql.user WHERE user='root' OR user='';"

run_mysql_query() {
    local query="$1"
    if [[ -n "$TIMEOUT_BIN" ]]; then
        $TIMEOUT_BIN "${MYSQL_TIMEOUT_SEC}s" $MYSQL_CMD_BASE "$query" 2>/dev/null || echo "ERROR_TIMEOUT"
    else
        $MYSQL_CMD_BASE "$query" 2>/dev/null || echo "ERROR"
    fi
}

ACCOUNT_INFO="$(run_mysql_query "$QUERY_PRIMARY")"
if [[ "$ACCOUNT_INFO" == "ERROR" ]]; then ACCOUNT_INFO="$(run_mysql_query "$QUERY_FALLBACK1")"; fi
if [[ "$ACCOUNT_INFO" == "ERROR" ]]; then ACCOUNT_INFO="$(run_mysql_query "$QUERY_FALLBACK2")"; fi

REASON_LINE=""
DETAIL_CONTENT=""

if [[ "$ACCOUNT_INFO" == "ERROR_TIMEOUT" ]]; then
    STATUS="FAIL"
    REASON_LINE="MySQL 명령 실행이 ${MYSQL_TIMEOUT_SEC}초 내에 완료되지 않아 대기 또는 지연이 발생하였으며, 무한 로딩 방지를 위해 처리를 중단하였습니다."
elif [[ "$ACCOUNT_INFO" == "ERROR" ]]; then
    STATUS="FAIL"
    REASON_LINE="MySQL 접속에 실패했거나 mysql.user 조회 권한이 없어 D-01 점검을 수행할 수 없습니다."
else
    VULN_COUNT=0
    ROOT_COUNT=0
    REASONS=()

    while IFS=$'\t' read -r user host auth locked; do
        [[ -z "$user" && -z "$host" ]] && continue
        [[ "$locked" == "Y" ]] && is_locked="Y" || is_locked="N"

        # 익명 기본 계정은 잠금(또는 삭제)되어야 안전
        if [[ -z "$user" ]]; then
            if [[ "$is_locked" != "Y" ]]; then
                VULN_COUNT=$((VULN_COUNT + 1))
                REASONS+=("anonymous@${host}: 기본(익명) 계정이 활성 상태(잠금/삭제 필요)")
            fi
            continue
        fi

        # root 계정: 초기 비밀번호(공란) 사용 여부 + 원격 root 제한
        if [[ "$user" == "root" ]]; then
            ROOT_COUNT=$((ROOT_COUNT + 1))

            if [[ "$is_locked" != "Y" && -z "$auth" ]]; then
                VULN_COUNT=$((VULN_COUNT + 1))
                REASONS+=("root@${host}: 비밀번호 미설정(초기/공란) 상태")
                continue
            fi

            if [[ "$is_locked" != "Y" ]]; then
                case "$host" in
                    "localhost"|"127.0.0.1"|"::1") : ;;
                    *) VULN_COUNT=$((VULN_COUNT + 1)); REASONS+=("root@${host}: 원격 root 계정 활성(로컬 제한/잠금/삭제 필요)") ;;
                esac
            fi
        fi
    done <<< "$ACCOUNT_INFO"

    if [[ "$ROOT_COUNT" -eq 0 ]]; then
        STATUS="FAIL"
        REASON_LINE="root 기본 계정을 확인할 수 없어 D-01 판정 불가"
    else
        if [[ "$VULN_COUNT" -eq 0 ]]; then
            STATUS="PASS"
            REASON_LINE="D-01 양호: 기본 계정의 초기 비밀번호 사용이 확인되지 않고, 불필요한 기본 계정이 제한되어 있습니다."
        else
            STATUS="FAIL"
            REASON_LINE="D-01 취약: ${REASONS[*]}"
        fi
    fi
fi

CHECK_COMMAND="$MYSQL_CMD_BASE \"$QUERY_PRIMARY\" (fallback: \"$QUERY_FALLBACK1\" / \"$QUERY_FALLBACK2\")"
DETAIL_CONTENT="account_info=$ACCOUNT_INFO"

RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/"/\\"/g' \
  | sed ':a;N;$!ba;s/\n/\\n/g')

echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF
