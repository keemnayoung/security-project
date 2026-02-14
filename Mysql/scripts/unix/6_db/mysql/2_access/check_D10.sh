#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-12
# ============================================================================
# [점검 항목 상세]
# @ID          : D-10
# @Category    : 접근 관리
# @Platform    : MySQL
# @Importance  : 상
# @Title       : 원격에서 DB 서버로의 접속 제한
# @Description : 지정된 IP/호스트에서만 DB 접근 허용 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-10"
STATUS="FAIL"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="mysql.user.host"
EVIDENCE="N/A"

MYSQL_TIMEOUT=5
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"
export MYSQL_PWD="${MYSQL_PASSWORD}"
MYSQL_CMD="mysql --protocol=TCP -u${MYSQL_USER} -N -s -B -e"
TIMEOUT_BIN="$(command -v timeout 2>/dev/null || true)"

# 기본 허용 호스트(로컬). 필요 시 ALLOWED_HOSTS_CSV로 추가 가능
ALLOWED_HOSTS_CSV="${ALLOWED_HOSTS_CSV:-localhost,127.0.0.1,::1}"

run_mysql() {
    local sql="$1"
    if [[ -n "$TIMEOUT_BIN" ]]; then
        $TIMEOUT_BIN ${MYSQL_TIMEOUT}s $MYSQL_CMD "$sql" 2>/dev/null
    else
        $MYSQL_CMD "$sql" 2>/dev/null
    fi
}

in_csv() {
    local needle="$1"
    local csv="$2"
    IFS=',' read -r -a arr <<< "$csv"
    for item in "${arr[@]}"; do
        [[ "$needle" == "$item" ]] && return 0
    done
    return 1
}

AUTO_LOCAL_USERS_CSV="${AUTO_LOCAL_USERS_CSV:-root}"
MANUAL_ALLOWED_REMOTE_HOSTS_CSV="${MANUAL_ALLOWED_REMOTE_HOSTS_CSV:-}"
MANUAL_REVIEW_USERS_CSV="${MANUAL_REVIEW_USERS_CSV:-admin}"

Q1="SELECT user,host,COALESCE(account_locked,'N') FROM mysql.user;"
Q2="SELECT user,host,'N' FROM mysql.user;"

ROWS="$(run_mysql "$Q1")"
RC=$?
if [[ $RC -ne 0 ]]; then
    ROWS="$(run_mysql "$Q2")"
    RC=$?
fi

REASON_LINE=""
DETAIL_CONTENT=""

if [[ $RC -eq 124 ]]; then
    STATUS="FAIL"
    REASON_LINE="MySQL 계정 host 조회가 제한 시간(${MYSQL_TIMEOUT}초)을 초과했습니다."
    DETAIL_CONTENT="timeout_sec=${MYSQL_TIMEOUT}"
elif [[ $RC -ne 0 || -z "$ROWS" ]]; then
    STATUS="FAIL"
    REASON_LINE="MySQL 접속 실패 또는 권한 부족으로 D-10 점검을 수행할 수 없습니다."
    DETAIL_CONTENT="mysql_access=FAILED"
else
    VULN_COUNT=0
    SAMPLE="N/A"
    MANUAL_REVIEW_COUNT=0
    MANUAL_SAMPLE="N/A"
    AUTO_FIXED=0
    AUTO_FAIL=0

    while IFS=$'\t' read -r user host locked; do
        [[ -z "$host" ]] && continue

        if [[ "$locked" == "Y" ]]; then
            continue
        fi

        if in_csv "$user" "$AUTO_LOCAL_USERS_CSV"; then
            if ! in_csv "$host" "$ALLOWED_HOSTS_CSV"; then
                esc_user="${user//\'/\'\'}"
                esc_host="${host//\'/\'\'}"
                run_mysql "DROP USER IF EXISTS '${esc_user}'@'${esc_host}';" >/dev/null
                if [[ $? -eq 0 ]]; then
                    AUTO_FIXED=$((AUTO_FIXED + 1))
                    continue
                else
                    AUTO_FAIL=$((AUTO_FAIL + 1))
                fi
            else
                continue
            fi
        fi

        if in_csv "$host" "$ALLOWED_HOSTS_CSV"; then
            continue
        fi
        if [[ -n "$MANUAL_ALLOWED_REMOTE_HOSTS_CSV" ]] && in_csv "$host" "$MANUAL_ALLOWED_REMOTE_HOSTS_CSV"; then
            continue
        fi

        if in_csv "$user" "$MANUAL_REVIEW_USERS_CSV"; then
            MANUAL_REVIEW_COUNT=$((MANUAL_REVIEW_COUNT + 1))
            if [[ "$MANUAL_SAMPLE" == "N/A" ]]; then
                MANUAL_SAMPLE="${user}@${host}"
            fi
            continue
        fi

        VULN_COUNT=$((VULN_COUNT + 1))
        if [[ "$SAMPLE" == "N/A" ]]; then
            SAMPLE="${user}@${host}"
        fi
    done <<< "$ROWS"

    if [[ $VULN_COUNT -eq 0 ]]; then
        STATUS="PASS"
        if [[ $MANUAL_REVIEW_COUNT -gt 0 ]]; then
            REASON_LINE="원격 host 계정 중 수동 점검 대상 계정이 존재하나(MANUAL_REVIEW_USERS_CSV: ${MANUAL_REVIEW_USERS_CSV}), 즉시 취약으로 분류하지 않았습니다. (자동 조치: 원격 계정 ${AUTO_FIXED}건 삭제)"
            DETAIL_CONTENT="manual_review_sample=${MANUAL_SAMPLE}; allowed_hosts=${ALLOWED_HOSTS_CSV}${MANUAL_ALLOWED_REMOTE_HOSTS_CSV:+,${MANUAL_ALLOWED_REMOTE_HOSTS_CSV}}; auto_deleted=${AUTO_FIXED}"
        else
            REASON_LINE="모든 활성 계정이 허용 호스트(${ALLOWED_HOSTS_CSV}${MANUAL_ALLOWED_REMOTE_HOSTS_CSV:+,${MANUAL_ALLOWED_REMOTE_HOSTS_CSV}})로 제한되어 D-10 기준을 충족합니다. (자동 조치: 원격 계정 ${AUTO_FIXED}건 삭제)"
            DETAIL_CONTENT="allowed_hosts=${ALLOWED_HOSTS_CSV}${MANUAL_ALLOWED_REMOTE_HOSTS_CSV:+,${MANUAL_ALLOWED_REMOTE_HOSTS_CSV}}; auto_deleted=${AUTO_FIXED}"
        fi
    else
        STATUS="FAIL"
        REASON_LINE="허용되지 않은 원격 접근 가능 계정이 확인되었습니다. (자동 조치: 원격 계정 ${AUTO_FIXED}건 삭제, 실패 ${AUTO_FAIL}건)"
        DETAIL_CONTENT="vuln_count=${VULN_COUNT}; sample=${SAMPLE}; auto_deleted=${AUTO_FIXED}; auto_delete_fail=${AUTO_FAIL}"
    fi
fi

FILE_HASH="N/A(TABLE_CHECK)"

CHECK_COMMAND="mysql -N -s -B -e \"SELECT user,host,COALESCE(account_locked,'N') FROM mysql.user;\""
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
cat << EOF_JSON
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF_JSON
