#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.1
# @Author: 한은결
# @Last Updated: 2026-02-16
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

# 허용 호스트(기본 로컬)
ALLOWED_HOSTS_CSV="${ALLOWED_HOSTS_CSV:-localhost,127.0.0.1,::1}"

run_mysql() {
    local sql="$1"
    # timeout 적용(무한 대기 방지)
    if [[ -n "$TIMEOUT_BIN" ]]; then
        $TIMEOUT_BIN ${MYSQL_TIMEOUT}s $MYSQL_CMD "$sql" 2>/dev/null
    else
        $MYSQL_CMD "$sql" 2>/dev/null
    fi
}

in_csv() {
    # CSV 포함 여부 확인(공백 없는 CSV 전제)
    local needle="$1"
    local csv="$2"
    IFS=',' read -r -a arr <<< "$csv"
    for item in "${arr[@]}"; do
        [[ "$needle" == "$item" ]] && return 0
    done
    return 1
}

# 로컬 전용 계정 목록(자동 정리 대상)
AUTO_LOCAL_USERS_CSV="${AUTO_LOCAL_USERS_CSV:-root}"
# 운영상 허용 원격 host 목록(수동 관리)
MANUAL_ALLOWED_REMOTE_HOSTS_CSV="${MANUAL_ALLOWED_REMOTE_HOSTS_CSV:-}"
# 수동 점검 대상 계정 목록(즉시 취약 제외)
MANUAL_REVIEW_USERS_CSV="${MANUAL_REVIEW_USERS_CSV:-admin}"

# 구버전 호환(account_locked 미존재 대비)
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
    REASON_LINE="MySQL 계정 host 조회가 제한 시간(${MYSQL_TIMEOUT}초)을 초과하여 D-10 점검에 실패했습니다. DB 응답 지연 또는 접속 설정을 확인해주시기 바랍니다.\n조치 방법은 DB 상태/부하 및 접속 옵션을 점검하신 후 재시도해주시기 바랍니다."
    DETAIL_CONTENT="제한 시간은 ${MYSQL_TIMEOUT}초로 설정되어 있습니다(timeout_sec=${MYSQL_TIMEOUT})."
elif [[ $RC -ne 0 || -z "$ROWS" ]]; then
    STATUS="FAIL"
    REASON_LINE="MySQL 접속 실패 또는 권한 부족으로 D-10 점검을 수행할 수 없습니다. 진단 계정 권한 또는 접속 정보를 점검해주시기 바랍니다.\n조치 방법은 진단 계정의 권한과 인증 정보를 확인해주시기 바랍니다."
    DETAIL_CONTENT="MySQL 접속 상태가 확인되지 않았습니다(mysql_access=FAILED)."
else
    VULN_COUNT=0
    SAMPLE="N/A"
    MANUAL_REVIEW_COUNT=0
    MANUAL_SAMPLE="N/A"
    AUTO_FIXED=0
    AUTO_FAIL=0

    while IFS=$'\t' read -r user host locked; do
        [[ -z "$host" ]] && continue

        # 잠긴 계정 제외
        if [[ "$locked" == "Y" ]]; then
            continue
        fi

        # 로컬 전용 계정이 원격 host로 존재하면 자동 삭제 시도
        if in_csv "$user" "$AUTO_LOCAL_USERS_CSV"; then
            if ! in_csv "$host" "$ALLOWED_HOSTS_CSV"; then
                # SQL 작은따옴표 이스케이프
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

        # 허용 host 통과
        if in_csv "$host" "$ALLOWED_HOSTS_CSV"; then
            continue
        fi
        # 운영 허용 원격 host 통과
        if [[ -n "$MANUAL_ALLOWED_REMOTE_HOSTS_CSV" ]] && in_csv "$host" "$MANUAL_ALLOWED_REMOTE_HOSTS_CSV"; then
            continue
        fi

        # 수동 점검 대상 계정 별도 집계(즉시 취약 제외)
        if in_csv "$user" "$MANUAL_REVIEW_USERS_CSV"; then
            MANUAL_REVIEW_COUNT=$((MANUAL_REVIEW_COUNT + 1))
            if [[ "$MANUAL_SAMPLE" == "N/A" ]]; then
                MANUAL_SAMPLE="${user}@${host}"
            fi
            continue
        fi

        # 허용되지 않은 원격 계정 취약 집계
        VULN_COUNT=$((VULN_COUNT + 1))
        if [[ "$SAMPLE" == "N/A" ]]; then
            SAMPLE="${user}@${host}"
        fi
    done <<< "$ROWS"

    if [[ $VULN_COUNT -eq 0 ]]; then
        STATUS="PASS"
        if [[ $MANUAL_REVIEW_COUNT -gt 0 ]]; then
            REASON_LINE="원격 host 계정 중 수동 점검 대상 계정이 존재하나(MANUAL_REVIEW_USERS_CSV: ${MANUAL_REVIEW_USERS_CSV}), 즉시 취약으로 분류하지 않았으며 허용 호스트 제한이 적용되어 있어 이 항목에 대한 보안 위협이 없습니다. 또한 자동 조치로 원격 계정 ${AUTO_FIXED}건이 삭제되었습니다."
            DETAIL_CONTENT="수동 점검 대상 계정 예시는 ${MANUAL_SAMPLE} 이며, 허용 호스트는 ${ALLOWED_HOSTS_CSV}${MANUAL_ALLOWED_REMOTE_HOSTS_CSV:+,${MANUAL_ALLOWED_REMOTE_HOSTS_CSV}} 입니다. 자동 삭제된 원격 계정 수는 ${AUTO_FIXED}건입니다."
        else
            REASON_LINE="모든 활성 계정이 허용 호스트(${ALLOWED_HOSTS_CSV}${MANUAL_ALLOWED_REMOTE_HOSTS_CSV:+,${MANUAL_ALLOWED_REMOTE_HOSTS_CSV}})로 제한되어 있어 이 항목에 대한 보안 위협이 없습니다. 또한 자동 조치로 원격 계정 ${AUTO_FIXED}건이 삭제되었습니다."
            DETAIL_CONTENT="허용 호스트는 ${ALLOWED_HOSTS_CSV}${MANUAL_ALLOWED_REMOTE_HOSTS_CSV:+,${MANUAL_ALLOWED_REMOTE_HOSTS_CSV}} 이며, 자동 삭제된 원격 계정 수는 ${AUTO_FIXED}건입니다."
        fi
    else
        STATUS="FAIL"
        REASON_LINE="허용되지 않은 원격 접근 가능 계정이 확인되어 무단 원격 접속 위험이 있습니다. 또한 자동 조치로 원격 계정 ${AUTO_FIXED}건이 삭제되었으나 ${AUTO_FAIL}건은 삭제에 실패했습니다.\n조치 방법은 허용 호스트 목록을 기준으로 원격 접근 계정을 정리(삭제 또는 잠금)해주시기 바라며, 필요한 원격 접속만 MANUAL_ALLOWED_REMOTE_HOSTS_CSV에 등록하여 범위를 최소화해주시기 바랍니다. 자동 삭제 실패 건은 권한 및 계정 상태를 확인하신 후 수동으로 정리해주시기 바랍니다."
        DETAIL_CONTENT="허용되지 않은 원격 계정 수는 ${VULN_COUNT}건이며, 예시는 ${SAMPLE} 입니다. 자동 삭제 성공 건수는 ${AUTO_FIXED}건, 자동 삭제 실패 건수는 ${AUTO_FAIL}건입니다."
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