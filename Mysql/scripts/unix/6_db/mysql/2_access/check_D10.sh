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
CATEGORY="접근 관리"
TITLE="원격에서 DB 서버로의 접속 제한"
IMPORTANCE="상"
TARGET_FILE="mysql.user.host"

STATUS="FAIL"
EVIDENCE="N/A"

MYSQL_TIMEOUT=5
MYSQL_CMD="mysql --protocol=TCP -uroot -N -s -B -e"
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

Q1="SELECT user,host,COALESCE(account_locked,'N') FROM mysql.user;"
Q2="SELECT user,host,'N' FROM mysql.user;"

ROWS="$(run_mysql "$Q1")"
RC=$?
if [[ $RC -ne 0 ]]; then
    ROWS="$(run_mysql "$Q2")"
    RC=$?
fi

if [[ $RC -eq 124 ]]; then
    STATUS="FAIL"
    EVIDENCE="MySQL 계정 host 조회가 제한 시간(${MYSQL_TIMEOUT}초)을 초과했습니다."
elif [[ $RC -ne 0 || -z "$ROWS" ]]; then
    STATUS="FAIL"
    EVIDENCE="MySQL 접속 실패 또는 권한 부족으로 D-10 점검을 수행할 수 없습니다."
else
    VULN_COUNT=0
    SAMPLE="N/A"

    while IFS=$'\t' read -r user host locked; do
        [[ -z "$host" ]] && continue

        # 잠금 계정은 실제 원격 접근이 불가능하므로 제외
        if [[ "$locked" == "Y" ]]; then
            continue
        fi

        # 허용 목록(기본: 로컬) 외 계정은 취약으로 판정
        if in_csv "$host" "$ALLOWED_HOSTS_CSV"; then
            continue
        fi

        # 와일드카드 또는 비인가 호스트
        VULN_COUNT=$((VULN_COUNT + 1))
        if [[ "$SAMPLE" == "N/A" ]]; then
            SAMPLE="${user}@${host}"
        fi
    done <<< "$ROWS"

    if [[ $VULN_COUNT -eq 0 ]]; then
        STATUS="PASS"
        EVIDENCE="모든 활성 계정이 허용 호스트(${ALLOWED_HOSTS_CSV})로 제한되어 D-10 기준을 충족합니다."
    else
        STATUS="FAIL"
        EVIDENCE="허용되지 않은 원격 접근 가능 계정이 확인되었습니다. (${VULN_COUNT}건, 예: ${SAMPLE})"
    fi
fi

if [ -f "$TARGET_FILE" ]; then
    FILE_HASH=$(sha256sum "$TARGET_FILE" 2>/dev/null | awk '{print $1}')
    [[ -z "$FILE_HASH" ]] && FILE_HASH="HASH_ERROR"
else
    FILE_HASH="NOT_FOUND"
fi

IMPACT_LEVEL="MEDIUM"
ACTION_IMPACT="허용되지 않은 호스트의 DB 접속이 제한되어 비인가 원격 접근 위험이 감소합니다."

cat <<EOF_JSON
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "mysql.user.host를 지정된 IP/호스트로 제한하고 와일드카드('%') 사용 계정은 제거 또는 잠금하세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF_JSON
