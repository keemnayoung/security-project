#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-11
# ============================================================================
# [점검 항목 상세]
# @ID          : D-06
# @Category    : 계정 관리
# @Platform    : MySQL
# @IMPORTANCE  : 중
# @Title       : DB 사용자 계정을 개별적으로 부여하여 사용
# @Description : DB 접근 시 사용자별로 서로 다른 계정을 사용하여 접근하는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-06"
STATUS="FAIL"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="mysql.user"

EVIDENCE="N/A"

# 실행 안정성: DB 지연 시 무한 대기를 막기 위한 timeout/접속 옵션
TIMEOUT_BIN="$(command -v timeout 2>/dev/null || true)"
MYSQL_TIMEOUT=5
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"
export MYSQL_PWD="${MYSQL_PASSWORD}"
MYSQL_CMD="mysql --protocol=TCP -u${MYSQL_USER} -N -s -B -e"

# 오탐 완화:
COMMON_USERS_CSV="${COMMON_USERS_CSV:-guest,test,demo,shared,common,public,user}"
EXEMPT_USERS_CSV="${EXEMPT_USERS_CSV:-root,mysql.sys,mysql.session,mysql.infoschema,mysqlxsys,mariadb.sys}"

QUERY="
SELECT user,
       SUM(CASE WHEN host NOT IN ('localhost','127.0.0.1','::1') THEN 1 ELSE 0 END) AS non_local_host_count,
       SUM(CASE WHEN host='%' THEN 1 ELSE 0 END) AS wildcard_count,
       GROUP_CONCAT(host ORDER BY host SEPARATOR ',') AS hosts
FROM mysql.user
WHERE IFNULL(account_locked,'N') != 'Y'
GROUP BY user;
"

in_csv() {
  local needle="$1"
  local csv="$2"
  IFS=',' read -r -a arr <<< "$csv"
  for item in "${arr[@]}"; do
    [[ "$needle" == "$item" ]] && return 0
  done
  return 1
}

run_mysql_query() {
  local q="$1"
  if [[ -n "$TIMEOUT_BIN" ]]; then
    $TIMEOUT_BIN "${MYSQL_TIMEOUT}s" $MYSQL_CMD "$q" 2>/dev/null || echo "ERROR_TIMEOUT"
  else
    $MYSQL_CMD "$q" 2>/dev/null || echo "ERROR"
  fi
}

RESULT="$(run_mysql_query "$QUERY")"

REASON_LINE=""
DETAIL_CONTENT=""

if [[ "$RESULT" == "ERROR_TIMEOUT" ]]; then
  STATUS="FAIL"
  REASON_LINE="DB 사용자 계정 조회가 제한 시간(${MYSQL_TIMEOUT}초)을 초과하여 D-06 점검에 실패했습니다."
  DETAIL_CONTENT="result=ERROR_TIMEOUT"
elif [[ "$RESULT" == "ERROR" ]]; then
  STATUS="FAIL"
  REASON_LINE="MySQL 접속 실패 또는 권한 부족으로 계정 개별 사용 여부를 확인할 수 없습니다."
  DETAIL_CONTENT="result=ERROR"
else
  VULN_COUNT=0
  SAMPLE="N/A"
  REASON="N/A"

  while IFS=$'\t' read -r user non_local wildcard hosts; do
    [[ -z "$user" ]] && continue

    if in_csv "$user" "$EXEMPT_USERS_CSV"; then
      continue
    fi

    flag="N"
    reason=""

    if in_csv "$user" "$COMMON_USERS_CSV"; then
      flag="Y"
      reason="공용/테스트 성격의 계정명"
    elif [[ "$wildcard" -gt 0 && "$non_local" -gt 1 ]]; then
      flag="Y"
      reason="와일드카드(host=%) + 다중 원격 호스트"
    elif [[ "$non_local" -ge 3 ]]; then
      flag="Y"
      reason="다수 원격 호스트에서 동일 계정 사용"
    fi

    if [[ "$flag" == "Y" ]]; then
      VULN_COUNT=$((VULN_COUNT + 1))
      if [[ "$SAMPLE" == "N/A" ]]; then
        SAMPLE="${user} (hosts=${hosts})"
        REASON="$reason"
      fi
    fi
  done <<< "$RESULT"

  if [[ "$VULN_COUNT" -eq 0 ]]; then
    STATUS="PASS"
    REASON_LINE="공용 계정 사용 징후(명백한 공용 계정명/과도한 다중 원격 호스트)가 확인되지 않아 D-06 기준을 충족합니다."
    DETAIL_CONTENT="vuln_count=0"
  else
    STATUS="FAIL"
    REASON_LINE="공용 계정 사용 가능성이 높은 계정이 확인되었습니다."
    DETAIL_CONTENT="vuln_count=${VULN_COUNT}; reason=${REASON}; sample=${SAMPLE}"
  fi
fi

CHECK_COMMAND="$MYSQL_CMD \"$QUERY\""
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