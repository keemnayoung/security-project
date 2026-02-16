#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.1
# @Author: 한은결
# @Last Updated: 2026-02-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-04
# @Category    : 계정 관리
# @Platform    : MySQL
# @IMPORTANCE  : 상
# @Title       : 데이터베이스 관리자 권한을 꼭 필요한 계정에만 부여
# @Description : 관리자 권한이 필요한 계정 및 그룹에만 관리자 권한을 부여하였는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-04"
STATUS="FAIL"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="mysql.user"

TIMEOUT_BIN="$(command -v timeout 2>/dev/null || true)"
MYSQL_TIMEOUT=5
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"
export MYSQL_PWD="${MYSQL_PASSWORD}"
MYSQL_CMD="mysql --protocol=TCP -u${MYSQL_USER} -N -s -B -e"

ALLOWED_ADMIN_USERS_CSV="${ALLOWED_ADMIN_USERS_CSV:-root,mysql.sys,mysql.session,mysql.infoschema,mysqlxsys,mariadb.sys}"
ALLOWED_ADMIN_PRINCIPALS_CSV="${ALLOWED_ADMIN_PRINCIPALS_CSV:-root@localhost,root@127.0.0.1,root@::1}"

QUERY="
SELECT grantee,
       GROUP_CONCAT(DISTINCT privilege_type ORDER BY privilege_type SEPARATOR ',') AS privileges
FROM information_schema.user_privileges
WHERE privilege_type IN ('SUPER','SYSTEM_USER','CREATE USER','RELOAD','SHUTDOWN','PROCESS')
   OR privilege_type LIKE '%_ADMIN'
GROUP BY grantee;
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

extract_user() {
  echo "$1" | sed -E "s/^'([^']+)'.*$/\1/"
}

extract_host() {
  echo "$1" | sed -E "s/^'[^']+'@'([^']+)'$/\1/"
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
  REASON_LINE="관리자 권한 부여 상태 조회가 제한 시간(${MYSQL_TIMEOUT}초)을 초과하여 D-04 점검에 실패했습니다. DB 응답 지연 또는 접속 설정을 확인해주시기 바랍니다.\n조치 방법은 DB 상태/부하 및 접속 옵션을 점검하신 후 재시도해주시기 바랍니다."
  DETAIL_CONTENT="조회 결과는 ERROR_TIMEOUT 입니다."
elif [[ "$RESULT" == "ERROR" ]]; then
  STATUS="FAIL"
  REASON_LINE="MySQL 접속 실패 또는 권한 부족으로 관리자 권한 부여 상태를 확인할 수 없습니다. 진단 계정 권한 또는 접속 정보를 점검해주시기 바랍니다.\n조치 방법은 진단 계정의 권한과 인증 정보를 확인해주시기 바랍니다."
  DETAIL_CONTENT="조회 결과는 ERROR 입니다."
else
  VIOLATION_COUNT=0
  SAMPLE="N/A"
  VIOLATIONS=()

  while IFS=$'\t' read -r grantee privs; do
    [[ -z "$grantee" ]] && continue

    user="$(extract_user "$grantee")"
    host="$(extract_host "$grantee")"
    principal="${user}@${host}"

    if in_csv "$user" "$ALLOWED_ADMIN_USERS_CSV"; then
      continue
    fi
    if in_csv "$principal" "$ALLOWED_ADMIN_PRINCIPALS_CSV"; then
      continue
    fi

    VIOLATION_COUNT=$((VIOLATION_COUNT + 1))
    [[ "$SAMPLE" == "N/A" ]] && SAMPLE="${principal} [${privs}]"
    VIOLATIONS+=("${principal}(${privs})")
  done <<< "$RESULT"

  if [[ "$VIOLATION_COUNT" -eq 0 ]]; then
    STATUS="PASS"
    REASON_LINE="관리자급 권한이 인가된 관리자 계정으로 제한되어 있어 이 항목에 대한 보안 위협이 없습니다."
    DETAIL_CONTENT="관리자 권한 위반 계정 수는 0건입니다."
  else
    STATUS="FAIL"
    REASON_LINE="인가되지 않은 계정에 관리자급 권한이 부여되어 있어 관리자 권한 최소 부여 기준에 부합하지 않습니다.\n조치 방법은 불필요한 관리자급 권한(SUPER, SYSTEM_USER, *_ADMIN 등)을 회수하시고, 관리자 권한은 허용된 관리자 계정으로만 제한해주시기 바랍니다. 조치 후 권한 부여 상태를 재확인해주시기 바랍니다."
    DETAIL_CONTENT="관리자 권한 위반 계정 수는 ${VIOLATION_COUNT}건이며, 예시는 ${SAMPLE} 입니다."
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