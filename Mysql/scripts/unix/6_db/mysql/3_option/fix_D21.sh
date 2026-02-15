#!/bin/bash
# @Author: 한은결
# D-21: 인가되지 않은 GRANT OPTION 사용 제한
ID="D-21"
CATEGORY="옵션 관리"
TITLE="인가되지 않은 GRANT OPTION 사용 제한"
IMPORTANCE="중"

STATUS="FAIL"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
EVIDENCE="N/A"

MYSQL_TIMEOUT=8
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"
export MYSQL_PWD="${MYSQL_PASSWORD}"
MYSQL_CMD="mysql --protocol=TCP -u${MYSQL_USER} -N -s -B -e"
TIMEOUT_BIN="$(command -v timeout 2>/dev/null || true)"

# 인가 예외(기관 정책에 따라 확장)
ALLOWED_GRANT_USERS_CSV="${ALLOWED_GRANT_USERS_CSV:-root,mysql.sys,mysql.session,mysql.infoschema,mysqlxsys,mariadb.sys}"
ALLOWED_GRANT_PRINCIPALS_CSV="${ALLOWED_GRANT_PRINCIPALS_CSV:-root@localhost,root@127.0.0.1,root@::1}"
ALLOWED_GRANT_GRANTEES_CSV="${ALLOWED_GRANT_GRANTEES_CSV:-}"

run_mysql() {
  local sql="$1"
  if [[ -n "$TIMEOUT_BIN" ]]; then
    $TIMEOUT_BIN ${MYSQL_TIMEOUT}s $MYSQL_CMD "$sql" 2>/dev/null
  else
    $MYSQL_CMD "$sql" 2>/dev/null
  fi
  return $?
}

in_csv() {
  local needle="$1" csv="$2"
  needle="$(printf "%s" "$needle" | tr '[:upper:]' '[:lower:]')"
  needle="${needle//[[:space:]]/}"
  IFS=',' read -r -a arr <<< "$csv"
  for item in "${arr[@]}"; do
    item="$(printf "%s" "$item" | tr '[:upper:]' '[:lower:]')"
    item="${item//[[:space:]]/}"
    [[ -n "$item" && "$needle" == "$item" ]] && return 0
  done
  return 1
}

extract_user_from_grantee() { echo "$1" | sed -E "s/^'([^']+)'.*$/\\1/"; }
extract_host_from_grantee() { echo "$1" | sed -E "s/^'[^']+'@'([^']+)'$/\\1/"; }

is_allowed_grantee() {
  local grantee="$1"
  local user host principal

  if [[ -n "$ALLOWED_GRANT_GRANTEES_CSV" ]] && in_csv "$grantee" "$ALLOWED_GRANT_GRANTEES_CSV"; then
    return 0
  fi

  user="$(extract_user_from_grantee "$grantee")"
  host="$(extract_host_from_grantee "$grantee")"
  principal="${user}@${host}"
  in_csv "$user" "$ALLOWED_GRANT_USERS_CSV" && return 0
  in_csv "$principal" "$ALLOWED_GRANT_PRINCIPALS_CSV" && return 0
  return 1
}

Q_IS_TABLE="SELECT GRANTEE,'TABLE' AS SCOPE, CONCAT(TABLE_SCHEMA,'.',TABLE_NAME) AS OBJ, PRIVILEGE_TYPE, IS_GRANTABLE FROM information_schema.table_privileges WHERE IS_GRANTABLE='YES';"
Q_IS_SCHEMA="SELECT GRANTEE,'SCHEMA' AS SCOPE, TABLE_SCHEMA AS OBJ, PRIVILEGE_TYPE, IS_GRANTABLE FROM information_schema.schema_privileges WHERE IS_GRANTABLE='YES';"
Q_IS_GLOBAL="SELECT GRANTEE,'GLOBAL' AS SCOPE, '*.*' AS OBJ, PRIVILEGE_TYPE, IS_GRANTABLE FROM information_schema.user_privileges WHERE IS_GRANTABLE='YES' OR PRIVILEGE_TYPE='GRANT OPTION';"

ROWS_T="$(run_mysql "$Q_IS_TABLE")"; RC_T=$?
ROWS_S="$(run_mysql "$Q_IS_SCHEMA")"; RC_S=$?
ROWS_G="$(run_mysql "$Q_IS_GLOBAL")"; RC_G=$?

FALLBACK_USED="N"
if [[ $RC_T -ne 0 || $RC_S -ne 0 || $RC_G -ne 0 ]]; then
  # 제한적 fallback: mysql.user.Grant_priv 기반
  FALLBACK_USED="Y"
  ROWS_T=""
  ROWS_S=""
  ROWS_G="$(run_mysql "SELECT CONCAT(\"'\",User,\"'@'\",Host,\"'\") AS GRANTEE,'GLOBAL' AS SCOPE,'*.*' AS OBJ,'GRANT OPTION' AS PRIVILEGE_TYPE,'YES' AS IS_GRANTABLE FROM mysql.user WHERE Grant_priv='Y';")"
  RC_G=$?
fi

if [[ $RC_T -eq 124 || $RC_S -eq 124 || $RC_G -eq 124 ]]; then
  ACTION_RESULT="MANUAL_REQUIRED"
  ACTION_LOG="수동 조치 안내: GRANT OPTION(WITH GRANT OPTION) 조회 시간 초과. 접속/권한/부하 확인 후 인가되지 않은 GRANT OPTION을 회수하십시오."
  EVIDENCE="조회가 ${MYSQL_TIMEOUT}초를 초과했습니다."
elif [[ $RC_G -ne 0 ]]; then
  ACTION_RESULT="MANUAL_REQUIRED"
  ACTION_LOG="수동 조치 안내: GRANT OPTION(WITH GRANT OPTION) 조회 실패. 접속 정보 및 권한을 확인한 후 인가되지 않은 GRANT OPTION을 회수하십시오."
  EVIDENCE="MySQL 접속 실패 또는 권한 부족으로 D-21 조치를 수행할 수 없습니다."
else
  VULN_COUNT=0
  SAMPLE="N/A"
  REASON="N/A"

  check_rows() {
    local rows="$1"
    local default_reason="$2"
    local grantee scope obj priv grantable
    while IFS=$'\t' read -r grantee scope obj priv grantable; do
      [[ -z "$grantee" || -z "$priv" ]] && continue
      is_allowed_grantee "$grantee" && continue
      VULN_COUNT=$((VULN_COUNT + 1))
      if [[ "$SAMPLE" == "N/A" ]]; then
        SAMPLE="${grantee} (${scope}:${obj}, ${priv}, grantable=${grantable:-?})"
        REASON="$default_reason"
      fi
    done <<< "$rows"
  }

  [[ -n "$ROWS_T" ]] && check_rows "$ROWS_T" "테이블 권한 WITH GRANT OPTION"
  [[ -n "$ROWS_S" ]] && check_rows "$ROWS_S" "스키마 권한 WITH GRANT OPTION"
  check_rows "$ROWS_G" "글로벌 GRANT OPTION/WITH GRANT OPTION"

  if [[ "$VULN_COUNT" -eq 0 ]]; then
    STATUS="PASS"
    ACTION_RESULT="NOT_REQUIRED"
    ACTION_LOG="추가 조치 불필요: 인가되지 않은 WITH GRANT OPTION/GRANT OPTION이 확인되지 않았습니다."
    EVIDENCE="D-21 기준 추가 조치 불필요"
  else
    STATUS="FAIL"
    ACTION_RESULT="MANUAL_REQUIRED"
    ACTION_LOG="수동 조치 필요: 인가되지 않은 계정/ROLE의 WITH GRANT OPTION/GRANT OPTION을 회수(REVOKE)하고, 권한 위임이 필요하면 ROLE로 관리하십시오."
    if [[ "$FALLBACK_USED" == "Y" ]]; then
      EVIDENCE="D-21 취약(제한적 점검): mysql.user(Grant_priv) 기준 인가되지 않은 GRANT OPTION이 확인됩니다. (${VULN_COUNT}건, 예: ${SAMPLE})"
    else
      EVIDENCE="D-21 취약: 인가되지 않은 WITH GRANT OPTION/GRANT OPTION이 확인됩니다. (${VULN_COUNT}건, 사유: ${REASON}, 예: ${SAMPLE})"
    fi
  fi
fi

echo ""
cat <<JSON
{
  "check_id":"$ID",
  "category":"$CATEGORY",
  "title":"$TITLE",
  "importance":"$IMPORTANCE",
  "status":"$STATUS",
  "evidence":"$EVIDENCE",
  "guide":"mysql.user의 grant_priv 또는 information_schema의 IS_GRANTABLE 값을 통해 WITH GRANT OPTION 보유 현황을 확인한 뒤 인가되지 않은 계정이나 ROLE의 GRANT OPTION을 REVOKE로 회수하고, 필요 시 해당 권한을 WITH GRANT OPTION 없이 재부여하며 권한 위임이 필요한 경우 ROLE에만 WITH GRANT OPTION을 부여하고 사용자에게는 ROLE만 할당하고 인가 예외는 ALLOWED_GRANT_USERS_CSV, ALLOWED_GRANT_PRINCIPALS_CSV, ALLOWED_GRANT_GRANTEES_CSV로 관리합니다.",
  "action_result":"$ACTION_RESULT",
  "action_log":"$ACTION_LOG",
  "action_date":"$(date '+%Y-%m-%d %H:%M:%S')",
  "check_date":"$(date '+%Y-%m-%d %H:%M:%S')"
}
JSON

