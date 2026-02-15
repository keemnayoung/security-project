#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-07
# ============================================================================
# [점검 항목 상세]
# @ID          : D-21
# @Category    : 옵션 관리
# @Platform    : MySQL
# @IMPORTANCE  : 중
# @Title       : 인가되지 않은 GRANT OPTION 사용 제한
# @Description : 일반 사용자에게 GRANT OPTION이 부여되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-21"
STATUS="FAIL"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="mysql.user"
CHECK_COMMAND="information_schema.table_privileges/schema_privileges/user_privileges(is_grantable=YES or GRANT OPTION) 및 (fallback) mysql.user(Grant_priv='Y') 점검"
REASON_LINE=""
DETAIL_CONTENT=""

TIMEOUT_BIN="$(command -v timeout 2>/dev/null || true)"
MYSQL_TIMEOUT=5
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"
export MYSQL_PWD="${MYSQL_PASSWORD}"
MYSQL_CMD="mysql --protocol=TCP -u${MYSQL_USER} -N -s -B -e"

# 인가 예외(기관 정책에 따라 확장)
ALLOWED_GRANT_USERS_CSV="${ALLOWED_GRANT_USERS_CSV:-root,mysql.sys,mysql.session,mysql.infoschema,mysqlxsys,mariadb.sys}"
ALLOWED_GRANT_PRINCIPALS_CSV="${ALLOWED_GRANT_PRINCIPALS_CSV:-root@localhost,root@127.0.0.1,root@::1}"
ALLOWED_GRANT_GRANTEES_CSV="${ALLOWED_GRANT_GRANTEES_CSV:-}"

escape_json_str() {
  echo "$1" | sed ':a;N;$!ba;s/\n/\\n/g' | sed 's/\\"/\\\\"/g; s/"/\\"/g'
}

in_csv() {
  local needle="$1"
  local csv="$2"
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

extract_user_from_grantee() { echo "$1" | sed -E "s/^'([^']+)'.*$/\1/"; }
extract_host_from_grantee() { echo "$1" | sed -E "s/^'[^']+'@'([^']+)'$/\1/"; }

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

run_mysql_query() {
  local query="$1"
  if [[ -n "$TIMEOUT_BIN" ]]; then
    $TIMEOUT_BIN "${MYSQL_TIMEOUT}s" $MYSQL_CMD "$query" 2>/dev/null || echo "ERROR_TIMEOUT"
  else
    $MYSQL_CMD "$query" 2>/dev/null || echo "ERROR"
  fi
}

# 정보 스키마 기반 점검(우선)
Q_IS_TABLE="
SELECT GRANTEE,'TABLE' AS SCOPE, CONCAT(TABLE_SCHEMA,'.',TABLE_NAME) AS OBJ, PRIVILEGE_TYPE, IS_GRANTABLE
FROM information_schema.table_privileges
WHERE IS_GRANTABLE='YES';
"
Q_IS_SCHEMA="
SELECT GRANTEE,'SCHEMA' AS SCOPE, TABLE_SCHEMA AS OBJ, PRIVILEGE_TYPE, IS_GRANTABLE
FROM information_schema.schema_privileges
WHERE IS_GRANTABLE='YES';
"
Q_IS_GLOBAL="
SELECT GRANTEE,'GLOBAL' AS SCOPE, '*.*' AS OBJ, PRIVILEGE_TYPE, IS_GRANTABLE
FROM information_schema.user_privileges
WHERE IS_GRANTABLE='YES' OR PRIVILEGE_TYPE='GRANT OPTION';
"

R_TABLE="$(run_mysql_query "$Q_IS_TABLE")"
R_SCHEMA="$(run_mysql_query "$Q_IS_SCHEMA")"
R_GLOBAL="$(run_mysql_query "$Q_IS_GLOBAL")"

FALLBACK_USED="N"
if [[ "$R_TABLE" == "ERROR" || "$R_SCHEMA" == "ERROR" || "$R_GLOBAL" == "ERROR" ]]; then
  FALLBACK_USED="Y"
  R_TABLE="N/A"
  R_SCHEMA="N/A"
  R_GLOBAL="$(run_mysql_query "SELECT CONCAT(\"'\",User,\"'@'\",Host,\"'\") AS GRANTEE,'GLOBAL' AS SCOPE,'*.*' AS OBJ,'GRANT OPTION' AS PRIVILEGE_TYPE,'YES' AS IS_GRANTABLE FROM mysql.user WHERE Grant_priv='Y';")"
fi

if [[ "$R_TABLE" == "ERROR_TIMEOUT" || "$R_SCHEMA" == "ERROR_TIMEOUT" || "$R_GLOBAL" == "ERROR_TIMEOUT" ]]; then
  STATUS="ERROR"
  REASON_LINE="D-21 ERROR: GRANT OPTION 부여 현황 조회가 제한 시간(${MYSQL_TIMEOUT}초)을 초과했습니다."
  DETAIL_CONTENT="DB 응답 지연으로 점검을 완료하지 못했기 때문에 이 항목에 대한 보안 상태를 판단할 수 없습니다. DB 상태(부하/네트워크) 확인 후 재실행하십시오."
elif [[ "$R_GLOBAL" == "ERROR" ]]; then
  STATUS="ERROR"
  REASON_LINE="D-21 ERROR: MySQL 접속 실패 또는 권한 부족으로 점검을 수행할 수 없습니다."
  DETAIL_CONTENT="MySQL 접속 계정 권한 및 접속 정보를 확인한 뒤 재실행하십시오."
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
      if is_allowed_grantee "$grantee"; then
        continue
      fi
      VULN_COUNT=$((VULN_COUNT + 1))
      if [[ "$SAMPLE" == "N/A" ]]; then
        SAMPLE="${grantee} (${scope}:${obj}, ${priv}, grantable=${grantable:-?})"
        REASON="$default_reason"
      fi
    done <<< "$rows"
  }

  [[ "$R_TABLE" != "N/A" ]] && check_rows "$R_TABLE" "information_schema.table_privileges(IS_GRANTABLE='YES')"
  [[ "$R_SCHEMA" != "N/A" ]] && check_rows "$R_SCHEMA" "information_schema.schema_privileges(IS_GRANTABLE='YES')"
  check_rows "$R_GLOBAL" "information_schema.user_privileges(IS_GRANTABLE='YES' 또는 PRIVILEGE_TYPE='GRANT OPTION')"

  if [[ "$VULN_COUNT" -eq 0 ]]; then
    STATUS="PASS"
    if [[ "$FALLBACK_USED" == "Y" ]]; then
      REASON_LINE="D-21 PASS: mysql.user(Grant_priv='Y') 기준으로 인가되지 않은 GRANT OPTION이 확인되지 않습니다."
      DETAIL_CONTENT="mysql.user에서 Grant_priv='Y'인 계정이 인가 목록으로 제한되어 있기 때문에 이 항목에 대한 보안 위협이 없습니다."
    else
      REASON_LINE="D-21 PASS: information_schema 권한 뷰에서 인가되지 않은 WITH GRANT OPTION/GRANT OPTION이 확인되지 않습니다."
      DETAIL_CONTENT="information_schema의 table_privileges/schema_privileges/user_privileges에서 IS_GRANTABLE='YES' 또는 GRANT OPTION이 인가되지 않은 계정에 존재하지 않기 때문에 이 항목에 대한 보안 위협이 없습니다."
    fi
  else
    STATUS="FAIL"
    REASON_LINE="D-21 FAIL: 인가되지 않은 계정에 WITH GRANT OPTION/GRANT OPTION이 부여되어 취약합니다."
    DETAIL_CONTENT="information_schema(또는 mysql.user)에서 ${REASON} 설정이 인가되지 않은 계정에 존재하기 때문에 취약합니다. (총 ${VULN_COUNT}건, 예: ${SAMPLE}). 조치: 해당 계정에서 GRANT OPTION/IS_GRANTABLE 권한을 REVOKE로 회수하고, 권한 위임이 필요하면 ROLE에만 WITH GRANT OPTION을 부여한 뒤 사용자에는 ROLE만 부여하십시오."
  fi
fi

RAW_EVIDENCE_JSON=$(cat <<EOF
{
  "command":"$(escape_json_str "$CHECK_COMMAND")",
  "detail":"$(escape_json_str "${REASON_LINE}\n${DETAIL_CONTENT}")",
  "target_file":"$(escape_json_str "$TARGET_FILE")"
}
EOF
)

RAW_EVIDENCE_ESCAPED="$(escape_json_str "$RAW_EVIDENCE_JSON")"

echo ""
cat <<EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF