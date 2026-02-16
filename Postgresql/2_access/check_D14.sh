#!/bin/bash
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.1
# @Author: 윤영아
# @Last Updated: 2026-02-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-14
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 중
# @Title       : 데이터베이스의 주요 설정 파일, 비밀번호 파일 등과 같은 주요 파일들의 접근 권한이 적절하게 설정
# @Description : 데이터베이스의 주요 파일들에 대해 관리자를 제외한 일반 사용자의 파일 수정 권한을 제거하였는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================


COMMON_FILE="$(cd "$(dirname "$0")/.." && pwd)/_pg_common.sh"
# shellcheck disable=SC1090
. "$COMMON_FILE"
load_pg_env

ID="D-14"
STATUS="PASS"
EVIDENCE_LIST=""
GUIDE_MSG="현재 기준에서 추가 조치가 필요하지 않습니다."

# 데이터 디렉터리 경로 조회
DATA_DIR=$(run_psql "SHOW data_directory;" | xargs)
[ -z "$DATA_DIR" ] && DATA_DIR="$PGDATA"
# pg_hba.conf 경로 조회
HBA_FILE=$(run_psql "SHOW hba_file;" | xargs)
# postgresql.conf 경로 조회
CONF_FILE=$(run_psql "SHOW config_file;" | xargs)
IDENT_FILE="$DATA_DIR/pg_ident.conf"
# 로그 디렉터리 설정값 조회
LOG_DIR=$(run_psql "SHOW log_directory;" | xargs)

if [ -n "$LOG_DIR" ] && [ "${LOG_DIR#/}" = "$LOG_DIR" ]; then
  LOG_DIR="$DATA_DIR/$LOG_DIR"
fi

POSTGRES_HOME=$(getent passwd "$PG_SUPERUSER" | cut -d: -f6)
HISTORY_FILE="${POSTGRES_HOME}/.psql_history"

check_item() {
  local file="$1"
  local max_mode="$2"
  local type="$3"

  if [ ! -e "$file" ]; then
    return
  fi

  local mode owner
  mode=$(stat -c '%a' "$file" 2>/dev/null)
  owner=$(stat -c '%U' "$file" 2>/dev/null)

  if [ -z "$mode" ] || [ -z "$owner" ]; then
    STATUS="FAIL"
    EVIDENCE_LIST="${EVIDENCE_LIST}${file}(조회실패),"
    return
  fi

  if [ "$owner" != "$PG_SUPERUSER" ] && [ "$owner" != "postgres" ]; then
    STATUS="FAIL"
    EVIDENCE_LIST="${EVIDENCE_LIST}${file}(소유자:${owner}),"
  fi

  if [ "$mode" -gt "$max_mode" ] 2>/dev/null; then
    STATUS="FAIL"
    EVIDENCE_LIST="${EVIDENCE_LIST}${file}(권한:${mode}>${max_mode}),"
  fi

  if [ "$type" = "logdir" ] && [ -d "$file" ]; then
    while IFS= read -r lf; do
      lmode=$(stat -c '%a' "$lf" 2>/dev/null)
      if [ -n "$lmode" ] && [ "$lmode" -gt 640 ] 2>/dev/null; then
        STATUS="FAIL"
        EVIDENCE_LIST="${EVIDENCE_LIST}${lf}(로그권한:${lmode}),"
      fi
    done < <(find "$file" -maxdepth 1 -type f 2>/dev/null)
  fi
}

check_item "$DATA_DIR" 750 "dir"
check_item "$CONF_FILE" 640 "file"
check_item "$HBA_FILE" 640 "file"
check_item "$IDENT_FILE" 640 "file"
check_item "$HISTORY_FILE" 600 "file"
check_item "$LOG_DIR" 750 "logdir"

if [ "$STATUS" = "PASS" ]; then
  EVIDENCE="주요 파일 및 디렉터리의 소유자와 권한이 기준에 부합하여 이 항목에 대한 보안 위협이 없습니다."
  GUIDE_MSG="점검 대상 경로는 data=${DATA_DIR}, conf=${CONF_FILE}, hba=${HBA_FILE}, ident=${IDENT_FILE}, history=${HISTORY_FILE}, log_dir=${LOG_DIR} 입니다."
else
  EVIDENCE="주요 파일 및 디렉터리의 소유자 또는 권한이 기준을 초과하여 정보 노출 및 권한 오남용 위험이 있습니다.\n조치 방법은 취약 항목의 소유자를 ${PG_SUPERUSER} 또는 postgres로 정리하고, postgresql.conf/pg_hba.conf/pg_ident.conf 및 로그 파일은 640 이하, .psql_history는 600 이하로 설정해주시기 바랍니다."
  GUIDE_MSG="취약 항목은 ${EVIDENCE_LIST%,} 입니다. 설정 변경 후 동일 기준으로 재점검해주시기 바랍니다."
fi

# ===== 표준 출력(scan_history) =====
CHECK_COMMAND="stat 기반 주요 파일/디렉터리 권한·소유자 점검(data_directory/config_file/hba_file/log_directory/.psql_history)"
REASON_LINE="${EVIDENCE}"
DETAIL_CONTENT="${GUIDE_MSG}"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
TARGET_FILE="${DATA_DIR},${CONF_FILE},${HBA_FILE},${IDENT_FILE},${HISTORY_FILE},${LOG_DIR}"

escape_json_str() {
  echo "$1" | sed ':a;N;$!ba;s/\n/\\n/g' | sed 's/\\"/\\\\"/g; s/"/\\"/g'
}

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