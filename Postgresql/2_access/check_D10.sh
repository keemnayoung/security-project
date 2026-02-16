#!/bin/bash
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-10
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : 원격에서 DB 서버로의 접속 제한
# @Description : 지정된 IP 주소에서만 DB 서버 접속이 허용되는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

COMMON_FILE="$(cd "$(dirname "$0")/.." && pwd)/_pg_common.sh"
# shellcheck disable=SC1090
. "$COMMON_FILE"
load_pg_env

ID="D-10"
STATUS="FAIL"
EVIDENCE="N/A"
GUIDE_MSG="N/A"

# postgresql.conf 실제 경로 조회
CONF_FILE=$(run_psql "SHOW config_file;" | xargs)
# pg_hba.conf 실제 경로 조회
HBA_FILE=$(run_psql "SHOW hba_file;" | xargs)
# listen_addresses 설정값 조회
LISTEN_ADDR=$(run_psql "SHOW listen_addresses;" | xargs)

resolve_conf_path() {
  local p="$1"
  if [ -n "$p" ] && [ -f "$p" ]; then
    printf '%s' "$p"
    return 0
  fi
  if [ -n "${PGDATA:-}" ] && [ -f "${PGDATA}/postgresql.conf" ]; then
    printf '%s' "${PGDATA}/postgresql.conf"
    return 0
  fi
  return 1
}

resolve_hba_path() {
  local p="$1"
  if [ -n "$p" ] && [ -f "$p" ]; then
    printf '%s' "$p"
    return 0
  fi
  if [ -n "${PGDATA:-}" ] && [ -f "${PGDATA}/pg_hba.conf" ]; then
    printf '%s' "${PGDATA}/pg_hba.conf"
    return 0
  fi
  return 1
}

extract_listen_addresses_from_file() {
  local f="$1"
  [ -n "$f" ] && [ -f "$f" ] || return 1
  awk '
    /^[[:space:]]*#/ || /^[[:space:]]*$/ {next}
    {
      line=$0
      sub(/[[:space:]]*#.*/,"",line)
      if (line ~ /^[[:space:]]*listen_addresses[[:space:]]*=/) {
        sub(/^[[:space:]]*listen_addresses[[:space:]]*=/,"",line)
        gsub(/^[[:space:]]+/,"",line); gsub(/[[:space:]]+$/,"",line)
        gsub(/^'\''/,"",line); gsub(/'\''$/,"",line)
        gsub(/^"/,"",line); gsub(/"$/,"",line)
        v=line
      }
    }
    END{ if (v!="") print v }
  ' "$f"
}

is_listen_safe() {
  local raw="$1"
  raw=$(printf '%s' "$raw" | tr -d "'\"" | tr -d '[:space:]')
  [ -n "$raw" ] || return 1
  printf '%s' "$raw" | tr ',' '\n' | awk '
    BEGIN{ok=1}
    {
      t=tolower($0)
      if (t=="" ) next
      if (t!="localhost" && t!="127.0.0.1" && t!="::1") ok=0
    }
    END{exit(ok?0:1)}
  '
}

is_loopback_addr() {
  local addr="$1"
  addr=$(printf '%s' "$addr" | tr -d "'\"" | tr -d '[:space:]')
  printf '%s' "$addr" | awk '
    {a=tolower($0)}
    END{
      if (a=="localhost" || a=="samehost") exit 0
      if (a=="127.0.0.1/32" || a=="127.0.0.0/8" || a=="127.0.0.1") exit 0
      if (a=="::1/128" || a=="::1") exit 0
      exit 1
    }
  '
}

is_open_addr() {
  local addr="$1"
  addr=$(printf '%s' "$addr" | tr -d "'\"" | tr -d '[:space:]')
  printf '%s' "$addr" | awk '
    {a=tolower($0)}
    END{
      if (a=="*" || a=="all" || a=="0.0.0.0/0" || a=="::/0" || a=="::0/0" || a=="0/0") exit 0
      exit 1
    }
  '
}

HBA_FILE_RESOLVED="$(resolve_hba_path "$HBA_FILE" 2>/dev/null || true)"
if [ -n "$HBA_FILE_RESOLVED" ] && [ -f "$HBA_FILE_RESOLVED" ]; then
  HBA_FILE="$HBA_FILE_RESOLVED"
fi

if [ -z "${LISTEN_ADDR:-}" ]; then
  CONF_FILE_RESOLVED="$(resolve_conf_path "$CONF_FILE" 2>/dev/null || true)"
  AUTO_CONF=""
  if [ -n "${PGDATA:-}" ] && [ -f "${PGDATA}/postgresql.auto.conf" ]; then
    AUTO_CONF="${PGDATA}/postgresql.auto.conf"
  fi
  LISTEN_ADDR="$(extract_listen_addresses_from_file "$AUTO_CONF" 2>/dev/null || true)"
  [ -z "${LISTEN_ADDR:-}" ] && LISTEN_ADDR="$(extract_listen_addresses_from_file "$CONF_FILE_RESOLVED" 2>/dev/null || true)"
fi

if [ -z "$HBA_FILE" ] || [ ! -f "$HBA_FILE" ]; then
  STATUS="FAIL"
  EVIDENCE="pg_hba.conf 경로를 확인하지 못하여 원격 접속 허용 범위를 점검할 수 없습니다.\n조치 방법은 SHOW hba_file 결과와 파일 접근 권한을 확인해주시기 바랍니다."
  GUIDE_MSG="hba_file 경로 확인 및 파일 접근 권한을 점검해주시기 바랍니다."
else
  HOST_SUMMARY=$(
    awk '
      /^[[:space:]]*#/ || /^[[:space:]]*$/ {next}
      {
        line=NR
        sub(/[[:space:]]*#.*/,"")
        gsub(/[[:space:]]+/," ",$0)
        sub(/^ /,""); sub(/ $/,"")
        split($0,a," ")
        if (tolower(a[1]) ~ /^host/) {
          if (length(a) >= 5) {
            printf "line:%s type=%s db=%s user=%s addr=%s method=%s\n", line,a[1],a[2],a[3],a[4],a[length(a)]
          }
        }
      }
    ' "$HBA_FILE"
  )

  ALLOWED_ADDR=$(
    printf '%s\n' "$HOST_SUMMARY" | awk -F'addr=| method=' 'NF>=3{print $2}' | sort -u | tr '\n' ',' | sed 's/,$//'
  )

  TRUST_LINES=$(
    printf '%s\n' "$HOST_SUMMARY" | awk '/[[:space:]]method=trust([[:space:]]|$)/{sub(/^line:/,"",$1); sub(/[^0-9].*$/,"",$1); print $1}' | tr '\n' ',' | sed 's/,$//'
  )

  OPEN_ADDR=""
  LOOPBACK_ADDR=""
  REMOTE_ADDR=""
  OTHER_ADDR=""
  if [ -n "$ALLOWED_ADDR" ]; then
    while IFS= read -r addr; do
      [ -n "$addr" ] || continue
      if is_loopback_addr "$addr"; then
        LOOPBACK_ADDR+="${addr},"
      elif is_open_addr "$addr"; then
        OPEN_ADDR+="${addr},"
        REMOTE_ADDR+="${addr},"
      else
        OTHER_ADDR+="${addr},"
        REMOTE_ADDR+="${addr},"
      fi
    done < <(printf '%s' "$ALLOWED_ADDR" | tr ',' '\n')
  fi
  OPEN_ADDR=$(printf '%s' "$OPEN_ADDR" | sed 's/,$//')
  LOOPBACK_ADDR=$(printf '%s' "$LOOPBACK_ADDR" | sed 's/,$//')
  REMOTE_ADDR=$(printf '%s' "$REMOTE_ADDR" | sed 's/,$//')
  OTHER_ADDR=$(printf '%s' "$OTHER_ADDR" | sed 's/,$//')

  LISTEN_STATUS="취약"
  if is_listen_safe "${LISTEN_ADDR:-}"; then
    LISTEN_STATUS="허용"
  fi

  # D-10 범위: 원격 접속 제한(주소/바인딩)
  if [ "$LISTEN_STATUS" != "허용" ] || [ -n "$OPEN_ADDR" ] || [ -n "$OTHER_ADDR" ]; then
    STATUS="FAIL"
    EVIDENCE="listen_addresses=${LISTEN_ADDR:-unknown} (${LISTEN_STATUS})이며 pg_hba.conf에서 원격 CIDR 허용이 확인되어 무단 원격 접속 위험이 있습니다.\n조치 방법은 listen_addresses를 루프백(localhost/127.0.0.1/::1)만 남기고, pg_hba.conf의 open 대역(*, all, 0.0.0.0/0, ::/0 등) 및 불필요 원격 CIDR을 제거하거나 필요 최소 대역만 남겨주시기 바랍니다."
    GUIDE_MSG="CIDR-ADDRESS 전체는 ${ALLOWED_ADDR:-없음} 입니다. open 대역은 ${OPEN_ADDR:-없음} 이며, 루프백 허용은 ${LOOPBACK_ADDR:-없음} 이고, 기타 원격 CIDR은 ${OTHER_ADDR:-없음} 입니다. 설정 적용 후 postgresql 서비스를 재시작 또는 리로드한 뒤 재점검해주시기 바랍니다. trust METHOD 라인은 ${TRUST_LINES:-없음} 입니다."
  else
    STATUS="PASS"
    EVIDENCE="listen_addresses=${LISTEN_ADDR:-unknown} (${LISTEN_STATUS})이며 pg_hba.conf에서 open 대역 및 불필요 원격 CIDR이 확인되지 않아 원격 접속이 제한되어 있으므로 이 항목에 대한 보안 위협이 없습니다."
    GUIDE_MSG="CIDR-ADDRESS 전체는 ${ALLOWED_ADDR:-없음} 이며, 루프백 허용은 ${LOOPBACK_ADDR:-없음} 입니다. trust METHOD 라인은 ${TRUST_LINES:-없음} 입니다."
  fi
fi

# ===== 표준 출력(scan_history) =====
CHECK_COMMAND="SHOW config_file; SHOW hba_file; SHOW listen_addresses; parse pg_hba.conf(listen_addresses/CIDR-ADDRESS)"
REASON_LINE="${EVIDENCE}"
DETAIL_CONTENT="${GUIDE_MSG}"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

escape_json_str() {
  echo "$1" | sed ':a;N;$!ba;s/\n/\\n/g' | sed 's/\\"/\\\\"/g; s/"/\\"/g'
}

RAW_EVIDENCE_JSON=$(cat <<EOF
{
  "command":"$(escape_json_str "$CHECK_COMMAND")",
  "detail":"$(escape_json_str "${REASON_LINE}\n${DETAIL_CONTENT}")",
  "target_file":"$(escape_json_str "${HBA_FILE:-unknown}")"
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