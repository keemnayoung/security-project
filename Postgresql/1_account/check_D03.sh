#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.1
# @Author: 윤영아
# @Last Updated: 2026-02-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-03
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : 비밀번호 사용기간 및 복잡도를 기관의 정책에 맞도록 설정
# @Description : DBMS 계정 비밀번호에 대해 복잡도 정책이 적용되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================


COMMON_FILE="$(cd "$(dirname "$0")/.." && pwd)/_pg_common.sh"
# shellcheck disable=SC1090
. "$COMMON_FILE"
load_pg_env

# D-03: 비밀번호 사용기간/복잡도 정책
ID="D-03"
STATUS="FAIL"
EVIDENCE="N/A"
GUIDE_MSG="N/A"

run_psql() {
  local sql="$1"
  if PGPASSWORD="${POSTGRES_PASSWORD:-}" psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DB" -t -A -q -c "$sql" 2>/dev/null; then
    return 0
  fi
  if command -v sudo >/dev/null 2>&1; then
    sudo -u "$PG_SUPERUSER" psql -d "$POSTGRES_DB" -t -A -q -c "$sql" 2>/dev/null
    return $?
  fi
  return 1
}

escape_json_str() {
  # JSON 문자열 안전 처리(\, ", 줄바꿈)
  echo "$1" | sed ':a;N;$!ba;s/\n/\\n/g' | sed 's/\\/\\\\/g; s/"/\\"/g'
}

# pg_hba.conf 실제 파일 경로 조회
HBA_FILE="$(run_psql "SHOW hba_file;")"
HBA_FILE="$(echo "$HBA_FILE" | head -n 1 | xargs)"

if [ -z "$HBA_FILE" ] || [ ! -f "$HBA_FILE" ]; then
  STATUS="FAIL"
  EVIDENCE="pg_hba.conf 경로를 확인하지 못하여 비밀번호 정책 적용 위치를 판단할 수 없습니다.\n조치 방법은 SHOW hba_file 결과와 파일 접근 권한을 확인해주시기 바랍니다."
  GUIDE_MSG="hba_file 경로 확인 및 파일 접근 권한을 점검해주시기 바랍니다."
else
  # pg_hba.conf에서 인증 방식(method) 목록 추출
  AUTH_METHODS="$(grep -Ev '^\s*#|^\s*$' "$HBA_FILE" 2>/dev/null | awk '{print $NF}' | sort -u | tr '\n' ',' | sed 's/,$//')"

  if echo "$AUTH_METHODS" | grep -Eq 'pam|ldap|gss|sspi'; then
    STATUS="PASS"
    EVIDENCE="외부 인증 방식(${AUTH_METHODS})이 사용되고 있어 비밀번호 정책을 OS 또는 중앙 인증 정책으로 관리할 수 있으므로 이 항목에 대한 보안 위협이 없습니다."
    GUIDE_MSG="기관 정책에 맞는 OS 또는 중앙 인증 비밀번호 정책이 적용되어 있는지 정기적으로 점검해주시기 바랍니다."
  elif echo "$AUTH_METHODS" | grep -Eq 'password|md5|scram-sha-256'; then
    # 로그인 가능 계정 중 만료 미설정(rolvaliduntil IS NULL) 계정 수 집계
    NO_EXPIRY_COUNT="$(run_psql "
SELECT count(*)
FROM pg_roles
WHERE rolcanlogin = true
  AND rolname NOT LIKE 'pg_%'
  AND rolvaliduntil IS NULL;
")"
    NO_EXPIRY_COUNT="$(echo "$NO_EXPIRY_COUNT" | xargs)"

    if [ -n "$NO_EXPIRY_COUNT" ] && [ "$NO_EXPIRY_COUNT" -eq 0 ] 2>/dev/null; then
      STATUS="PASS"
      EVIDENCE="DB 내부 인증(${AUTH_METHODS})이 사용되며 로그인 계정의 만료 정책이 적용되어 있으므로 이 항목에 대한 보안 위협이 없습니다."
      GUIDE_MSG="비밀번호 복잡도 정책은 PAM 또는 LDAP 연계, 또는 운영 정책으로 별도 관리해주시기 바랍니다."
    else
      STATUS="FAIL"
      EVIDENCE="DB 내부 인증(${AUTH_METHODS})이 사용되며 로그인 계정에 만료 정책이 적용되지 않았을 가능성이 있어 장기간 비밀번호 사용으로 인한 계정 탈취 위험이 있습니다.\n조치 방법은 로그인 계정에 VALID UNTIL 만료 정책을 적용하고, 필요 시 PAM 또는 LDAP 연계를 통해 기관 비밀번호 정책을 충족해주시기 바랍니다."
      GUIDE_MSG="만료 미설정 로그인 계정이 존재할 수 있습니다. 예) ALTER ROLE <계정명> VALID UNTIL '<YYYY-MM-DD>'; 를 적용해주시기 바랍니다. 또한 인증체계(PAM/LDAP) 연계를 검토해주시기 바랍니다."
    fi
  else
    STATUS="FAIL"
    EVIDENCE="pg_hba.conf 인증 방식(${AUTH_METHODS})을 기준으로 비밀번호 정책 적용 위치를 판별할 수 없어 점검 결과를 확정할 수 없습니다.\n조치 방법은 pg_hba.conf 인증 방식과 정책 적용 위치(DB/OS/중앙 인증)를 수동으로 점검해주시기 바랍니다."
    GUIDE_MSG="pg_hba.conf의 인증 방식과 비밀번호 정책 적용 위치를 확인해주시기 바랍니다."
  fi
fi

SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
CHECK_COMMAND="(psql 접속) SHOW hba_file; 후 pg_hba.conf의 인증 방식($AUTH_METHODS) 및 pg_roles(rolvaliduntil) 만료 미설정 계정 수 확인"
TARGET_FILE="$HBA_FILE"

REASON_LINE="$EVIDENCE"
DETAIL_CONTENT="$GUIDE_MSG"

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