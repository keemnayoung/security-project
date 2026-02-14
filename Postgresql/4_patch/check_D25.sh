#!/bin/bash
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-25
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : 데이터베이스의 접근, 변경, 삭제 등의 감사 기록이 기관의 감사 기록 정책에 적합하도록 설정
# @Description : 감사 기록 정책 설정이 기관 정책에 적합하게 설정되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================



COMMON_FILE="$(cd "$(dirname "$0")/.." && pwd)/_pg_common.sh"
# shellcheck disable=SC1090
. "$COMMON_FILE"
load_pg_env

ID="D-25"
STATUS="FAIL"
EVIDENCE="N/A"
GUIDE_MSG="N/A"

# PostgreSQL Versioning Policy (snapshot: 2026-02)
# format: major|current_minor|supported|final_release(YYYY-MM-DD)
PG_VERSION_POLICY="${PG_VERSION_POLICY:-18|18.2|Yes|2030-11-14;17|17.8|Yes|2029-11-08;16|16.12|Yes|2028-11-09;15|15.16|Yes|2027-11-11;14|14.21|Yes|2026-11-12;13|13.23|No|2025-11-13;12|12.22|No|2024-11-21;11|11.22|No|2023-11-09;10|10.23|No|2022-11-10;9.6|9.6.24|No|2021-11-11}"

VERSION="$(run_psql "SHOW server_version;" | xargs)"
VERSION="$(echo "$VERSION" | awk '{print $1}')"

normalize_major() {
  local v="$1"
  local a b
  a="$(echo "$v" | cut -d'.' -f1)"
  b="$(echo "$v" | cut -d'.' -f2)"
  if [ -z "$a" ] || ! echo "$a" | grep -Eq '^[0-9]+$'; then
    echo ""
    return
  fi
  if [ "$a" -ge 10 ]; then
    echo "$a"
  else
    [ -z "$b" ] && b="0"
    echo "$a.$b"
  fi
}

vercmp() {
  # prints: -1 (a<b), 0 (a=b), 1 (a>b)
  local a="$1" b="$2"
  local ai bi i
  IFS='.' read -r -a A <<< "$a"
  IFS='.' read -r -a B <<< "$b"
  local n="${#A[@]}"
  [ "${#B[@]}" -gt "$n" ] && n="${#B[@]}"
  for ((i=0; i<n; i++)); do
    ai="${A[$i]:-0}"
    bi="${B[$i]:-0}"
    ai="${ai%%[^0-9]*}"
    bi="${bi%%[^0-9]*}"
    [ -z "$ai" ] && ai=0
    [ -z "$bi" ] && bi=0
    if [ "$ai" -lt "$bi" ]; then
      echo -1
      return
    fi
    if [ "$ai" -gt "$bi" ]; then
      echo 1
      return
    fi
  done
  echo 0
}

policy_lookup() {
  local key="$1"
  echo "$PG_VERSION_POLICY" | tr ';' '\n' | awk -F'|' -v k="$key" '$1==k {print; exit}'
}

detect_pkg_query_name() {
  # Pick an installed server package name to use for dnf --showduplicates.
  if command -v rpm >/dev/null 2>&1; then
    rpm -qa --qf '%{NAME}\n' 2>/dev/null \
      | grep -E '^postgresql([0-9]+)?-server$' \
      | head -n 1
  fi
}

repo_has_target_minor() {
  local pkg="$1"
  local minor="$2"
  command -v dnf >/dev/null 2>&1 || return 2
  [ -n "$pkg" ] || return 2
  [ -n "$minor" ] || return 2

  dnf --showduplicates list "$pkg" 2>/dev/null | grep -Fq "$minor"
  return $?
}

if [ -z "$VERSION" ]; then
  STATUS="FAIL"
  EVIDENCE="PostgreSQL 버전 조회 실패"
  GUIDE_MSG="DB 접속 정보를 확인하십시오."
else
  TODAY="$(date '+%Y-%m-%d')"
  MAJOR_KEY="$(normalize_major "$VERSION")"
  POLICY_ROW="$(policy_lookup "$MAJOR_KEY")"

  if [ -z "$MAJOR_KEY" ] || [ -z "$POLICY_ROW" ]; then
    STATUS="FAIL"
    EVIDENCE="현재 버전: PostgreSQL $VERSION (정책 테이블 미등록 메이저)"
    GUIDE_MSG="PG_VERSION_POLICY 값을 최신 PostgreSQL Versioning Policy에 맞게 갱신하십시오."
  else
    POLICY_MINOR="$(echo "$POLICY_ROW" | awk -F'|' '{print $2}')"
    POLICY_SUPPORTED="$(echo "$POLICY_ROW" | awk -F'|' '{print $3}')"
    POLICY_FINAL="$(echo "$POLICY_ROW" | awk -F'|' '{print $4}')"
    CMP="$(vercmp "$VERSION" "$POLICY_MINOR")"

    if [ "$POLICY_SUPPORTED" != "Yes" ] || [ "$TODAY" \> "$POLICY_FINAL" ]; then
      STATUS="FAIL"
      EVIDENCE="현재 버전: PostgreSQL $VERSION / 메이저 $MAJOR_KEY 지원종료(EOL, final=$POLICY_FINAL)"
      GUIDE_MSG="메이저 업그레이드가 필요합니다. pg_upgrade 또는 dump/restore 방식으로 지원 버전(14~18)으로 이전하십시오."
    elif [ "$CMP" -lt 0 ]; then
      STATUS="FAIL"
      EVIDENCE="현재 버전: PostgreSQL $VERSION / 권장 최신 minor: $POLICY_MINOR (메이저 $MAJOR_KEY 지원중)"
      PKG_QUERY="$(detect_pkg_query_name)"
      ONE_LINER="dnf --showduplicates list ${PKG_QUERY:-postgresql-server} | tail -n 30"
      REPO_HINT=""
      if [ -n "$PKG_QUERY" ]; then
        if repo_has_target_minor "$PKG_QUERY" "$POLICY_MINOR"; then
          REPO_HINT="레포에 ${POLICY_MINOR} 패키지가 존재합니다. 업데이트/재시작으로 반영 가능합니다."
        else
          REPO_HINT="레포에 ${POLICY_MINOR} 패키지가 보이지 않습니다. 이 경우 자동 업데이트로는 반영되지 않으며, 레포/미러 동기화 또는 표준 레포 전환이 먼저입니다."
        fi
      fi
      GUIDE_MSG="동일 메이저($MAJOR_KEY.x) 최신 minor($POLICY_MINOR)로 업데이트하십시오. minor 업데이트는 정지-바이너리업데이트-재시작 절차로 적용 가능합니다.\n\n운영에서 FAIL 시 1줄 확인:\n${ONE_LINER}\n- 위 목록에 ${POLICY_MINOR}가 없으면: 레포/lock/exclude 문제로 업데이트 불가\n- ${POLICY_MINOR}가 있으면: 업데이트 후 재시작 및 버전 재확인\n${REPO_HINT}"
    else
      STATUS="PASS"
      EVIDENCE="지원 버전 사용 중: PostgreSQL $VERSION (정책 기준 major=$MAJOR_KEY, latest_minor=$POLICY_MINOR, final=$POLICY_FINAL)"
      GUIDE_MSG="현재 기준에서 추가 조치가 필요하지 않습니다."
    fi
  fi
fi

if [ "$STATUS" = "PASS" ] && [ -n "${MAJOR_KEY:-}" ] && [ -n "${POLICY_ROW:-}" ]; then
  CMP_AHEAD="$(vercmp "$VERSION" "$(echo "$POLICY_ROW" | awk -F'|' '{print $2}')")"
  if [ "$CMP_AHEAD" -gt 0 ]; then
    STATUS="FAIL"
    EVIDENCE="현재 버전: PostgreSQL $VERSION (정책 테이블의 최신 minor보다 높음, 정책 테이블 갱신 필요 가능)"
    GUIDE_MSG="PG_VERSION_POLICY 값을 PostgreSQL 공식 Versioning Policy에 맞춰 갱신하십시오."
  fi
fi

if [ "$STATUS" = "FAIL" ] && [ -z "$GUIDE_MSG" ]; then
  GUIDE_MSG="기관 정책 및 벤더 권고에 맞는 최신 보안 패치 버전으로 업데이트하십시오."
fi

if [ "$STATUS" = "PASS" ] && [ -z "$EVIDENCE" ]; then
  STATUS="PASS"
  EVIDENCE="지원 버전 사용 중: PostgreSQL $VERSION"
  GUIDE_MSG="주기적으로 PostgreSQL 공식 보안 공지를 확인하십시오."
fi

# ===== 표준 출력(scan_history) =====
CHECK_COMMAND="SHOW server_version; 및 PG_VERSION_POLICY(메이저별 최신 minor/지원여부/EOL) 비교로 보안 패치 적용 여부 판정"
REASON_LINE="D-25 ${STATUS}: ${EVIDENCE}"
DETAIL_CONTENT="${GUIDE_MSG}"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
TARGET_FILE="server_version"

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