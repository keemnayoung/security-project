#!/bin/bash
# ============================================================================
# MySQL 보안 조치 래퍼 스크립트
# 목적: 입력값이 필요한 fix 스크립트를 한 번에 실행
# 사용:
#   1) 환경파일 준비(예: mysql_fix.env)
#   2) sudo bash remediate_with_inputs.sh --env-file ./mysql_fix.env
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

APPLY_TARGETS="${APPLY_TARGETS:-D01,D06,D10,D11,D08,D07,D25}"
RUN_CHECKS="${RUN_CHECKS:-Y}"
ENV_FILE=""

usage() {
  cat <<'EOF'
Usage:
  bash scripts/unix/6_db/mysql/remediate_with_inputs.sh [--env-file <path>]

Options:
  --env-file <path>   환경변수 파일 로드 (KEY=VALUE 형식)
  -h, --help          도움말 출력

필수/권장 변수(타겟별):
  D01: NEW_PASS
  D06: COMMON_USER, COMMON_HOST, NEW_USER, NEW_HOST, NEW_PASS, PRIV_SCOPE, DB_NAME, PRIV_LIST
      (PRIV_SCOPE=TABLE 이면 TABLE_NAME 추가)
  D10: TARGET_USER, ALLOW_HOST (fallback 대비 NEW_PASS 권장)
  D11: TARGET_USER, TARGET_HOST, KEEP_SCOPE
      (KEEP_SCOPE=TABLE 이면 KEEP_DB, KEEP_TABLE, KEEP_PRIV_LIST)
      (KEEP_SCOPE=DB    이면 KEEP_DB, KEEP_PRIV_LIST)
  D08: 취약 계정 발견 시 아래 중 하나 필요
      - D08_TARGET_USER,D08_TARGET_HOST,D08_TARGET_PASS
      - TARGET_ACCOUNTS_CSV
      - AUTO_FIX_ALL=Y + DEFAULT_TARGET_PASS
  D07: 보통 불필요, 자동탐지 실패 시 MY_CNF 필요
  D25: 저장소 기준 확인 불가 환경이면 VENDOR_LATEST_VERSION 권장

실행 타겟 제어:
  APPLY_TARGETS='D01,D10,D11' RUN_CHECKS=Y bash .../remediate_with_inputs.sh --env-file ./mysql_fix.env
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --env-file)
      shift
      ENV_FILE="${1:-}"
      [[ -z "$ENV_FILE" ]] && { echo "[ERROR] --env-file 경로가 비어 있습니다."; exit 1; }
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[ERROR] 알 수 없는 옵션: $1"
      usage
      exit 1
      ;;
  esac
  shift
done

if [[ -n "$ENV_FILE" ]]; then
  if [[ ! -f "$ENV_FILE" ]]; then
    echo "[ERROR] 환경파일을 찾을 수 없습니다: $ENV_FILE"
    exit 1
  fi
  # shellcheck disable=SC1090
  source "$ENV_FILE"
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "[ERROR] root 권한으로 실행하세요. (sudo 권장)"
  exit 1
fi

RUN_CHECKS="$(echo "$RUN_CHECKS" | tr '[:lower:]' '[:upper:]')"
if [[ "$RUN_CHECKS" != "Y" && "$RUN_CHECKS" != "N" ]]; then
  echo "[ERROR] RUN_CHECKS 값은 Y 또는 N 이어야 합니다."
  exit 1
fi

contains_target() {
  local target="$1"
  local norm=",$(echo "$APPLY_TARGETS" | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]'),"
  [[ "$norm" == *",$target,"* ]]
}

require_vars() {
  local label="$1"
  shift
  local missing=()
  local key
  for key in "$@"; do
    if [[ -z "${!key:-}" ]]; then
      missing+=("$key")
    fi
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    echo "[ERROR] ${label} 필수 변수 누락: ${missing[*]}"
    return 1
  fi
  return 0
}

echo "[INFO] 선택 타겟: $APPLY_TARGETS"
echo "[INFO] 점검 재실행: RUN_CHECKS=$RUN_CHECKS"

# 사전 검증
if contains_target "D01"; then
  require_vars "D01" NEW_PASS || exit 1
fi

if contains_target "D06"; then
  require_vars "D06" COMMON_USER COMMON_HOST NEW_USER NEW_HOST NEW_PASS PRIV_SCOPE DB_NAME PRIV_LIST || exit 1
  PRIV_SCOPE_UP="$(echo "${PRIV_SCOPE}" | tr '[:lower:]' '[:upper:]')"
  if [[ "$PRIV_SCOPE_UP" == "TABLE" ]]; then
    require_vars "D06(TABLE)" TABLE_NAME || exit 1
  fi
fi

if contains_target "D10"; then
  require_vars "D10" TARGET_USER ALLOW_HOST || exit 1
fi

if contains_target "D11"; then
  require_vars "D11" TARGET_USER TARGET_HOST KEEP_SCOPE || exit 1
  KEEP_SCOPE_UP="$(echo "${KEEP_SCOPE}" | tr '[:lower:]' '[:upper:]')"
  if [[ "$KEEP_SCOPE_UP" == "TABLE" ]]; then
    require_vars "D11(TABLE)" KEEP_DB KEEP_TABLE KEEP_PRIV_LIST || exit 1
  elif [[ "$KEEP_SCOPE_UP" == "DB" ]]; then
    require_vars "D11(DB)" KEEP_DB KEEP_PRIV_LIST || exit 1
  fi
fi

if contains_target "D08"; then
  if [[ -n "${D08_TARGET_USER:-}" || -n "${D08_TARGET_HOST:-}" || -n "${D08_TARGET_PASS:-}" ]]; then
    require_vars "D08(단일 대상)" D08_TARGET_USER D08_TARGET_HOST D08_TARGET_PASS || exit 1
  elif [[ -n "${TARGET_ACCOUNTS_CSV:-}" ]]; then
    :
  elif [[ "${AUTO_FIX_ALL:-N}" =~ ^[Yy]$ ]]; then
    require_vars "D08(일괄 전환)" DEFAULT_TARGET_PASS || exit 1
  else
    echo "[WARN] D08은 취약 계정이 있을 경우 입력값이 필요합니다."
  fi
fi

if contains_target "D25" && [[ -z "${VENDOR_LATEST_VERSION:-}" ]]; then
  echo "[WARN] D25는 환경에 따라 VENDOR_LATEST_VERSION 미지정 시 FAIL 날 수 있습니다."
fi

run_fix_and_optional_check() {
  local id="$1"
  local fix_rel="$2"
  local check_rel="$3"
  local fix_path="${SCRIPT_DIR}/${fix_rel}"
  local check_path="${SCRIPT_DIR}/${check_rel}"

  echo ""
  echo "[INFO] ===== ${id} FIX 시작 ====="
  bash "$fix_path"

  if [[ "$RUN_CHECKS" == "Y" ]]; then
    echo "[INFO] ----- ${id} CHECK 시작 -----"
    bash "$check_path"
  fi
}

# D01 수행 후 후속 체크/조치를 위해 MYSQL_PWD 자동 동기화
if contains_target "D01"; then
  run_fix_and_optional_check "D01" "1_account/fix_D01.sh" "1_account/check_D01.sh"
  if [[ -z "${MYSQL_PWD:-}" ]]; then
    export MYSQL_PWD="${NEW_PASS}"
    echo "[INFO] MYSQL_PWD를 NEW_PASS로 설정했습니다. (후속 스크립트 접속용)"
  fi
fi

if contains_target "D06"; then
  run_fix_and_optional_check "D06" "1_account/fix_D06.sh" "1_account/check_D06.sh"
fi

if contains_target "D10"; then
  run_fix_and_optional_check "D10" "2_access/fix_D10.sh" "2_access/check_D10.sh"
fi

if contains_target "D11"; then
  run_fix_and_optional_check "D11" "2_access/fix_D11.sh" "2_access/check_D11.sh"
fi

if contains_target "D08"; then
  # D10/D11의 TARGET_* 변수와 충돌하지 않도록 D08 실행 시점에 전용 변수로 주입
  unset TARGET_USER TARGET_HOST TARGET_PASS
  if [[ -n "${D08_TARGET_USER:-}" || -n "${D08_TARGET_HOST:-}" || -n "${D08_TARGET_PASS:-}" ]]; then
    export TARGET_USER="${D08_TARGET_USER}"
    export TARGET_HOST="${D08_TARGET_HOST}"
    export TARGET_PASS="${D08_TARGET_PASS}"
  fi
  run_fix_and_optional_check "D08" "1_account/fix_D08.sh" "1_account/check_D08.sh"
fi

if contains_target "D07"; then
  run_fix_and_optional_check "D07" "1_account/fix_D07.sh" "1_account/check_D07.sh"
fi

if contains_target "D25"; then
  run_fix_and_optional_check "D25" "4_patch/fix_D25.sh" "4_patch/check_D25.sh"
fi

echo ""
echo "[DONE] 선택한 조치 스크립트 실행이 완료되었습니다."
