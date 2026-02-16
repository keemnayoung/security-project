#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.1
# @Author: 권순형
# @Last Updated: 2026-02-15
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-30
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 중
# @Title       : UMASK 설정 관리
# @Description : 시스템 UMASK 값이 022 이상 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

## 기본 변수
ID="U-30"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

# (필수 보완) 실제 운영에서 많이 쓰는 전역 초기화 위치 포함
PROFILE_FILE="/etc/profile"
PROFILE_D_GLOB="/etc/profile.d/*.sh"
BASHRC_FILE="/etc/bashrc"
LOGIN_DEFS_FILE="/etc/login.defs"

TARGET_FILE="/etc/profile /etc/profile.d/*.sh /etc/bashrc /etc/login.defs"

CHECK_COMMAND='
[ -f /etc/profile ] && grep -inE "^[[:space:]]*umask[[:space:]]+[0-9]+" /etc/profile || echo "/etc/profile:not_found";
ls -1 /etc/profile.d/*.sh 1>/dev/null 2>&1 && grep -inE "^[[:space:]]*umask[[:space:]]+[0-9]+" /etc/profile.d/*.sh || echo "/etc/profile.d/*.sh:not_found_or_no_matches";
[ -f /etc/bashrc ] && grep -inE "^[[:space:]]*umask[[:space:]]+[0-9]+" /etc/bashrc || echo "/etc/bashrc:not_found";
[ -f /etc/login.defs ] && grep -inE "^[[:space:]]*UMASK[[:space:]]+[0-9]+" /etc/login.defs || echo "/etc/login.defs:not_found"
'

REASON_LINE=""
DETAIL_CONTENT=""
FOUND_ANY="N"
FOUND_VULN="N"

# 결과 수집: "file:line:setting:value" 형태로 저장
FOUND_LIST=()

# -----------------------------
# 함수: UMASK 값 추출(마지막 설정 우선)
# -----------------------------
get_umask_from_file() {
  local file="$1"
  local mode="$2"  # "lower"=umask, "upper"=UMASK
  if [ ! -f "$file" ]; then
    return 0
  fi

  if [ "$mode" = "lower" ]; then
    local line
    line=$(grep -inE '^[[:space:]]*umask[[:space:]]+[0-9]+' "$file" 2>/dev/null | tail -n 1)
    if [ -n "$line" ]; then
      local lno val
      lno=$(echo "$line" | cut -d: -f1)
      val=$(echo "$line" | awk '{print $2}')
      FOUND_LIST+=("${file}:${lno}:umask:${val}")
      FOUND_ANY="Y"
    fi
  else
    local line
    line=$(grep -inE '^[[:space:]]*UMASK[[:space:]]+[0-9]+' "$file" 2>/dev/null | tail -n 1)
    if [ -n "$line" ]; then
      local lno val
      lno=$(echo "$line" | cut -d: -f1)
      val=$(echo "$line" | awk '{print $2}')
      FOUND_LIST+=("${file}:${lno}:UMASK:${val}")
      FOUND_ANY="Y"
    fi
  fi
}

# -----------------------------
# 함수: UMASK 값이 "022 이상(=022 포함, 더 제한적이면 양호)"인지 판단
# - UMASK는 8진수로 해석
# - 022의 의미(그룹/기타 write 차단) 비트가 반드시 포함되어야 함
#   => (umask_value & 022) == 022
# -----------------------------
is_umask_ok() {
  local raw="$1"

  # 숫자만 추출(혹시 0022 같은 형태 대비)
  local v
  v=$(echo "$raw" | grep -oE '^[0-9]+' || true)
  [ -z "$v" ] && return 1

  # 8진수 변환 (8#)
  local dec
  dec=$((8#$v))

  # required=022(8진)
  local required=$((8#022))

  # required 비트 포함 여부
  if [ $(( dec & required )) -eq "$required" ]; then
    return 0
  fi
  return 1
}

# -----------------------------
# 실제 점검
# -----------------------------
# /etc/profile
get_umask_from_file "$PROFILE_FILE" "lower"

# /etc/profile.d/*.sh (존재하는 파일만)
if ls -1 $PROFILE_D_GLOB >/dev/null 2>&1; then
  for f in $PROFILE_D_GLOB; do
    get_umask_from_file "$f" "lower"
  done
fi

# /etc/bashrc
get_umask_from_file "$BASHRC_FILE" "lower"

# /etc/login.defs
get_umask_from_file "$LOGIN_DEFS_FILE" "upper"

# 판정
if [ "$FOUND_ANY" = "N" ]; then
  STATUS="FAIL"
  REASON_LINE="UMASK 설정이 주요 설정 파일(/etc/profile, /etc/profile.d/*.sh, /etc/bashrc, /etc/login.defs)에서 확인되지 않아 기본 파일 생성 권한이 과도하게 열릴 수 있으므로 취약합니다. UMASK 값을 022로 설정해야 합니다."
  DETAIL_CONTENT="no_umask_setting_found"
else
  # 하나라도 022 미만(=필수 비트 미포함)이면 FAIL 처리
  VULN_ITEMS=()
  OK_ITEMS=()

  for item in "${FOUND_LIST[@]}"; do
    # item="file:line:KEY:VAL"
    file=$(echo "$item" | cut -d: -f1)
    lno=$(echo "$item" | cut -d: -f2)
    key=$(echo "$item" | cut -d: -f3)
    val=$(echo "$item" | cut -d: -f4)

    if is_umask_ok "$val"; then
      OK_ITEMS+=("${file}:${lno} ${key}=${val}")
    else
      FOUND_VULN="Y"
      VULN_ITEMS+=("${file}:${lno} ${key}=${val}")
    fi
  done

  if [ "$FOUND_VULN" = "Y" ]; then
    STATUS="FAIL"
    REASON_LINE="UMASK 값이 022 미만(필수 차단 비트 미포함)으로 설정된 항목이 존재하여 새로 생성되는 파일/디렉터리 권한이 과도하게 부여될 수 있으므로 취약합니다. UMASK 값을 022(또는 더 제한적으로) 설정해야 합니다."
    DETAIL_CONTENT="vuln_items=$(printf "%s; " "${VULN_ITEMS[@]}")\nok_items=$(printf "%s; " "${OK_ITEMS[@]}")"
  else
    STATUS="PASS"
    REASON_LINE="UMASK 값이 022 이상(022 포함, 더 제한적이면 양호)으로 설정되어 새로 생성되는 파일/디렉터리 권한이 과도하게 부여되지 않으므로 이 항목은 양호합니다."
    DETAIL_CONTENT="ok_items=$(printf "%s; " "${OK_ITEMS[@]}")"
  fi
fi

# raw_evidence 구성 (첫 줄: 평가 이유 / 다음 줄부터: 현재 설정값)
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

# JSON escape 처리 (따옴표, 줄바꿈)
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/"/\\"/g' \
  | sed ':a;N;$!ba;s/\n/\\n/g')

# scan_history 저장용 JSON 출력
echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF