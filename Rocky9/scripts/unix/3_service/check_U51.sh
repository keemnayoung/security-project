#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.2.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-51
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : DNS 서비스의 취약한 동적 업데이트 설정 금지
# @Description : allow-update 설정이 전체 허용(any/*/0.0.0.0/0)인지 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-51"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""

CHECK_COMMAND='systemctl is-active named named-chroot; pgrep -x named; grep -nE "^[[:space:]]*include[[:space:]]+\"" /etc/named.conf /etc/bind/named.conf /etc/bind/named.conf.options 2>/dev/null; grep -nE "allow-update[[:space:]]*\\{" /etc/named.conf /etc/bind/named.conf /etc/bind/named.conf.options 2>/dev/null'

VULNERABLE=0
FOUND_ANY=0
DETAIL_LINES=""

append_detail() {
  local line="$1"
  [ -z "$line" ] && return 0
  if [ -z "$DETAIL_LINES" ]; then
    DETAIL_LINES="$line"
  else
    DETAIL_LINES="${DETAIL_LINES}\n$line"
  fi
}

add_target_file() {
  local f="$1"
  [ -z "$f" ] && return 0
  if [ -z "$TARGET_FILE" ]; then
    TARGET_FILE="$f"
  else
    TARGET_FILE="${TARGET_FILE}, $f"
  fi
}

# -----------------------------
# named 실행 여부 확인
# -----------------------------
is_named_running() {
  systemctl is-active --quiet named 2>/dev/null && return 0
  systemctl is-active --quiet named-chroot 2>/dev/null && return 0
  pgrep -x named >/dev/null 2>&1 && return 0
  return 1
}

# include "..." 재귀 추적하여 설정 파일 목록 수집(중복 제거)
collect_named_conf_files() {
  local -a seeds=("$@")
  local -a queue=()
  local -a out=()
  local -a seen_list=()
  local f dir inc inc_path seen_file

  for f in "${seeds[@]}"; do
    [ -f "$f" ] && queue+=("$f")
  done

  while [ "${#queue[@]}" -gt 0 ]; do
    f="${queue[0]}"
    queue=("${queue[@]:1}")

    [ -f "$f" ] || continue

    # 중복 제거(배열로 단순 체크)
    local already="N"
    for seen_file in "${seen_list[@]}"; do
      [ "$seen_file" = "$f" ] && already="Y" && break
    done
    [ "$already" = "Y" ] && continue

    seen_list+=("$f")
    out+=("$f")

    dir="$(dirname "$f")"
    while IFS= read -r inc; do
      [ -z "$inc" ] && continue
      if [[ "$inc" = /* ]]; then
        inc_path="$inc"
      else
        inc_path="${dir}/${inc}"
      fi
      [ -f "$inc_path" ] && queue+=("$inc_path")
    done < <(grep -hE '^[[:space:]]*include[[:space:]]+"' "$f" 2>/dev/null | sed -E 's/.*"([^"]+)".*/\1/')
  done

  printf '%s\n' "${out[@]}"
}

# allow-update 내용이 과도하게 열려있는지(대표 시그널)
is_allow_update_wide_open() {
  # any, *, 0.0.0.0/0, 0.0.0.0 등 포함 시 wide open으로 판단
  echo "$1" | grep -qE '(\bany\b|\*|0\.0\.0\.0(/0)?|\:\:/0)'
}

# -----------------------------
# 진단 시작
# -----------------------------
CONF_SEEDS=("/etc/named.conf" "/etc/bind/named.conf.options" "/etc/bind/named.conf")

if ! is_named_running; then
  STATUS="PASS"
  REASON_LINE="DNS(named) 서비스가 비활성화되어 점검 대상이 없습니다."
  DETAIL_CONTENT="none"
else
  FOUND_ANY=1

  mapfile -t CONF_FILES < <(collect_named_conf_files "${CONF_SEEDS[@]}")

  if [ "${#CONF_FILES[@]}" -eq 0 ]; then
    STATUS="FAIL"
    VULNERABLE=1
    REASON_LINE="DNS 서비스가 실행 중이나 설정 파일(/etc/named.conf 등)을 찾지 못해 동적 업데이트(allow-update) 제한 여부를 확인할 수 없어 취약합니다. 설정 파일 위치를 확인하고 allow-update 정책을 점검해야 합니다."
    DETAIL_CONTENT="conf_files=none"
  else
    append_detail "[info] named_running=Y"
    append_detail "[info] conf_files=$(printf "%s " "${CONF_FILES[@]}" | sed 's/[[:space:]]$//')"

    found_any_allow_update=0
    wide_open_count=0
    restricted_count=0

    for f in "${CONF_FILES[@]}"; do
      add_target_file "$f"

      # allow-update는 여러 개가 있을 수 있으므로 전부 확인(주석 제외)
      while IFS= read -r line; do
        [ -z "$line" ] && continue
        found_any_allow_update=1

        if is_allow_update_wide_open "$line"; then
          VULNERABLE=1
          wide_open_count=$((wide_open_count + 1))
          append_detail "[check] $f allow-update=WIDE_OPEN | $(echo "$line" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g')"
        else
          restricted_count=$((restricted_count + 1))
          append_detail "[check] $f allow-update=SET(restricted?) | $(echo "$line" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g')"
        fi
      done < <(grep -vE '^[[:space:]]*#' "$f" 2>/dev/null | grep -E 'allow-update[[:space:]]*\{' || true)
    done

    if [ "$VULNERABLE" -eq 1 ]; then
      STATUS="FAIL"
      REASON_LINE="DNS 동적 업데이트(allow-update) 허용 대상이 과도하게 열려 있어 취약합니다. 비인가 사용자가 DNS 레코드를 변경할 수 있으므로 동적 업데이트가 불필요하면 allow-update를 none으로 차단하고, 필요한 경우에도 허용 IP 또는 키(TSIG)만으로 제한해야 합니다."
    else
      STATUS="PASS"
      if [ "$found_any_allow_update" -eq 1 ]; then
        REASON_LINE="DNS 동적 업데이트(allow-update)가 제한되어 있어 이 항목에 대한 보안 위협이 없습니다."
      else
        REASON_LINE="allow-update 설정이 없어 DNS 동적 업데이트가 차단되어 있어 이 항목에 대한 보안 위협이 없습니다."
      fi
    fi

    append_detail "[summary] allow_update_found=$found_any_allow_update restricted_count=$restricted_count wide_open_count=$wide_open_count"
    DETAIL_CONTENT="$DETAIL_LINES"
    [ -z "$DETAIL_CONTENT" ] && DETAIL_CONTENT="none"
  fi
fi

# target_file 기본값 보정
[ -z "$TARGET_FILE" ] && TARGET_FILE="/etc/named.conf, /etc/bind/named.conf.options, /etc/bind/named.conf (and included files)"

# raw_evidence 구성 (첫 줄: 평가 이유 / 다음 줄: 상세 증적)
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

# JSON 저장을 위한 escape 처리 (따옴표, 줄바꿈)
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