#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.1
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-50
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : DNS Zone Transfer 설정
# @Description : allow-transfer 설정으로 Zone Transfer 제한 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-50 DNS Zone Transfer 설정

# 기본 변수
# -----------------------------
ID="U-50"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""

CHECK_COMMAND='
systemctl is-active named named-chroot 2>/dev/null;
pgrep -x named 2>/dev/null;
# BIND conf candidates + include
grep -nE "^[[:space:]]*include[[:space:]]+\"" /etc/named.conf /etc/bind/named.conf /etc/bind/named.conf.options 2>/dev/null;
# allow-transfer candidates
grep -nE "allow-transfer[[:space:]]*\\{" /etc/named.conf /etc/bind/named.conf /etc/bind/named.conf.options 2>/dev/null;
# named.boot xfnets candidates
grep -nE "^[[:space:]]*xfnets[[:space:]]+" /etc/named.boot /etc/bind/named.boot 2>/dev/null;
'

VULNERABLE=0
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

# -----------------------------
# include "..." 재귀 추적하여 설정 파일 목록 수집(중복 제거)
# -----------------------------
collect_named_conf_files() {
  local -a seeds=("$@")
  local -a queue=()
  local -a out=()
  local -a seen=()
  local f dir inc inc_path already

  for f in "${seeds[@]}"; do
    [ -f "$f" ] && queue+=("$f")
  done

  while [ "${#queue[@]}" -gt 0 ]; do
    f="${queue[0]}"
    queue=("${queue[@]:1}")

    [ -f "$f" ] || continue

    already="N"
    for s in "${seen[@]}"; do
      [ "$s" = "$f" ] && already="Y" && break
    done
    [ "$already" = "Y" ] && continue

    seen+=("$f")
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
    done < <(
      grep -hE '^[[:space:]]*include[[:space:]]+"' "$f" 2>/dev/null \
        | sed -E 's/.*"([^"]+)".*/\1/'
    )
  done

  printf '%s\n' "${out[@]}"
}

# -----------------------------
# allow-transfer 블록 추출 (멀티라인 포함)
# - 파일 내 "allow-transfer {" 부터 "};" 까지의 첫 블록만 요약 추출
# -----------------------------
extract_allow_transfer_block() {
  local f="$1"
  awk '
    BEGIN{inblk=0; buf=""; found=0}
    /^[[:space:]]*#/ {next}
    {
      if(found==0 && $0 ~ /allow-transfer[[:space:]]*\{/){
        inblk=1
      }
      if(inblk==1){
        buf = buf $0 "\n"
        if($0 ~ /\}[[:space:]]*;/){
          found=1
          inblk=0
        }
      }
    }
    END{
      if(found==1) printf "%s", buf
    }
  ' "$f" 2>/dev/null
}

# wide-open 판정 시그널(대표)
is_wide_open_text() {
  # any; 0.0.0.0/0 ::/0 * 등을 포함하면 wide-open
  echo "$1" | grep -qiE '(\bany\b[[:space:]]*;|\*|0\.0\.0\.0([[:space:]]*;|/0)|\:\:/0)'
}

# allow-transfer가 "없음"은 기본적으로 취약(기본 동작이 전송 허용으로 해석될 수 있음)
# allow-transfer { none; }; 는 안전으로 취급
is_explicit_none() {
  echo "$1" | grep -qiE 'allow-transfer[[:space:]]*\{[^}]*\bnone\b[[:space:]]*;[^}]*\}'
}

# -----------------------------
# named.boot xfnets 추출 및 판정
# -----------------------------
get_xfnets_line() {
  local f="$1"
  grep -nE '^[[:space:]]*xfnets[[:space:]]+' "$f" 2>/dev/null | head -n1
}

is_xfnets_wide_open() {
  # xfnets에 "any" / 0.0.0.0(/0) / ::/0 / * 등이 들어가면 wide-open 취급
  echo "$1" | grep -qiE '(\bany\b|\*|0\.0\.0\.0(/0)?|\:\:/0)'
}

# -----------------------------
# 진단 시작
# -----------------------------
CONF_SEEDS=("/etc/named.conf" "/etc/bind/named.conf.options" "/etc/bind/named.conf")
BOOT_CANDIDATES=("/etc/named.boot" "/etc/bind/named.boot")

if ! is_named_running; then
  STATUS="PASS"
  REASON_LINE="DNS(named) 서비스가 비활성화되어 점검 대상이 없어 이 항목에 대한 보안 위협이 없습니다."
  DETAIL_CONTENT="none"
else
  append_detail "[info] named_running=Y"

  # 1) named.conf 계열 수집(include 재귀)
  mapfile -t CONF_FILES < <(collect_named_conf_files "${CONF_SEEDS[@]}")

  # 2) named.boot(xfnets) 존재 확인
  XFNETS_FOUND=0
  XFNETS_WIDE=0
  XFNETS_GOOD=0
  for bf in "${BOOT_CANDIDATES[@]}"; do
    [ -f "$bf" ] || continue
    add_target_file "$bf"
    xline="$(get_xfnets_line "$bf")"
    if [ -n "$xline" ]; then
      XFNETS_FOUND=1
      if is_xfnets_wide_open "$xline"; then
        XFNETS_WIDE=1
        append_detail "[check] $bf xfnets=WIDE_OPEN | $xline"
      else
        XFNETS_GOOD=1
        append_detail "[check] $bf xfnets=SET(restricted) | $xline"
      fi
    fi
  done

  # 3) allow-transfer 확인(멀티라인 블록)
  ALLOW_FOUND=0
  ALLOW_WIDE=0
  ALLOW_GOOD=0

  if [ "${#CONF_FILES[@]}" -gt 0 ]; then
    append_detail "[info] conf_files=$(printf "%s " "${CONF_FILES[@]}" | sed 's/[[:space:]]$//')"
    for cf in "${CONF_FILES[@]}"; do
      add_target_file "$cf"
      blk="$(extract_allow_transfer_block "$cf")"
      [ -z "$blk" ] && continue

      ALLOW_FOUND=1

      if is_explicit_none "$blk"; then
        ALLOW_GOOD=1
        append_detail "[check] $cf allow-transfer=NONE(restricted) | $(echo "$blk" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g')"
      elif is_wide_open_text "$blk"; then
        ALLOW_WIDE=1
        append_detail "[check] $cf allow-transfer=WIDE_OPEN | $(echo "$blk" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g')"
      else
        ALLOW_GOOD=1
        append_detail "[check] $cf allow-transfer=SET(restricted?) | $(echo "$blk" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g')"
      fi
    done
  else
    append_detail "[info] conf_files=none"
  fi

  # 4) 판정 로직(필수 기준)
  # - allow-transfer 또는 xfnets 중 하나라도 "제한 설정"이 확인되면 양호 후보
  # - 단, wide-open 시그널이 하나라도 있으면 취약
  # - 둘 다 아예 없으면 취약
  if [ "$ALLOW_WIDE" -eq 1 ] || [ "$XFNETS_WIDE" -eq 1 ]; then
    VULNERABLE=1
    STATUS="FAIL"
    REASON_LINE="DNS 설정에서 Zone Transfer 허용 대상이 광범위하게(any/0.0.0.0/0 등) 열려 있어 취약합니다. 조치 방법: allow-transfer 또는 xfnets를 Secondary DNS(또는 허용 IP)로만 제한 설정 후 DNS 서비스를 재시작하세요."
  else
    if [ "$ALLOW_FOUND" -eq 1 ] || [ "$XFNETS_FOUND" -eq 1 ]; then
      if [ "$ALLOW_GOOD" -eq 1 ] || [ "$XFNETS_GOOD" -eq 1 ]; then
        STATUS="PASS"
        REASON_LINE="DNS 설정에서 allow-transfer 또는 xfnets가 허용 대상(Secondary DNS/허용 IP)으로 제한되어 있어 이 항목에 대한 보안 위협이 없습니다."
      else
        # (이론상) FOUND는 있으나 GOOD로 판단 못한 케이스는 보수적으로 취약
        VULNERABLE=1
        STATUS="FAIL"
        REASON_LINE="DNS 설정에서 Zone Transfer 제한이 명확히 확인되지 않아 취약합니다. 조치 방법: allow-transfer 또는 xfnets를 Secondary DNS(또는 허용 IP)로만 제한 설정 후 DNS 서비스를 재시작하세요."
      fi
    else
      VULNERABLE=1
      STATUS="FAIL"
      REASON_LINE="DNS 설정에서 allow-transfer 또는 xfnets 제한 설정이 확인되지 않아 취약합니다. 조치 방법: allow-transfer(또는 xfnets)를 Secondary DNS(또는 허용 IP)로만 제한 설정 후 DNS 서비스를 재시작하세요."
    fi
  fi

  append_detail "[summary] allow_found=$ALLOW_FOUND allow_good=$ALLOW_GOOD allow_wide=$ALLOW_WIDE xfnets_found=$XFNETS_FOUND xfnets_good=$XFNETS_GOOD xfnets_wide=$XFNETS_WIDE"

  DETAIL_CONTENT="$DETAIL_LINES"
  [ -z "$DETAIL_CONTENT" ] && DETAIL_CONTENT="none"
fi

# target_file 기본값 보정
[ -z "$TARGET_FILE" ] && TARGET_FILE="/etc/named.conf, /etc/bind/named.conf.options, /etc/bind/named.conf, /etc/named.boot, /etc/bind/named.boot (and included files)"

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