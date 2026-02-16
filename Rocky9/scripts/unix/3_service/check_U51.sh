#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.1
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

CONF_SEEDS=("/etc/named.conf" "/etc/bind/named.conf.options" "/etc/bind/named.conf")

CHECK_COMMAND='
systemctl is-active named named-chroot 2>/dev/null;
pgrep -x named 2>/dev/null;
grep -nE "^[[:space:]]*include[[:space:]]+\"" /etc/named.conf /etc/bind/named.conf /etc/bind/named.conf.options 2>/dev/null;
# allow-update/update-policy 블록은 멀티라인일 수 있어 스크립트 내 awk 추출 로직으로 판정
'

# -----------------------------
# 공용
# -----------------------------
is_named_running() {
  systemctl is-active --quiet named 2>/dev/null && return 0
  systemctl is-active --quiet named-chroot 2>/dev/null && return 0
  pgrep -x named >/dev/null 2>&1 && return 0
  return 1
}

append_detail() {
  [ -z "${1:-}" ] && return 0
  if [ -z "$DETAIL_CONTENT" ]; then DETAIL_CONTENT="$1"; else DETAIL_CONTENT="${DETAIL_CONTENT}\n$1"; fi
}

add_target() {
  local f="${1:-}"
  [ -z "$f" ] && return 0
  if [ -z "$TARGET_FILE" ]; then TARGET_FILE="$f"
  else
    case ",$TARGET_FILE," in *",$f,"*) : ;; *) TARGET_FILE="${TARGET_FILE}, $f" ;; esac
  fi
}

# include "file"; 재귀 수집(중복 제거)
collect_named_conf_files() {
  local -a queue=() out=()
  declare -A seen=()
  local f dir inc inc_path

  for f in "$@"; do [ -f "$f" ] && queue+=("$f"); done

  while [ "${#queue[@]}" -gt 0 ]; do
    f="${queue[0]}"; queue=("${queue[@]:1}")
    [ -f "$f" ] || continue
    [ -n "${seen["$f"]+x}" ] && continue
    seen["$f"]=1
    out+=("$f")

    dir="$(dirname "$f")"
    while IFS= read -r inc; do
      [ -z "$inc" ] && continue
      [[ "$inc" = /* ]] && inc_path="$inc" || inc_path="${dir}/${inc}"
      [ -f "$inc_path" ] && queue+=("$inc_path")
    done < <(grep -hE '^[[:space:]]*include[[:space:]]+"' "$f" 2>/dev/null \
            | sed -E 's/.*"([^"]+)".*/\1/')
  done

  printf '%s\n' "${out[@]}"
}

# allow-update/update-policy 블록(멀티라인) 추출
# 출력: TYPE|FILE|ONE_LINE_CONTENT
extract_update_blocks() {
  local f="$1"
  awk -v FILE="$f" '
    BEGIN{IGNORECASE=1; inblk=0; type=""; buf=""}
    function norm(s){gsub(/[[:space:]]+/," ",s); gsub(/^[[:space:]]+|[[:space:]]+$/,"",s); return s}
    {
      line=$0
      sub(/^[[:space:]]*#.*/,"",line)      # 라인 주석(#) 제거(단순)
      sub(/[[:space:]]*\/\/.*/,"",line)    # 라인 주석(//) 제거(단순)
      if(line ~ /^[[:space:]]*$/) next

      if(!inblk && line ~ /(allow-update|update-policy)[[:space:]]*\{/){
        inblk=1
        type=(line ~ /allow-update[[:space:]]*\{/ ? "allow-update" : "update-policy")
        buf=line
        if(line ~ /\}[[:space:]]*;/){
          print type "|" FILE "|" norm(buf)
          inblk=0; type=""; buf=""
        }
        next
      }

      if(inblk){
        buf = buf " " line
        if(line ~ /\}[[:space:]]*;/){
          print type "|" FILE "|" norm(buf)
          inblk=0; type=""; buf=""
        }
      }
    }
  ' "$f" 2>/dev/null
}

# 과도 개방 판정(대표 시그널)
is_wide_open_allow() {
  local s="$1"
  echo "$s" | grep -qiE '\ballow-update[[:space:]]*\{[^}]*\bnone\b' && return 1
  echo "$s" | grep -qiE '(\bany\b|\*|0\.0\.0\.0(/0)?|::/0)' && return 0
  return 1
}

is_wide_open_policy() {
  local s="$1"
  # update-policy는 TSIG key 기반이 일반적이므로, grant가 * / any 등으로 과도하면 취약 시그널로 처리
  echo "$s" | grep -qiE '\bgrant[[:space:]]+(\*|any)\b' && return 0
  echo "$s" | grep -qiE '\bgrant[[:space:]]+[^;]*\b(\*|any)\b' && return 0
  return 1
}

# -----------------------------
# 진단 시작
# -----------------------------
if ! is_named_running; then
  STATUS="PASS"
  REASON_LINE="DNS(named) 서비스가 비활성화되어 있어 이 항목에 대한 보안 위협이 없습니다."
  DETAIL_CONTENT="systemctl/pgrep 기준으로 named 프로세스가 동작하지 않습니다."
else
  mapfile -t CONF_FILES < <(collect_named_conf_files "${CONF_SEEDS[@]}")
  if [ "${#CONF_FILES[@]}" -eq 0 ]; then
    STATUS="FAIL"
    REASON_LINE="DNS 서비스가 실행 중이나 설정 파일을 확인할 수 없어 취약합니다. 설정 파일 위치를 확인하고 allow-update/update-policy를 점검해야 합니다. (조치: named.conf에 allow-update { none; }; 또는 허용 대상을 IP/TSIG로 제한 후 서비스 재시작)"
    DETAIL_CONTENT="conf_files=none"
  else
    found=0; bad=0; good=0
    shown=0; max_show=25

    for f in "${CONF_FILES[@]}"; do
      add_target "$f"

      while IFS= read -r rec; do
        [ -z "$rec" ] && continue
        found=1
        type="${rec%%|*}"; rest="${rec#*|}"; file="${rest%%|*}"; content="${rest#*|}"

        if [ "$type" = "allow-update" ]; then
          if is_wide_open_allow "$content"; then bad=$((bad+1)); verdict="WIDE_OPEN"
          else good=$((good+1)); verdict="RESTRICTED" ; fi
        else
          if is_wide_open_policy "$content"; then bad=$((bad+1)); verdict="WIDE_OPEN"
          else good=$((good+1)); verdict="RESTRICTED" ; fi
        fi

        if [ "$shown" -lt "$max_show" ]; then
          append_detail "[check] $file $type=$verdict | $content"
          shown=$((shown+1))
        fi
      done < <(extract_update_blocks "$f")
    done

    if [ "$found" -eq 0 ]; then
      STATUS="PASS"
      REASON_LINE="설정 파일들(${CONF_FILES[0]} 등 include로 참조되는 파일 포함)에서 allow-update/update-policy가 확인되지 않아 동적 업데이트가 비활성화되어 이 항목에 대한 보안 위협이 없습니다."
      [ -z "$DETAIL_CONTENT" ] && DETAIL_CONTENT="allow-update/update-policy 블록 미검출"
    elif [ "$bad" -gt 0 ]; then
      STATUS="FAIL"
      REASON_LINE="설정 파일에서 DNS 동적 업데이트(allow-update/update-policy)가 과도하게 허용되어 취약합니다. (조치: 동적 업데이트가 불필요하면 allow-update { none; }; 적용, 필요 시에도 허용 IP 또는 TSIG 키로만 제한 후 named 재시작)"
      append_detail "[summary] found_blocks=$found restricted=$good wide_open=$bad"
    else
      STATUS="PASS"
      REASON_LINE="설정 파일에서 DNS 동적 업데이트(allow-update/update-policy)가 제한적으로 설정되어 있어 이 항목에 대한 보안 위협이 없습니다."
      append_detail "[summary] found_blocks=$found restricted=$good wide_open=$bad"
    fi
  fi
fi

[ -z "$TARGET_FILE" ] && TARGET_FILE="/etc/named.conf, /etc/bind/named.conf.options, /etc/bind/named.conf (and included files)"
[ -z "$DETAIL_CONTENT" ] && DETAIL_CONTENT="none"

# raw_evidence 구성 (첫 줄: 평가 이유 / 다음 줄: 상세 증적)
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE
$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

# JSON 저장을 위한 escape 처리 (따옴표, 줄바꿈)
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/\\/\\\\/g; s/"/\\"/g' \
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