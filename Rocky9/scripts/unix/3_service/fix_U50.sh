#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.3.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-50
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : DNS Zone Transfer 설정
# @Description : allow-transfer를 허용 대상으로 제한
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-50"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

# allow-transfer { <ACL>; };
# 기본값은 "none"으로 Zone Transfer 차단(권장)
# 예) export ALLOW_TRANSFER_ACL="10.0.0.2; 10.0.0.3"
ALLOW_TRANSFER_ACL="${ALLOW_TRANSFER_ACL:-none}"

CHECK_COMMAND='
(command -v systemctl >/dev/null 2>&1 && (
  for u in named.service named-chroot.service; do
    systemctl list-unit-files 2>/dev/null | grep -qiE "^${u}[[:space:]]" && \
      echo "unit:$u enabled=$(systemctl is-enabled "$u" 2>/dev/null || echo unknown) active=$(systemctl is-active "$u" 2>/dev/null || echo unknown)";
  done
)) || echo "systemctl_not_found";
(command -v named-checkconf >/dev/null 2>&1 && echo "named-checkconf_available" ) || echo "named-checkconf_not_found";
for f in /etc/named.conf /etc/bind/named.conf.options /etc/bind/named.conf; do
  [ -f "$f" ] && echo "seed_conf=$f"
done
'

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE="N/A"

ACTION_ERR_LOG=""
MODIFIED=0
MANUAL_REQUIRED=0

append_err() {
  if [ -n "$ACTION_ERR_LOG" ]; then
    ACTION_ERR_LOG="${ACTION_ERR_LOG}\n$1"
  else
    ACTION_ERR_LOG="$1"
  fi
}

append_detail() {
  if [ -n "$DETAIL_CONTENT" ]; then
    DETAIL_CONTENT="${DETAIL_CONTENT}\n$1"
  else
    DETAIL_CONTENT="$1"
  fi
}

# (필수) root 권한 권장 안내(실패 원인 명확화용)
if [ "$(id -u)" -ne 0 ]; then
  ACTION_ERR_LOG="(주의) root 권한이 아니면 설정 파일 수정 및 서비스 재시작이 실패할 수 있습니다."
fi

is_named_running() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl is-active named.service >/dev/null 2>&1 && return 0
    systemctl is-active named-chroot.service >/dev/null 2>&1 && return 0
  fi
  pgrep -x named >/dev/null 2>&1 && return 0
  return 1
}

restart_named_if_exists() {
  command -v systemctl >/dev/null 2>&1 || return 0
  if systemctl list-unit-files 2>/dev/null | grep -qiE '^named\.service[[:space:]]'; then
    systemctl restart named.service >/dev/null 2>&1 || return 1
    return 0
  fi
  if systemctl list-unit-files 2>/dev/null | grep -qiE '^named-chroot\.service[[:space:]]'; then
    systemctl restart named-chroot.service >/dev/null 2>&1 || return 1
    return 0
  fi
  return 0
}

backup_once() {
  local f="$1"
  [ -f "$f" ] || return 0
  if [ ! -f "${f}.bak_kisa_u50" ]; then
    cp -a "$f" "${f}.bak_kisa_u50" 2>/dev/null || return 1
  fi
  return 0
}

normalize_acl_inside() {
  local acl="$1"
  acl="$(echo "$acl" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
  if [[ "$acl" != *";" ]]; then
    acl="${acl};"
  fi
  echo "$acl"
}

collect_named_conf_files() {
  local -a seeds=("$@")
  local -a queue=()
  local -A seen=()
  local -a out=()
  local f inc inc_path dir

  for f in "${seeds[@]}"; do
    [ -f "$f" ] || continue
    queue+=("$f")
  done

  while [ "${#queue[@]}" -gt 0 ]; do
    f="${queue[0]}"
    queue=("${queue[@]:1}")

    [ -f "$f" ] || continue
    if [ -n "${seen[$f]:-}" ]; then
      continue
    fi
    seen["$f"]=1
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

# options 블록에 allow-transfer 적용(있으면 치환, 없으면 options 끝 직전에 삽입)
apply_allow_transfer_in_options() {
  local file="$1"
  local inside="$2"
  local stmt="    allow-transfer { ${inside} };"
  local tmp rc
  tmp="$(mktemp)"

  awk -v STMT="$stmt" '
    function count(s, ch,    t) { t=s; return gsub(ch,"",t); }
    BEGIN { in_opt=0; depth=0; done=0; }
    {
      line=$0
      if (in_opt==0 && line ~ /^[[:space:]]*options[[:space:]]*\{/) {
        in_opt=1
        depth = count(line, "{") - count(line, "}")
        print line
        next
      }
      if (in_opt==1) {
        # allow-transfer가 있으면 치환(기존 라인은 출력하지 않음)
        if (line ~ /^[[:space:]]*allow-transfer[[:space:]]*\{/) {
          print STMT
          done=1
          depth += count(line, "{") - count(line, "}")
          next
        }
        next_depth = depth + count(line, "{") - count(line, "}")
        # options 종료 직전 삽입(allow-transfer 없었던 경우)
        if (next_depth==0 && done==0 && line ~ /^[[:space:]]*\};[[:space:]]*(#.*|\/\/.*)?$/) {
          print STMT
          done=1
          print line
          in_opt=0; depth=0
          next
        }
        print line
        depth = next_depth
        if (depth<=0) { in_opt=0; depth=0 }
        next
      }
      print line
    }
    END { if (done==0) exit 3; }
  ' "$file" > "$tmp"
  rc=$?

  if [ "$rc" -eq 0 ]; then
    mv "$tmp" "$file"
    return 0
  fi

  rm -f "$tmp"
  return 1
}

# wide-open allow-transfer(any/*/0.0.0.0/0 등)만 안전 치환 (추가 삽입은 하지 않음)
tighten_wide_open_allow_transfer() {
  local file="$1"
  local inside="$2"
  local changed=0

  if grep -qE '^[[:space:]]*allow-transfer[[:space:]]*\{[[:space:]]*(any|\*|0\.0\.0\.0(/0)?)' "$file" 2>/dev/null; then
    sed -i -E "s|^[[:space:]]*allow-transfer[[:space:]]*\\{[^}]*\\};|    allow-transfer { ${inside} };|g" "$file" 2>/dev/null && changed=1
  fi

  return $changed
}

# ---------------------------
# 조치 프로세스
# ---------------------------
if [ "$(id -u)" -ne 0 ]; then
  IS_SUCCESS=0
  REASON_LINE="root 권한이 아니어서 DNS Zone Transfer 제한 설정을 적용할 수 없어 조치를 중단합니다."
  append_detail "allow_transfer_acl(target)=$(normalize_acl_inside "$ALLOW_TRANSFER_ACL")"
else
  if ! is_named_running; then
    IS_SUCCESS=1
    REASON_LINE="DNS(named) 서비스가 비활성화되어 있어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
    append_detail "named_status(current)=inactive_or_not_running"
    append_detail "allow_transfer_acl(target)=$(normalize_acl_inside "$ALLOW_TRANSFER_ACL")"
  else
    CONF_SEEDS=("/etc/named.conf" "/etc/bind/named.conf.options" "/etc/bind/named.conf")
    mapfile -t CONF_FILES < <(collect_named_conf_files "${CONF_SEEDS[@]}")

    if [ "${#CONF_FILES[@]}" -eq 0 ]; then
      IS_SUCCESS=0
      REASON_LINE="DNS 설정 파일(/etc/named.conf 등)을 찾지 못해 자동 조치를 완료할 수 없습니다."
      append_detail "named_status(current)=running"
      append_detail "conf_files(current)=not_found"
      append_detail "manual_guide=DNS 설정 파일 경로를 확인한 뒤 options 또는 zone에 allow-transfer 제한을 수동 적용해야 합니다."
    else
      main_conf=""
      for f in "${CONF_SEEDS[@]}"; do
        [ -f "$f" ] && main_conf="$f" && break
      done
      [ -z "$main_conf" ] && main_conf="${CONF_FILES[0]}"
      TARGET_FILE="$main_conf"

      inside="$(normalize_acl_inside "$ALLOW_TRANSFER_ACL")"
      append_detail "named_status(current)=running"
      append_detail "allow_transfer_acl(target)=$inside"
      append_detail "main_conf(current)=$main_conf"

      # 1) main_conf options 블록에 allow-transfer 반영(필수)
      if grep -qE '^[[:space:]]*options[[:space:]]*\{' "$main_conf" 2>/dev/null; then
        backup_once "$main_conf" || append_err "$main_conf 백업 실패"
        if apply_allow_transfer_in_options "$main_conf" "$inside"; then
          MODIFIED=1
          append_detail "apply_result(main_conf)=applied_in_options"
        else
          MANUAL_REQUIRED=1
          append_detail "apply_result(main_conf)=failed_to_apply_in_options"
          append_detail "manual_guide=options 블록에 allow-transfer { none; }; 또는 Secondary DNS만 허용하도록 수동 설정 후 재시작이 필요합니다."
        fi
      else
        MANUAL_REQUIRED=1
        append_detail "apply_result(main_conf)=options_block_not_found"
        append_detail "manual_guide=named.conf에 options 블록(또는 zone)을 확인한 뒤 allow-transfer 제한을 수동 적용해야 합니다."
      fi

      # 2) include 파일 중 wide-open allow-transfer가 있으면 제한으로 치환
      if [ "$MANUAL_REQUIRED" -eq 0 ]; then
        for f in "${CONF_FILES[@]}"; do
          [ -f "$f" ] || continue
          if tighten_wide_open_allow_transfer "$f" "$inside"; then
            backup_once "$f" || append_err "$f 백업 실패"
            MODIFIED=1
            append_detail "tighten_wide_open(after)=$f"
          fi
        done
      fi

      # 3) 구문 검증(named-checkconf) 후 재시작
      if [ "$MANUAL_REQUIRED" -eq 0 ]; then
        if command -v named-checkconf >/dev/null 2>&1; then
          if ! named-checkconf "$main_conf" >/dev/null 2>&1; then
            IS_SUCCESS=0
            REASON_LINE="allow-transfer 설정을 적용했으나 named 설정 구문 검증에 실패하여 조치가 완료되지 않았습니다."
            append_detail "named_checkconf(after)=failed"
            append_detail "manual_guide=named-checkconf 오류 원인을 확인 후 설정을 수정하고 named 재시작이 필요합니다."
            # raw_evidence에는 현재값만 기록: 아래에서 grep 결과를 찍어줌
            MANUAL_REQUIRED=1
          else
            append_detail "named_checkconf(after)=ok"
          fi
        else
          append_detail "named_checkconf(after)=not_available"
        fi
      fi

      if [ "$MANUAL_REQUIRED" -eq 0 ]; then
        if restart_named_if_exists; then
          append_detail "named_restart(after)=ok"
        else
          IS_SUCCESS=0
          REASON_LINE="allow-transfer 설정을 적용했으나 named 서비스 재시작에 실패하여 조치가 완료되지 않았습니다."
          append_detail "named_restart(after)=failed"
          append_detail "manual_guide=설정 적용 후 named 서비스를 수동으로 재시작하고 로그로 실패 원인을 확인해야 합니다."
          MANUAL_REQUIRED=1
        fi
      fi

      # 4) 조치 후 상태 근거(현재/조치 후만)
      # main_conf의 allow-transfer 관련 라인(주석 제외) 일부만 수집
      AT_LINES="$(grep -nEv '^[[:space:]]*#' "$main_conf" 2>/dev/null | grep -nE 'allow-transfer[[:space:]]*\{' | head -n 5)"
      [ -z "$AT_LINES" ] && AT_LINES="allow-transfer_line_not_found_in_main_conf"
      append_detail "allow_transfer_lines(after)=$AT_LINES"

      # 최종 판정
      if [ "$MANUAL_REQUIRED" -eq 1 ]; then
        IS_SUCCESS=0
        [ -n "$REASON_LINE" ] || REASON_LINE="일부 조치를 자동 적용하지 못해 수동 확인이 필요하여 조치가 완료되지 않았습니다."
      else
        IS_SUCCESS=1
        if [ "$MODIFIED" -eq 1 ]; then
          REASON_LINE="DNS Zone Transfer가 제한되도록 allow-transfer 설정이 적용되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
        else
          REASON_LINE="DNS Zone Transfer 제한 설정이 적절히 유지되어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
        fi
      fi
    fi
  fi
fi

if [ -n "$ACTION_ERR_LOG" ]; then
  DETAIL_CONTENT="$DETAIL_CONTENT\n$ACTION_ERR_LOG"
fi

# raw_evidence 구성
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

# DB 저장용 JSON 출력
echo ""
cat << EOF
{
    "item_code": "$ID",
    "action_date": "$ACTION_DATE",
    "is_success": $IS_SUCCESS,
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
}
EOF