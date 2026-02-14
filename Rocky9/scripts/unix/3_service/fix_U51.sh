#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.4.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-51
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : DNS 서비스의 취약한 동적 업데이트 설정 금지
# @Description : allow-update 전체 허용(any/*/0.0.0.0/0) 설정을 none으로 제한
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

set -u

# 기본 변수
ID="U-51"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

TARGET_FILE="N/A"

# 실행 모드:
# - no(기본): allow-update 설정을 allow-update { none; }; 로 제한 적용합니다.
# - yes: 자동 조치를 수행하지 않고 수동 조치 안내만 출력합니다.
USE_DNS_DYNAMIC_UPDATE="${USE_DNS_DYNAMIC_UPDATE:-no}"

CHECK_COMMAND='
(command -v systemctl >/dev/null 2>&1 && (
  for u in named.service named-chroot.service; do
    systemctl list-unit-files 2>/dev/null | grep -qiE "^${u}[[:space:]]" && \
      echo "unit:$u enabled=$(systemctl is-enabled "$u" 2>/dev/null || echo unknown) active=$(systemctl is-active "$u" 2>/dev/null || echo unknown)";
  done
)) || echo "systemctl_not_found";
(command -v named-checkconf >/dev/null 2>&1 && echo "named-checkconf_available") || echo "named-checkconf_not_found";
for f in /etc/named.conf /etc/bind/named.conf.options /etc/bind/named.conf; do
  [ -f "$f" ] && echo "seed_conf=$f"
done
'

REASON_LINE=""
DETAIL_CONTENT=""
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

mode="no"
case "$USE_DNS_DYNAMIC_UPDATE" in
  yes|YES|Yes|true|TRUE|on|ON|1) mode="yes" ;;
  no|NO|No|false|FALSE|off|OFF|0) mode="no" ;;
  *) mode="no" ;;
esac

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

backup_once() {
  local f="$1"
  [ -f "$f" ] || return 0
  if [ ! -f "${f}.bak_kisa_u51" ]; then
    cp -a "$f" "${f}.bak_kisa_u51" 2>/dev/null || return 1
  fi
  return 0
}

rewrite_allow_update_to_none() {
  # allow-update 블록(단일/멀티라인)을 allow-update { none; }; 으로 치환한다.
  # 파일의 최상위에 새로 추가하지는 않는다(구문 오류 방지).
  local file="$1"
  local tmp rc
  tmp="$(mktemp)"

  awk '
    BEGIN { inblk=0; saw=0; }
    {
      line=$0
      if (inblk==0) {
        if (line ~ /^[[:space:]]*allow-update[[:space:]]*\{/) {
          inblk=1
          saw=1
          print "    allow-update { none; };"
          if (line ~ /\};[[:space:]]*$/) {
            inblk=0
          }
          next
        }
        print line
        next
      }
      if (line ~ /\};[[:space:]]*$/) {
        inblk=0
      }
      next
    }
    END { if (saw==0) exit 3; }
  ' "$file" > "$tmp"
  rc=$?

  if [ "$rc" -eq 0 ]; then
    mv "$tmp" "$file"
    return 0
  fi

  rm -f "$tmp"
  return 1
}

########################################
# 조치 프로세스
########################################
if [ "$(id -u)" -ne 0 ]; then
  IS_SUCCESS=0
  REASON_LINE="root 권한이 아니어서 DNS 동적 업데이트 제한 설정을 적용할 수 없어 조치를 중단합니다."
  append_detail "mode(current)=$mode"
else
  if ! is_named_running; then
    IS_SUCCESS=1
    REASON_LINE="DNS(named) 서비스가 비활성화되어 있어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
    append_detail "named_status(current)=inactive_or_not_running"
    append_detail "mode(current)=$mode"
  else
    append_detail "named_status(current)=running"
    append_detail "mode(current)=$mode"

    if [ "$mode" = "yes" ]; then
      MANUAL_REQUIRED=1
      IS_SUCCESS=0
      REASON_LINE="동적 업데이트 필요 환경으로 설정되어 자동 조치를 수행하지 않아 조치가 완료되지 않았습니다."
      append_detail "manual_guide=allow-update를 허용 IP 또는 TSIG key로 제한 지정해야 합니다(예: allow-update { key \"tsig-key\"; 10.0.0.2; };)."
    else
      CONF_SEEDS=("/etc/named.conf" "/etc/bind/named.conf.options" "/etc/bind/named.conf")
      mapfile -t CONF_FILES < <(collect_named_conf_files "${CONF_SEEDS[@]}")

      if [ "${#CONF_FILES[@]}" -eq 0 ]; then
        IS_SUCCESS=0
        REASON_LINE="DNS 설정 파일(/etc/named.conf 등)을 찾지 못해 자동 조치를 완료할 수 없습니다."
        append_detail "conf_files(current)=not_found"
        append_detail "manual_guide=DNS 설정 파일 경로를 확인한 뒤 allow-update를 allow-update { none; }; 로 제한해야 합니다."
      else
        main_conf=""
        for f in "${CONF_SEEDS[@]}"; do
          [ -f "$f" ] && main_conf="$f" && break
        done
        [ -z "$main_conf" ] && main_conf="${CONF_FILES[0]}"
        TARGET_FILE="$main_conf"
        append_detail "main_conf(current)=$main_conf"

        changed=0
        for f in "${CONF_FILES[@]}"; do
          [ -f "$f" ] || continue
          if grep -qE '^[[:space:]]*allow-update[[:space:]]*\{' "$f" 2>/dev/null; then
            backup_once "$f" || append_err "$f 백업 실패"
            if rewrite_allow_update_to_none "$f"; then
              changed=1
              MODIFIED=1
              append_detail "allow_update_rewrite(after)=$f"
            else
              MANUAL_REQUIRED=1
              append_detail "allow_update_rewrite(after)=failed file=$f"
            fi
          fi
        done

        # allow-update가 아예 없으면, 기본적으로 동적 업데이트 차단으로 간주
        if [ "$changed" -eq 0 ] && [ "$MANUAL_REQUIRED" -eq 0 ]; then
          IS_SUCCESS=1
          REASON_LINE="allow-update 설정이 존재하지 않아 동적 업데이트가 차단된 상태로 확인되어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
          append_detail "allow_update_found(after)=no"
        else
          # 구문 검증(named-checkconf) 후 재시작
          if [ "$MANUAL_REQUIRED" -eq 0 ]; then
            if command -v named-checkconf >/dev/null 2>&1; then
              if ! named-checkconf "$main_conf" >/dev/null 2>&1; then
                MANUAL_REQUIRED=1
                append_detail "named_checkconf(after)=failed"
                append_detail "manual_guide=named-checkconf 오류 원인을 확인 후 설정을 수정하고 named 재시작이 필요합니다."
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
              MANUAL_REQUIRED=1
              append_detail "named_restart(after)=failed"
              append_detail "manual_guide=설정 적용 후 named 서비스를 수동으로 재시작하고 로그로 실패 원인을 확인해야 합니다."
            fi
          fi

          # 조치 후 근거: main_conf에서 allow-update 라인(주석 제외) 수집
          AU_LINES="$(grep -nEv '^[[:space:]]*#' "$main_conf" 2>/dev/null | grep -nE 'allow-update[[:space:]]*\{' | head -n 5)"
          [ -z "$AU_LINES" ] && AU_LINES="allow-update_line_not_found_in_main_conf"
          append_detail "allow_update_lines(after)=$AU_LINES"

          if [ "$MANUAL_REQUIRED" -eq 1 ]; then
            IS_SUCCESS=0
            REASON_LINE="조치를 수행했으나 DNS 동적 업데이트 제한 설정을 자동으로 완료하지 못해 조치가 완료되지 않았습니다."
          else
            IS_SUCCESS=1
            if [ "$MODIFIED" -eq 1 ]; then
              REASON_LINE="DNS 동적 업데이트가 차단되도록 allow-update { none; }; 설정이 적용되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
            else
              REASON_LINE="DNS 동적 업데이트 제한 설정이 적절히 유지되어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
            fi
          fi
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