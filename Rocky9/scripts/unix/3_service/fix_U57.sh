#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.0
# @Author: 이가영
# @Last Updated: 2026-02-16
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-57
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중 
# @Title : Ftpusers 파일 설정
# @Description : FTP 서비스에 root 계정 접근 제한 설정 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-57 Ftpusers 파일 설정

# 기본 변수
ID="U-57"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND='( [ -f /etc/ftpusers ] && grep -nEv "^[[:space:]]*#|^[[:space:]]*$" /etc/ftpusers | head -n 200 || echo "ftpusers_not_found" ); ( [ -f /etc/vsftpd.conf ] && grep -nE "^[[:space:]]*(userlist_enable|userlist_deny|userlist_file)[[:space:]]*=" /etc/vsftpd.conf 2>/dev/null || true ); ( [ -f /etc/vsftpd/vsftpd.conf ] && grep -nE "^[[:space:]]*(userlist_enable|userlist_deny|userlist_file)[[:space:]]*=" /etc/vsftpd/vsftpd.conf 2>/dev/null || true ); ( [ -f /etc/proftpd/proftpd.conf ] && grep -nE "^[[:space:]]*(UseFtpUsers|RootLogin)[[:space:]]+" /etc/proftpd/proftpd.conf 2>/dev/null || true ); ( [ -f /etc/proftpd.conf ] && grep -nE "^[[:space:]]*(UseFtpUsers|RootLogin)[[:space:]]+" /etc/proftpd.conf 2>/dev/null || true ); (ls -l /etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd.user_list /etc/vsftpd/user_list /etc/vsftpd.ftpusers /etc/vsftpd/ftpusers 2>/dev/null || true )'

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""
ACTION_ERR_LOG=""

add_detail(){ [ -n "${1:-}" ] && DETAIL_CONTENT="${DETAIL_CONTENT}${DETAIL_CONTENT:+\\n}$1"; }
add_err(){ [ -n "${1:-}" ] && ACTION_ERR_LOG="${ACTION_ERR_LOG}${ACTION_ERR_LOG:+\\n}$1"; }
add_file(){
  local f="${1:-}"; [ -z "$f" ] && return 0
  case ",$TARGET_FILE," in *,"$f",*) :;; *) TARGET_FILE="${TARGET_FILE}${TARGET_FILE:+, }$f";; esac
}

# 주석/공백 제외 root 라인 존재
has_root(){ [ -f "$1" ] && grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$1" 2>/dev/null | grep -qEx '[[:space:]]*root[[:space:]]*'; }

ensure_file(){ [ -f "$1" ] || { touch "$1" 2>/dev/null || return 1; }; return 0; }

# blacklist: root 없으면 추가(또는 #root 해제)
ensure_root_present(){
  local f="$1"; ensure_file "$f" || return 1
  if has_root "$f"; then return 0; fi
  if grep -qE '^[[:space:]]*#root[[:space:]]*$' "$f" 2>/dev/null; then
    sed -i -E 's/^[[:space:]]*#root[[:space:]]*$/root/' "$f" 2>/dev/null || return 1
  else
    echo "root" >> "$f" 2>/dev/null || return 1
  fi
  return 0
}

# whitelist: root 있으면 제거
ensure_root_absent(){
  local f="$1"; ensure_file "$f" || return 1
  if has_root "$f"; then
    sed -i -E '/^[[:space:]]*root[[:space:]]*$/d' "$f" 2>/dev/null || return 1
  fi
  return 0
}

# vsftpd/proftpd 설정값: 마지막 유효 라인
conf_kv(){
  local conf="$1" key="$2"
  grep -iE "^[[:space:]]*${key}[[:space:]]*=" "$conf" 2>/dev/null | grep -v '^[[:space:]]*#' | tail -n1 \
    | sed -E 's/.*=[[:space:]]*//; s/[[:space:]]*$//' | tr -d '\r'
}
upper(){ echo "${1:-}" | tr '[:lower:]' '[:upper:]'; }

need_root(){
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    REASON_LINE="root 권한이 아니어서 조치를 적용할 수 없어 조치가 완료되지 않았습니다. 중단합니다."
    DETAIL_CONTENT="sudo로 실행해야 합니다."
    return 1
  fi
  return 0
}

restart_if_exist(){
  local unit="$1"
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl list-unit-files 2>/dev/null | grep -qiE "^${unit}[[:space:]]" || return 0
  systemctl restart "$unit" >/dev/null 2>&1 || add_err "${unit} 재시작 실패"
}

need_root || goto_finalize=1
goto_finalize=${goto_finalize:-0}

VS_CONF=""
[ -f /etc/vsftpd.conf ] && VS_CONF="/etc/vsftpd.conf"
[ -z "$VS_CONF" ] && [ -f /etc/vsftpd/vsftpd.conf ] && VS_CONF="/etc/vsftpd/vsftpd.conf"

PF_CONF=""
[ -f /etc/proftpd/proftpd.conf ] && PF_CONF="/etc/proftpd/proftpd.conf"
[ -z "$PF_CONF" ] && [ -f /etc/proftpd.conf ] && PF_CONF="/etc/proftpd.conf"

# -------------------------
# 조치 수행
# -------------------------
if [ "$goto_finalize" -eq 0 ]; then
  # 1) vsftpd
  if command -v vsftpd >/dev/null 2>&1 || [ -n "$VS_CONF" ]; then
    if [ -n "$VS_CONF" ] && [ -f "$VS_CONF" ]; then
      add_file "$VS_CONF"
      ULE="$(conf_kv "$VS_CONF" userlist_enable)"; ULD="$(conf_kv "$VS_CONF" userlist_deny)"; ULF="$(conf_kv "$VS_CONF" userlist_file)"
      ULE="$(upper "${ULE:-NO}")"; ULD="$(upper "${ULD:-YES}")"

      if [ "$ULE" = "YES" ]; then
        LIST="${ULF:-/etc/vsftpd.user_list}"
        [ -z "${ULF:-}" ] && [ -f /etc/vsftpd/user_list ] && LIST="/etc/vsftpd/user_list"
        add_file "$LIST"
        if [ "$ULD" = "NO" ]; then
          ensure_root_absent "$LIST" || add_err "vsftpd whitelist(root 제거) 실패: $LIST"
        else
          ensure_root_present "$LIST" || add_err "vsftpd blacklist(root 추가) 실패: $LIST"
        fi
      else
        FU="/etc/vsftpd.ftpusers"; [ ! -f "$FU" ] && FU="/etc/vsftpd/ftpusers"; [ ! -f "$FU" ] && FU="/etc/ftpusers"
        add_file "$FU"
        ensure_root_present "$FU" || add_err "vsftpd ftpusers(root 추가) 실패: $FU"
      fi
      restart_if_exist "vsftpd.service"
    else
      add_err "vsftpd가 감지되었으나 설정 파일을 찾지 못했습니다."
    fi
  fi

  # 2) proftpd
  if command -v proftpd >/dev/null 2>&1 || [ -n "$PF_CONF" ]; then
    if [ -n "$PF_CONF" ] && [ -f "$PF_CONF" ]; then
      add_file "$PF_CONF"
      if grep -qiE '^[[:space:]]*UseFtpUsers[[:space:]]+off([[:space:]]|$)' "$PF_CONF" 2>/dev/null; then
        if ! grep -qiE '^[[:space:]]*RootLogin[[:space:]]+off([[:space:]]|$)' "$PF_CONF" 2>/dev/null; then
          echo "RootLogin off" >> "$PF_CONF" 2>/dev/null || add_err "proftpd RootLogin off 추가 실패: $PF_CONF"
        fi
      else
        FU="/etc/ftpusers"; add_file "$FU"
        ensure_root_present "$FU" || add_err "proftpd ftpusers(root 추가) 실패: $FU"
        if [ -f /etc/ftpd/ftpusers ]; then
          add_file "/etc/ftpd/ftpusers"
          ensure_root_present "/etc/ftpd/ftpusers" || add_err "ftpd/ftpusers(root 추가) 실패: /etc/ftpd/ftpusers"
        fi
      fi
      restart_if_exist "proftpd.service"
    else
      add_err "proftpd가 감지되었으나 설정 파일을 찾지 못했습니다."
    fi
  fi

  # 3) 일반 ftpusers(존재 시 보강)
  if [ -f /etc/ftpusers ]; then
    add_file "/etc/ftpusers"
    ensure_root_present "/etc/ftpusers" || add_err "/etc/ftpusers(root 추가) 실패"
  fi
  if [ -f /etc/ftpd/ftpusers ]; then
    add_file "/etc/ftpd/ftpusers"
    ensure_root_present "/etc/ftpd/ftpusers" || add_err "/etc/ftpd/ftpusers(root 추가) 실패"
  fi

  # -------------------------
  # 조치 후 검증(After만 기록)
  # -------------------------
  OK=1
  if [ -n "$VS_CONF" ] && [ -f "$VS_CONF" ]; then
    ULE="$(upper "$(conf_kv "$VS_CONF" userlist_enable)")"; ULD="$(upper "$(conf_kv "$VS_CONF" userlist_deny)")"; ULF="$(conf_kv "$VS_CONF" userlist_file)"
    ULE="${ULE:-NO}"; ULD="${ULD:-YES}"
    add_detail "vsftpd_conf(after)=$VS_CONF"
    add_detail "vsftpd_userlist_enable(after)=$ULE"
    add_detail "vsftpd_userlist_deny(after)=$ULD"
    if [ "$ULE" = "YES" ]; then
      LIST="${ULF:-/etc/vsftpd.user_list}"
      [ -z "${ULF:-}" ] && [ -f /etc/vsftpd/user_list ] && LIST="/etc/vsftpd/user_list"
      add_detail "vsftpd_list_file(after)=$LIST"
      if [ "$ULD" = "NO" ]; then
        has_root "$LIST" && OK=0
        add_detail "vsftpd_list_root(after)=$(has_root "$LIST" && echo present || echo absent)"
      else
        has_root "$LIST" || OK=0
        add_detail "vsftpd_list_root(after)=$(has_root "$LIST" && echo present || echo absent)"
      fi
    else
      FU="/etc/vsftpd.ftpusers"; [ ! -f "$FU" ] && FU="/etc/vsftpd/ftpusers"; [ ! -f "$FU" ] && FU="/etc/ftpusers"
      add_detail "vsftpd_ftpusers_file(after)=$FU"
      has_root "$FU" || OK=0
      add_detail "vsftpd_ftpusers_root(after)=$(has_root "$FU" && echo present || echo absent)"
    fi
  fi

  if [ -n "$PF_CONF" ] && [ -f "$PF_CONF" ]; then
    add_detail "proftpd_conf(after)=$PF_CONF"
    if grep -qiE '^[[:space:]]*UseFtpUsers[[:space:]]+off([[:space:]]|$)' "$PF_CONF" 2>/dev/null; then
      RL="$(grep -Ei '^[[:space:]]*RootLogin[[:space:]]+' "$PF_CONF" 2>/dev/null | grep -v '^[[:space:]]*#' | tail -n1)"
      echo "$RL" | grep -qi 'off' || OK=0
      add_detail "proftpd_rootlogin(after)=${RL:-RootLogin not_set}"
    else
      FU="/etc/ftpusers"
      add_detail "proftpd_ftpusers_file(after)=$FU"
      has_root "$FU" || OK=0
      add_detail "proftpd_ftpusers_root(after)=$(has_root "$FU" && echo present || echo absent)"
    fi
  fi

  if [ -n "$ACTION_ERR_LOG" ]; then OK=0; add_detail "action_error(after)=$ACTION_ERR_LOG"; fi

  if [ "$OK" -eq 1 ]; then
    IS_SUCCESS=1
    REASON_LINE="FTP 서비스의 root 접속 제한 설정이 적용되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
  else
    IS_SUCCESS=0
    REASON_LINE="조치를 수행했으나 root 접속 제한 설정이 일부 확인되지 않아 조치가 완료되지 않았습니다."
  fi
fi

# target_file 기본값 보정
[ -z "$TARGET_FILE" ] && TARGET_FILE="/etc/ftpusers, /etc/ftpd/ftpusers, /etc/vsftpd.user_list, /etc/vsftpd/user_list, /etc/vsftpd.ftpusers, /etc/vsftpd/ftpusers, /etc/vsftpd.conf, /etc/vsftpd/vsftpd.conf, /etc/proftpd/proftpd.conf, /etc/proftpd.conf"

# raw_evidence(After만)
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n${DETAIL_CONTENT:-none}",
  "target_file": "$TARGET_FILE"
}
EOF
)

RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" | sed 's/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g')

echo ""
cat <<EOF
{
    "item_code": "$ID",
    "action_date": "$ACTION_DATE",
    "is_success": $IS_SUCCESS,
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
}
EOF