#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.2.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-56
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 하
# @Title : FTP 서비스 접근 제어 설정
# @Description : FTP 서비스 접근 제어(hosts.allow/hosts.deny 등) 설정 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-56"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""
CHECK_COMMAND='command -v vsftpd; command -v proftpd; systemctl is-active vsftpd proftpd; grep -nE "^(tcp_wrappers|userlist_enable|userlist_file|ftpusers)" /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null; grep -nE "^[[:space:]]*UseFtpUsers|<Limit[[:space:]]+LOGIN>" /etc/proftpd/proftpd.conf /etc/proftpd.conf 2>/dev/null; grep -nE "^[[:space:]]*(vsftpd|in\\.ftpd|ftpd)[[:space:]]*:" /etc/hosts.allow /etc/hosts.deny 2>/dev/null; grep -nE "^[[:space:]]*ftp([[:space:]]|$)" /etc/inetd.conf /etc/xinetd.d/ftp 2>/dev/null'

VULNERABLE=0
FTP_IN_USE=0
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

has_non_comment_match() {
  local file="$1"
  local pattern="$2"
  grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$file" 2>/dev/null | grep -qE "$pattern"
}

# hosts.allow / hosts.deny 기반 접근제어 점검
# - allow: 데몬 라인이 존재해야 함(예: vsftpd: 10.0.0.0/8)
# - deny : ALL:ALL 또는 데몬:ALL 형태가 있어야 함(기본 차단)
check_hosts_control() {
  local daemon_regex="$1"
  local label="$2"
  local allow_ok=0
  local deny_ok=0

  if [ -f "/etc/hosts.allow" ] && has_non_comment_match "/etc/hosts.allow" "^(${daemon_regex})[[:space:]]*:"; then
    allow_ok=1
    append_detail "[hosts.allow] ${label} allow_rule=FOUND"
  else
    append_detail "[hosts.allow] ${label} allow_rule=NOT_FOUND"
  fi

  if [ -f "/etc/hosts.deny" ] && has_non_comment_match "/etc/hosts.deny" "^(ALL[[:space:]]*:[[:space:]]*ALL|(${daemon_regex})[[:space:]]*:[[:space:]]*ALL)"; then
    deny_ok=1
    append_detail "[hosts.deny] ${label} deny_rule=FOUND"
  else
    append_detail "[hosts.deny] ${label} deny_rule=NOT_FOUND"
  fi

  if [ "$allow_ok" -eq 0 ] || [ "$deny_ok" -eq 0 ]; then
    VULNERABLE=1
    append_detail "[result] ${label} hosts_access_control=INSUFFICIENT (need allow + deny baseline)"
  else
    append_detail "[result] ${label} hosts_access_control=OK"
  fi
}

# 파일 존재/권한 참고(없으면 취약으로 보되, 이 항목의 핵심은 "접근제어"이므로 근거로만 남김)
check_owner_perm_ref() {
  local file="$1"
  local max_perm="$2"
  local label="$3"

  if [ ! -f "$file" ]; then
    VULNERABLE=1
    append_detail "[file] ${label}=NOT_FOUND ($file)"
    return
  fi

  local owner perms
  owner="$(stat -c '%U' "$file" 2>/dev/null || true)"
  perms="$(stat -c '%a' "$file" 2>/dev/null || true)"
  append_detail "[file] ${label} owner=$owner perm=$perms path=$file"

  if [ "$owner" != "root" ]; then
    VULNERABLE=1
    append_detail "[result] ${label} owner_not_root"
  fi

  if echo "$perms" | grep -Eq '^[0-7]{3,4}$'; then
    # 4자리(특수권한)도 고려해 마지막 3자리만 비교하도록 정수 변환
    local p3="$perms"
    [ ${#p3} -eq 4 ] && p3="${p3:1}"
    if [ "$p3" -gt "$max_perm" ]; then
      VULNERABLE=1
      append_detail "[result] ${label} perm_too_open (current=$p3 > max=$max_perm)"
    fi
  else
    VULNERABLE=1
    append_detail "[result] ${label} perm_parse_failed (perm=$perms)"
  fi
}

is_named_running() {
  systemctl is-active --quiet named 2>/dev/null && return 0
  systemctl is-active --quiet named-chroot 2>/dev/null && return 0
  return 1
}

# ----------------------------------------------------------------------------
# vsftpd
# ----------------------------------------------------------------------------
VSFTPD_CONF=""
if [ -f "/etc/vsftpd.conf" ]; then
  VSFTPD_CONF="/etc/vsftpd.conf"
elif [ -f "/etc/vsftpd/vsftpd.conf" ]; then
  VSFTPD_CONF="/etc/vsftpd/vsftpd.conf"
fi

if command -v vsftpd >/dev/null 2>&1 || [ -n "$VSFTPD_CONF" ] || systemctl list-units --type=service 2>/dev/null | grep -q vsftpd; then
  FTP_IN_USE=1

  if [ -n "$VSFTPD_CONF" ]; then
    add_target_file "$VSFTPD_CONF"

    # tcp_wrappers=YES 권고(접근제어 기반)
    if has_non_comment_match "$VSFTPD_CONF" '^tcp_wrappers[[:space:]]*=[[:space:]]*YES'; then
      append_detail "[vsftpd] tcp_wrappers=YES"
    else
      VULNERABLE=1
      append_detail "[vsftpd] tcp_wrappers=YES NOT_SET"
    fi

    # hosts.allow/hosts.deny 점검(vsftpd 또는 in.ftpd)
    check_hosts_control 'vsftpd|in\.ftpd' 'vsftpd'

    # userlist/ftpusers 파일 존재/권한(참고 증적)
    if has_non_comment_match "$VSFTPD_CONF" '^userlist_enable[[:space:]]*=[[:space:]]*YES'; then
      # userlist_enable=YES면 user_list가 접근제어에 사용될 수 있음
      UL_FILE="$(grep -E '^[[:space:]]*userlist_file[[:space:]]*=' "$VSFTPD_CONF" 2>/dev/null | grep -v '^[[:space:]]*#' | tail -n1 | sed -E 's/.*=[[:space:]]*//')"
      [ -z "$UL_FILE" ] && UL_FILE="/etc/vsftpd.user_list"
      [ ! -f "$UL_FILE" ] && UL_FILE="/etc/vsftpd/user_list"
      check_owner_perm_ref "$UL_FILE" 640 "vsftpd user_list"
    else
      # 일반적으로 ftpusers 파일로 계정 차단을 운용
      FU_FILE="/etc/vsftpd.ftpusers"
      [ ! -f "$FU_FILE" ] && FU_FILE="/etc/vsftpd/ftpusers"
      [ ! -f "$FU_FILE" ] && FU_FILE="/etc/ftpusers"
      check_owner_perm_ref "$FU_FILE" 640 "vsftpd ftpusers"
    fi

    if systemctl is-active --quiet vsftpd 2>/dev/null; then
      append_detail "[vsftpd] service_active=Y"
    else
      append_detail "[vsftpd] service_active=N"
    fi
  else
    VULNERABLE=1
    append_detail "[vsftpd] config_file=NOT_FOUND"
  fi
fi

# ----------------------------------------------------------------------------
# proftpd
# ----------------------------------------------------------------------------
PROFTPD_CONF=""
if [ -f "/etc/proftpd/proftpd.conf" ]; then
  PROFTPD_CONF="/etc/proftpd/proftpd.conf"
elif [ -f "/etc/proftpd.conf" ]; then
  PROFTPD_CONF="/etc/proftpd.conf"
fi

if command -v proftpd >/dev/null 2>&1 || [ -n "$PROFTPD_CONF" ] || systemctl list-units --type=service 2>/dev/null | grep -q proftpd; then
  FTP_IN_USE=1

  if [ -n "$PROFTPD_CONF" ]; then
    add_target_file "$PROFTPD_CONF"
    check_owner_perm_ref "$PROFTPD_CONF" 640 "proftpd.conf"

    # UseFtpUsers 기본값은 on으로 보는 경우가 많아, 미설정이면 on으로 간주
    USE_FTPUSERS="$(grep -Ei '^[[:space:]]*UseFtpUsers' "$PROFTPD_CONF" 2>/dev/null | grep -v '^[[:space:]]*#' | tail -n1 | awk '{print tolower($2)}')"
    [ -z "$USE_FTPUSERS" ] && USE_FTPUSERS="on"
    append_detail "[proftpd] UseFtpUsers=$USE_FTPUSERS"

    if [ "$USE_FTPUSERS" = "off" ]; then
      # <Limit LOGIN> 접근제어(Allow/Deny) 존재 여부 확인
      LIMIT_LOGIN="$(sed -n '/<Limit[[:space:]]\+LOGIN>/,/<\/Limit>/p' "$PROFTPD_CONF" 2>/dev/null)"
      if [ -z "$LIMIT_LOGIN" ] || ! echo "$LIMIT_LOGIN" | grep -qiE 'Allow[[:space:]]+from|Deny[[:space:]]+from|AllowUser|DenyUser'; then
        VULNERABLE=1
        append_detail "[proftpd] <Limit LOGIN> access_control=INSUFFICIENT"
      else
        append_detail "[proftpd] <Limit LOGIN> access_control=FOUND"
      fi
    else
      # ftpusers 파일 점검(참고 증적)
      FU_FILE="/etc/ftpusers"
      [ ! -f "$FU_FILE" ] && FU_FILE="/etc/ftpd/ftpusers"
      check_owner_perm_ref "$FU_FILE" 640 "proftpd ftpusers"
    fi

    if systemctl is-active --quiet proftpd 2>/dev/null; then
      append_detail "[proftpd] service_active=Y"
    else
      append_detail "[proftpd] service_active=N"
    fi
  else
    VULNERABLE=1
    append_detail "[proftpd] config_file=NOT_FOUND"
  fi
fi

# ----------------------------------------------------------------------------
# inetd/xinetd 기반 FTP (접근제어는 hosts.allow/hosts.deny 기반으로 확인)
# ----------------------------------------------------------------------------
if [ -f "/etc/inetd.conf" ] && has_non_comment_match "/etc/inetd.conf" '^[[:space:]]*ftp([[:space:]]|$)'; then
  FTP_IN_USE=1
  add_target_file "/etc/inetd.conf"
  append_detail "[inetd] ftp_service=ENABLED"
  check_hosts_control 'in\.ftpd|ftpd' 'inetd 기반 FTP'
fi

if [ -f "/etc/xinetd.d/ftp" ] && has_non_comment_match "/etc/xinetd.d/ftp" '^[[:space:]]*disable[[:space:]]*=[[:space:]]*no'; then
  FTP_IN_USE=1
  add_target_file "/etc/xinetd.d/ftp"
  append_detail "[xinetd] ftp disable=no -> ENABLED"
  check_hosts_control 'in\.ftpd|ftpd|vsftpd' 'xinetd 기반 FTP'
fi

# ----------------------------------------------------------------------------
# 최종 판정/문구(U-15~U-16 톤)
# ----------------------------------------------------------------------------
if [ "$FTP_IN_USE" -eq 0 ]; then
  STATUS="PASS"
  REASON_LINE="FTP 서비스가 비활성화되어 점검 대상이 없습니다."
  DETAIL_CONTENT="none"
else
  if [ "$VULNERABLE" -eq 1 ]; then
    STATUS="FAIL"
    REASON_LINE="FTP 서비스 접근 제어 설정이 미흡하여 비인가 접속 위험이 있으므로 취약합니다. 허용할 IP/호스트 또는 허용 계정만 접속 가능하도록 접근 제어 정책을 수립하고 설정 파일 및 hosts.allow/hosts.deny 등에 반영해야 합니다."
  else
    STATUS="PASS"
    REASON_LINE="FTP 서비스 접근 제어가 설정되어 있어 이 항목에 대한 보안 위협이 없습니다."
  fi

  DETAIL_CONTENT="$DETAIL_LINES"
  [ -z "$DETAIL_CONTENT" ] && DETAIL_CONTENT="none"
fi

# target_file 기본값 보정
[ -z "$TARGET_FILE" ] && TARGET_FILE="/etc/vsftpd.conf, /etc/vsftpd/vsftpd.conf, /etc/proftpd/proftpd.conf, /etc/proftpd.conf, /etc/hosts.allow, /etc/hosts.deny, /etc/inetd.conf, /etc/xinetd.d/ftp"

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