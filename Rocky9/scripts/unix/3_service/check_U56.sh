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

set -u

# 기본 변수
ID="U-56"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""
CHECK_COMMAND='
command -v vsftpd proftpd 2>/dev/null;
systemctl is-active vsftpd proftpd 2>/dev/null;
grep -nE "^(userlist_enable|userlist_file|ftpusers|UseFtpUsers|<Limit[[:space:]]+LOGIN>)" /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf /etc/proftpd/proftpd.conf /etc/proftpd.conf 2>/dev/null;
ls -l /etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd.ftpusers /etc/vsftpd/ftpusers /etc/vsftpd.user_list /etc/vsftpd/user_list 2>/dev/null;
grep -nEv "^[[:space:]]*#|^[[:space:]]*$" /etc/inetd.conf /etc/xinetd.d/ftp 2>/dev/null | head -n 50
' | tr '\n' ' '

VULN=0
FTP_IN_USE=0
DETAIL_LINES=""

append_detail(){ [ -n "${1:-}" ] && DETAIL_LINES="${DETAIL_LINES}${DETAIL_LINES:+\n}$1"; }
add_target(){ [ -n "${1:-}" ] && TARGET_FILE="${TARGET_FILE}${TARGET_FILE:+, }$1"; }

noncomment_grep(){ # $1=file $2=regex
  grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$1" 2>/dev/null | grep -qE "$2"
}

perm_ok_640(){ # $1=perm(3~4digits)
  local p="$1"
  [ -z "$p" ] && return 1
  [[ "$p" =~ ^[0-7]{3,4}$ ]] || return 1
  [ ${#p} -eq 4 ] && p="${p:1}"
  [ "$p" -le 640 ]
}

check_list_file(){ # $1=path $2=label
  local f="$1" label="$2"
  if [ ! -f "$f" ]; then
    VULN=1; append_detail "[$label] file_not_found: $f"; return
  fi

  local owner perm lines
  owner="$(stat -c '%U' "$f" 2>/dev/null || true)"
  perm="$(stat -c '%a' "$f" 2>/dev/null || true)"
  lines="$(grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$f" 2>/dev/null | wc -l | tr -d ' ')"

  append_detail "[$label] $f owner=$owner perm=$perm noncomment_lines=$lines"
  [ "$owner" = "root" ] || { VULN=1; append_detail "[$label] owner_not_root"; }
  perm_ok_640 "$perm" || { VULN=1; append_detail "[$label] perm_too_open_or_parse_failed"; }
  [ "${lines:-0}" -ge 1 ] || { VULN=1; append_detail "[$label] empty_or_comment_only"; }
}

# ------------------------------------------------------------
# FTP 사용 여부(최소 판단): 서비스/설정/inetd(xinetd) 활성 중 하나라도 있으면 사용 중으로 간주
# ------------------------------------------------------------
VSFTPD_CONF=""
[ -f /etc/vsftpd.conf ] && VSFTPD_CONF="/etc/vsftpd.conf"
[ -z "$VSFTPD_CONF" ] && [ -f /etc/vsftpd/vsftpd.conf ] && VSFTPD_CONF="/etc/vsftpd/vsftpd.conf"

PROFTPD_CONF=""
[ -f /etc/proftpd/proftpd.conf ] && PROFTPD_CONF="/etc/proftpd/proftpd.conf"
[ -z "$PROFTPD_CONF" ] && [ -f /etc/proftpd.conf ] && PROFTPD_CONF="/etc/proftpd.conf"

INETD_FTP=0
[ -f /etc/inetd.conf ] && noncomment_grep /etc/inetd.conf '^[[:space:]]*ftp([[:space:]]|$)' && INETD_FTP=1

XINETD_FTP=0
[ -f /etc/xinetd.d/ftp ] && noncomment_grep /etc/xinetd.d/ftp '^[[:space:]]*disable[[:space:]]*=[[:space:]]*no' && XINETD_FTP=1

if systemctl is-active --quiet vsftpd 2>/dev/null || [ -n "$VSFTPD_CONF" ] || \
   systemctl is-active --quiet proftpd 2>/dev/null || [ -n "$PROFTPD_CONF" ] || \
   [ "$INETD_FTP" -eq 1 ] || [ "$XINETD_FTP" -eq 1 ]; then
  FTP_IN_USE=1
fi

# ------------------------------------------------------------
# vsftpd 점검: userlist_enable=YES면 user_list(또는 userlist_file) 확인, 아니면 ftpusers 확인
# ------------------------------------------------------------
if [ "$FTP_IN_USE" -eq 1 ] && ( command -v vsftpd >/dev/null 2>&1 || [ -n "$VSFTPD_CONF" ] || systemctl is-active --quiet vsftpd 2>/dev/null ); then
  add_target "${VSFTPD_CONF:-/etc/vsftpd.conf(/etc/vsftpd/vsftpd.conf)}"

  if [ -n "$VSFTPD_CONF" ] && [ -f "$VSFTPD_CONF" ]; then
    UL_EN="$(grep -Ei '^[[:space:]]*userlist_enable[[:space:]]*=' "$VSFTPD_CONF" 2>/dev/null | grep -v '^[[:space:]]*#' | tail -n1 | awk -F= '{gsub(/[[:space:]]/,"",$2); print tolower($2)}')"
    UL_FILE="$(grep -Ei '^[[:space:]]*userlist_file[[:space:]]*=' "$VSFTPD_CONF" 2>/dev/null | grep -v '^[[:space:]]*#' | tail -n1 | awk -F= '{gsub(/^[[:space:]]*/,"",$2); print $2}')"

    [ -z "$UL_EN" ] && UL_EN="(not_set)"
    append_detail "[vsftpd] userlist_enable=$UL_EN"

    if [ "$UL_EN" = "yes" ]; then
      [ -z "$UL_FILE" ] && UL_FILE="/etc/vsftpd.user_list"
      [ ! -f "$UL_FILE" ] && UL_FILE="/etc/vsftpd/user_list"
      check_list_file "$UL_FILE" "vsftpd user_list"
      add_target "$UL_FILE"
    else
      FU="/etc/vsftpd.ftpusers"
      [ ! -f "$FU" ] && FU="/etc/vsftpd/ftpusers"
      [ ! -f "$FU" ] && FU="/etc/ftpusers"
      check_list_file "$FU" "vsftpd ftpusers"
      add_target "$FU"
    fi
  else
    VULN=1
    append_detail "[vsftpd] config_not_found"
  fi
fi

# ------------------------------------------------------------
# proftpd 점검: UseFtpUsers 기본 on(미설정이면 on)
#  - on  : ftpusers 파일 확인
#  - off : <Limit LOGIN> 내 Allow/Deny(AllowUser/DenyUser/Allow from/Deny from) 존재 확인
# ------------------------------------------------------------
if [ "$FTP_IN_USE" -eq 1 ] && ( command -v proftpd >/dev/null 2>&1 || [ -n "$PROFTPD_CONF" ] || systemctl is-active --quiet proftpd 2>/dev/null ); then
  add_target "${PROFTPD_CONF:-/etc/proftpd/proftpd.conf(/etc/proftpd.conf)}"

  if [ -n "$PROFTPD_CONF" ] && [ -f "$PROFTPD_CONF" ]; then
    USE="$(grep -Ei '^[[:space:]]*UseFtpUsers[[:space:]]+' "$PROFTPD_CONF" 2>/dev/null | grep -v '^[[:space:]]*#' | tail -n1 | awk '{print tolower($2)}')"
    [ -z "$USE" ] && USE="on"
    append_detail "[proftpd] UseFtpUsers=$USE"

    if [ "$USE" = "off" ]; then
      LIMIT="$(sed -n '/<Limit[[:space:]]\+LOGIN>/,/<\/Limit>/p' "$PROFTPD_CONF" 2>/dev/null)"
      echo "$LIMIT" | grep -qiE 'AllowUser|DenyUser|Allow[[:space:]]+from|Deny[[:space:]]+from' \
        && append_detail "[proftpd] <Limit LOGIN> access_control=FOUND" \
        || { VULN=1; append_detail "[proftpd] <Limit LOGIN> access_control=NOT_FOUND"; }
    else
      FU="/etc/ftpusers"
      [ ! -f "$FU" ] && FU="/etc/ftpd/ftpusers"
      check_list_file "$FU" "proftpd ftpusers"
      add_target "$FU"
    fi
  else
    VULN=1
    append_detail "[proftpd] config_not_found"
  fi
fi

# ------------------------------------------------------------
# inetd/xinetd 기반 ftpd 점검: ftpusers 파일 확인
# ------------------------------------------------------------
if [ "$INETD_FTP" -eq 1 ] || [ "$XINETD_FTP" -eq 1 ]; then
  FTP_IN_USE=1
  [ "$INETD_FTP" -eq 1 ] && add_target "/etc/inetd.conf" && append_detail "[inetd] ftp_service=ENABLED"
  [ "$XINETD_FTP" -eq 1 ] && add_target "/etc/xinetd.d/ftp" && append_detail "[xinetd] ftp_service=ENABLED"

  FU="/etc/ftpusers"
  [ ! -f "$FU" ] && FU="/etc/ftpd/ftpusers"
  check_list_file "$FU" "ftpd ftpusers"
  add_target "$FU"
fi

# ------------------------------------------------------------
# 최종 판정/문구(요구 문구 반영)
# ------------------------------------------------------------
if [ "$FTP_IN_USE" -eq 0 ]; then
  STATUS="PASS"
  REASON_LINE="FTP 서비스가 비활성화되어 점검 대상이 없습니다."
  DETAIL_CONTENT="none"
else
  DETAIL_CONTENT="${DETAIL_LINES:-none}"

  if [ "$VULN" -eq 1 ]; then
    STATUS="FAIL"
    REASON_LINE="FTP 접근제어 설정(ftpusers/user_list 또는 proftpd <Limit LOGIN>)이 미흡하게 설정되어 있어 취약합니다. 조치: ftpusers/user_list에 차단(또는 허용) 정책을 적용하고, 파일 소유자 root 및 권한 640 이하로 설정하거나(proftpd는 UseFtpUsers on 또는 <Limit LOGIN>에 Allow/Deny 규칙 추가) 서비스를 재시작하십시오."
  else
    STATUS="PASS"
    REASON_LINE="FTP 접근제어가 설정 파일(ftpusers/user_list 또는 <Limit LOGIN>)에 적용되어 있어 이 항목에 대한 보안 위협이 없습니다."
  fi
fi

[ -z "$TARGET_FILE" ] && TARGET_FILE="N/A"

# raw_evidence 구성 (첫 줄: 평가 이유 / 다음 줄: 상세 증적)
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

# escape 처리
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" | sed 's/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g')

# scan_history JSON 출력 (직전 echo "" 필수)
echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF