#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-57
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중 
# @Title : Ftpusers 파일 설정
# @Description : FTP 서비스에 root 계정 접근 제한 설정 여부 점검
# @Criteria_Good : root 계정 접속을 차단한 경우
# @Criteria_Bad : root 계정 접속을 허용한 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-57 Ftpusers 파일 설정

set -u

# 기본 변수
ID="U-57"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

CHECK_COMMAND='command -v vsftpd proftpd 2>/dev/null; systemctl is-active vsftpd proftpd 2>/dev/null; grep -nE "^[[:space:]]*(userlist_enable|userlist_deny|userlist_file)[[:space:]]*=" /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null; grep -nE "^[[:space:]]*(UseFtpUsers|RootLogin)[[:space:]]+" /etc/proftpd/proftpd.conf /etc/proftpd.conf 2>/dev/null; grep -nE "^[[:space:]]*root[[:space:]]*$" /etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd.ftpusers /etc/vsftpd/ftpusers /etc/vsftpd.user_list /etc/vsftpd/user_list 2>/dev/null'

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""
VULN=0
FTP_FOUND=0
DETAIL_LINES=""

add_detail(){ [ -n "${1:-}" ] && DETAIL_LINES="${DETAIL_LINES}${DETAIL_LINES:+\\n}$1"; }
add_file(){ [ -n "${1:-}" ] && TARGET_FILE="${TARGET_FILE}${TARGET_FILE:+, }$1"; }

# 주석/공백 제외하고 root 단독 라인 존재 확인
has_root_line(){
  local f="$1"
  [ -f "$f" ] || return 2
  grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$f" 2>/dev/null | grep -qE '^[[:space:]]*root[[:space:]]*$'
}

# vsftpd conf에서 key=VALUE 마지막 값
vs_kv(){
  local conf="$1" key="$2"
  grep -iE "^[[:space:]]*${key}[[:space:]]*=" "$conf" 2>/dev/null | grep -v '^[[:space:]]*#' | tail -n1 | sed -E 's/.*=[[:space:]]*//; s/[[:space:]]*$//'
}

upper(){ echo "${1:-}" | tr '[:lower:]' '[:upper:]'; }

# -------------------------
# 1) vsftpd 점검
# -------------------------
VS_CONF=""
[ -f /etc/vsftpd.conf ] && VS_CONF="/etc/vsftpd.conf"
[ -z "$VS_CONF" ] && [ -f /etc/vsftpd/vsftpd.conf ] && VS_CONF="/etc/vsftpd/vsftpd.conf"

if command -v vsftpd >/dev/null 2>&1 || [ -n "$VS_CONF" ] || systemctl list-units --type=service 2>/dev/null | grep -q vsftpd; then
  FTP_FOUND=1
  if [ -n "$VS_CONF" ] && [ -f "$VS_CONF" ]; then
    add_file "$VS_CONF"
    ULE="$(vs_kv "$VS_CONF" userlist_enable)"; ULD="$(vs_kv "$VS_CONF" userlist_deny)"; ULF="$(vs_kv "$VS_CONF" userlist_file)"
    ULE="${ULE:-not_set}"; ULD="${ULD:-not_set}"; ULF="${ULF:-not_set}"
    add_detail "[vsftpd] conf=$VS_CONF userlist_enable=$ULE userlist_deny=$ULD userlist_file=$ULF"

    if [ "$(upper "$ULE")" = "YES" ]; then
      # user_list 모드
      LIST_FILE="$ULF"
      if [ "$LIST_FILE" = "not_set" ] || [ -z "$LIST_FILE" ]; then
        LIST_FILE="/etc/vsftpd.user_list"; [ ! -f "$LIST_FILE" ] && LIST_FILE="/etc/vsftpd/user_list"
      fi
      add_file "$LIST_FILE"

      if [ "$(upper "$ULD")" = "NO" ]; then
        # whitelist: root가 목록에 있으면 허용 -> 취약
        if has_root_line "$LIST_FILE"; then
          VULN=1
          add_detail "[vsftpd] userlist_deny=NO(whitelist) & root PRESENT -> root FTP login may be allowed"
        else
          add_detail "[vsftpd] userlist_deny=NO(whitelist) & root ABSENT -> root FTP login blocked"
        fi
      else
        # blacklist(deny=YES 또는 미설정): root가 목록에 있어야 차단
        if has_root_line "$LIST_FILE"; then
          add_detail "[vsftpd] userlist_deny!=NO(blacklist) & root PRESENT -> root FTP login blocked"
        else
          VULN=1
          add_detail "[vsftpd] userlist_deny!=NO(blacklist) & root ABSENT -> root FTP login may be allowed"
        fi
      fi
    else
      # ftpusers 모드
      F="/etc/vsftpd.ftpusers"; [ ! -f "$F" ] && F="/etc/vsftpd/ftpusers"; [ ! -f "$F" ] && F="/etc/ftpusers"
      add_file "$F"
      if has_root_line "$F"; then
        add_detail "[vsftpd] ftpusers has root -> root FTP login blocked"
      else
        VULN=1
        add_detail "[vsftpd] ftpusers missing root(or file missing) -> root FTP login may be allowed"
      fi
    fi
  else
    VULN=1
    add_detail "[vsftpd] detected but config NOT_FOUND -> cannot verify root block policy"
  fi
fi

# -------------------------
# 2) proftpd 점검
# -------------------------
PF_CONF=""
[ -f /etc/proftpd/proftpd.conf ] && PF_CONF="/etc/proftpd/proftpd.conf"
[ -z "$PF_CONF" ] && [ -f /etc/proftpd.conf ] && PF_CONF="/etc/proftpd.conf"

if command -v proftpd >/dev/null 2>&1 || [ -n "$PF_CONF" ] || systemctl list-units --type=service 2>/dev/null | grep -q proftpd; then
  FTP_FOUND=1
  if [ -n "$PF_CONF" ] && [ -f "$PF_CONF" ]; then
    add_file "$PF_CONF"
    USE="$(grep -Ei '^[[:space:]]*UseFtpUsers[[:space:]]+' "$PF_CONF" 2>/dev/null | grep -v '^[[:space:]]*#' | tail -n1 | awk '{print tolower($2)}')"
    USE="${USE:-on}"
    add_detail "[proftpd] conf=$PF_CONF UseFtpUsers=$USE"

    if [ "$USE" = "off" ]; then
      RL="$(grep -Ei '^[[:space:]]*RootLogin[[:space:]]+' "$PF_CONF" 2>/dev/null | grep -v '^[[:space:]]*#' | tail -n1 | awk '{print tolower($2)}')"
      RL="${RL:-not_set}"
      add_detail "[proftpd] RootLogin=$RL"
      if [ "$RL" = "off" ]; then
        add_detail "[proftpd] RootLogin off -> root FTP login blocked"
      else
        VULN=1
        add_detail "[proftpd] UseFtpUsers off but RootLogin off NOT set -> root FTP login may be allowed"
      fi
    else
      FU="/etc/ftpusers"; [ ! -f "$FU" ] && FU="/etc/ftpd/ftpusers"
      add_file "$FU"
      if has_root_line "$FU"; then
        add_detail "[proftpd] ftpusers has root -> root FTP login blocked"
      else
        VULN=1
        add_detail "[proftpd] ftpusers missing root(or file missing) -> root FTP login may be allowed"
      fi
    fi
  else
    VULN=1
    add_detail "[proftpd] detected but config NOT_FOUND -> cannot verify root block policy"
  fi
fi

# -------------------------
# 3) FTP 미탐지 fallback(ftpusers만 존재하는 경우 참고)
# -------------------------
if [ "$FTP_FOUND" -eq 0 ]; then
  if [ -f /etc/ftpusers ] || [ -f /etc/ftpd/ftpusers ]; then
    FU="/etc/ftpusers"; [ ! -f "$FU" ] && FU="/etc/ftpd/ftpusers"
    add_file "$FU"
    if has_root_line "$FU"; then
      STATUS="PASS"
      REASON_LINE="$FU 파일에 root 계정 차단 설정이 존재하여 이 항목에 대한 보안 위협이 없습니다."
      DETAIL_CONTENT="[fallback] ftp_service=not_detected, root_blocked=Y, file=$FU"
    else
      STATUS="FAIL"
      REASON_LINE="$FU 파일에서 root 계정 차단 설정을 확인할 수 있어 취약합니다. 조치: ftpusers(또는 서비스별 user_list/설정)에 root 차단을 추가하거나 FTP 서비스를 비활성화하십시오."
      DETAIL_CONTENT="[fallback] ftp_service=not_detected, root_blocked=NOT_CONFIRMED, file=$FU"
    fi
  else
    STATUS="PASS"
    REASON_LINE="FTP 서비스가 확인되지 않으며 관련 차단 파일도 없어 점검 대상이 제한적이어서 이 항목에 대한 보안 위협이 없습니다."
    DETAIL_CONTENT="ftp_service=not_detected"
  fi
else
  DETAIL_CONTENT="${DETAIL_LINES:-none}"
  if [ "$VULN" -eq 1 ]; then
    STATUS="FAIL"
    REASON_LINE="FTP 서비스 설정에서 root 계정 접속이 허용될 수 있어 취약합니다. 조치: vsftpd는 ftpusers/user_list에서 root 차단(또는 RootLogin/관련 옵션 적용), ProFTPD는 UseFtpUsers 사용 또는 RootLogin off 설정을 적용하십시오."
  else
    STATUS="PASS"
    REASON_LINE="FTP 서비스 설정에서 root 계정 접속이 차단되어 있어 이 항목에 대한 보안 위협이 없습니다."
  fi
fi

# target_file 비어있을 때 기본 후보
[ -z "$TARGET_FILE" ] && TARGET_FILE="/etc/ftpusers, /etc/ftpd/ftpusers, /etc/vsftpd.user_list, /etc/vsftpd/user_list, /etc/vsftpd.ftpusers, /etc/vsftpd/ftpusers, /etc/vsftpd.conf, /etc/vsftpd/vsftpd.conf, /etc/proftpd/proftpd.conf, /etc/proftpd.conf"

# raw_evidence 구성 (첫 줄: 평가 이유 / 다음 줄: 상세 증적)
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

# escape 처리(따옴표, 줄바꿈)
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" | sed 's/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g')

echo ""
cat <<EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF