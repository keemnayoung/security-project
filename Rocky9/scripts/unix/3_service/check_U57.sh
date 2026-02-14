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

# 기본 변수
ID="U-57"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""
CHECK_COMMAND='command -v vsftpd; command -v proftpd; systemctl is-active vsftpd proftpd; grep -nE "^[[:space:]]*(userlist_enable|userlist_deny|userlist_file)" /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null; grep -nE "^[[:space:]]*(UseFtpUsers|RootLogin)" /etc/proftpd/proftpd.conf /etc/proftpd.conf 2>/dev/null; grep -nE "^[[:space:]]*root[[:space:]]*$" /etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd.ftpusers /etc/vsftpd/ftpusers /etc/vsftpd.user_list /etc/vsftpd/user_list 2>/dev/null'

VULNERABLE=0
FTP_DETECTED=0
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

# 주석/공백 제외하고 root 라인 존재 여부
root_present_in_blacklist() {
  local f="$1"
  [ -f "$f" ] || return 2
  grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$f" 2>/dev/null | grep -qE '^[[:space:]]*root[[:space:]]*$'
}

# vsftpd userlist 설정값 읽기(미설정 시 기본값 가정은 하지 않고 "unknown"으로 둠)
get_vsftpd_conf_value() {
  local conf="$1"
  local key="$2"
  # 마지막 유효 라인을 사용
  grep -iE "^[[:space:]]*${key}[[:space:]]*=" "$conf" 2>/dev/null | grep -v '^[[:space:]]*#' | tail -n1 | sed -E 's/.*=[[:space:]]*//; s/[[:space:]]*$//'
}

# -----------------------------
# 1) vsftpd 점검
# - userlist_enable=YES 인 경우:
#   - userlist_deny=YES(기본 blacklist): userlist_file에 root가 있어야 차단(양호)
#   - userlist_deny=NO(whitelist): root가 "목록에 없으면" 차단(양호), 있으면 허용(취약)
# - userlist_enable!=YES 인 경우:
#   - ftpusers(또는 vsftpd.ftpusers/vsftpd/ftpusers/ftpusers) blacklist에 root가 있어야 차단(양호)
# -----------------------------
VSFTPD_CONF=""
if [ -f "/etc/vsftpd.conf" ]; then
  VSFTPD_CONF="/etc/vsftpd.conf"
elif [ -f "/etc/vsftpd/vsftpd.conf" ]; then
  VSFTPD_CONF="/etc/vsftpd/vsftpd.conf"
fi

if command -v vsftpd >/dev/null 2>&1 || [ -n "$VSFTPD_CONF" ] || systemctl list-units --type=service 2>/dev/null | grep -q vsftpd; then
  FTP_DETECTED=1

  if [ -n "$VSFTPD_CONF" ] && [ -f "$VSFTPD_CONF" ]; then
    add_target_file "$VSFTPD_CONF"

    ULE="$(get_vsftpd_conf_value "$VSFTPD_CONF" "userlist_enable")"
    ULD="$(get_vsftpd_conf_value "$VSFTPD_CONF" "userlist_deny")"
    ULF="$(get_vsftpd_conf_value "$VSFTPD_CONF" "userlist_file")"

    [ -z "$ULE" ] && ULE="(not_set)"
    [ -z "$ULD" ] && ULD="(not_set)"
    [ -z "$ULF" ] && ULF="(not_set)"

    append_detail "[vsftpd] conf=$VSFTPD_CONF userlist_enable=$ULE userlist_deny=$ULD userlist_file=$ULF"

    # userlist_enable=YES 인지 판단(대소문자 무시)
    if echo "$ULE" | tr '[:lower:]' '[:upper:]' | grep -q '^YES$'; then
      # userlist_file 결정(미설정이면 기본 후보)
      USERLIST_FILE="$ULF"
      if [ "$USERLIST_FILE" = "(not_set)" ] || [ -z "$USERLIST_FILE" ]; then
        USERLIST_FILE="/etc/vsftpd.user_list"
        [ ! -f "$USERLIST_FILE" ] && USERLIST_FILE="/etc/vsftpd/user_list"
      fi
      add_target_file "$USERLIST_FILE"

      # deny 모드 결정(미설정이면 vsftpd 기본은 YES로 알려져 있으나, 여기서는 "not_set"을 보수적으로 처리)
      ULD_UP="$(echo "$ULD" | tr '[:lower:]' '[:upper:]')"

      if [ "$ULD_UP" = "NO" ]; then
        # whitelist: root가 목록에 있으면 허용 -> 취약, 없으면 차단 -> 양호
        if root_present_in_blacklist "$USERLIST_FILE"; then
          VULNERABLE=1
          append_detail "[vsftpd] userlist_deny=NO(whitelist) but root is PRESENT -> root login may be allowed"
        else
          append_detail "[vsftpd] userlist_deny=NO(whitelist) and root is NOT present -> root login blocked"
        fi
      else
        # blacklist(deny=YES 또는 not_set): root가 목록에 있어야 차단 -> 양호
        if root_present_in_blacklist "$USERLIST_FILE"; then
          append_detail "[vsftpd] userlist_deny!=NO(blacklist) and root is PRESENT -> root login blocked"
        else
          VULNERABLE=1
          append_detail "[vsftpd] userlist_deny!=NO(blacklist) but root is NOT present -> root login may be allowed"
        fi
      fi
    else
      # userlist_enable != YES => ftpusers 계열 사용(blacklist)
      FTPUSERS_FILE="/etc/vsftpd.ftpusers"
      [ ! -f "$FTPUSERS_FILE" ] && FTPUSERS_FILE="/etc/vsftpd/ftpusers"
      [ ! -f "$FTPUSERS_FILE" ] && FTPUSERS_FILE="/etc/ftpusers"
      add_target_file "$FTPUSERS_FILE"

      if root_present_in_blacklist "$FTPUSERS_FILE"; then
        append_detail "[vsftpd] ftpusers blacklist has root -> root login blocked"
      else
        VULNERABLE=1
        append_detail "[vsftpd] ftpusers blacklist missing root(or file missing) -> root login may be allowed"
      fi
    fi

    if systemctl is-active --quiet vsftpd 2>/dev/null; then
      append_detail "[vsftpd] service_active=Y"
    else
      append_detail "[vsftpd] service_active=N"
    fi
  else
    # 바이너리/서비스 흔적은 있는데 설정 파일 확인 불가
    VULNERABLE=1
    append_detail "[vsftpd] detected but config_file=NOT_FOUND -> cannot verify root block policy"
  fi
fi

# -----------------------------
# 2) proftpd 점검
# - UseFtpUsers on(기본)  : /etc/ftpusers blacklist에서 root 차단(양호=있음)
# - UseFtpUsers off       : RootLogin off가 있어야 차단(양호)
# -----------------------------
PROFTPD_CONF=""
if [ -f "/etc/proftpd/proftpd.conf" ]; then
  PROFTPD_CONF="/etc/proftpd/proftpd.conf"
elif [ -f "/etc/proftpd.conf" ]; then
  PROFTPD_CONF="/etc/proftpd.conf"
fi

if command -v proftpd >/dev/null 2>&1 || [ -n "$PROFTPD_CONF" ] || systemctl list-units --type=service 2>/dev/null | grep -q proftpd; then
  FTP_DETECTED=1

  if [ -n "$PROFTPD_CONF" ] && [ -f "$PROFTPD_CONF" ]; then
    add_target_file "$PROFTPD_CONF"

    USE_FTPUSERS="$(grep -Ei '^[[:space:]]*UseFtpUsers' "$PROFTPD_CONF" 2>/dev/null | grep -v '^[[:space:]]*#' | tail -n1 | awk '{print tolower($2)}')"
    [ -z "$USE_FTPUSERS" ] && USE_FTPUSERS="on"
    append_detail "[proftpd] conf=$PROFTPD_CONF UseFtpUsers=$USE_FTPUSERS"

    if [ "$USE_FTPUSERS" = "off" ]; then
      ROOT_LOGIN="$(grep -Ei '^[[:space:]]*RootLogin' "$PROFTPD_CONF" 2>/dev/null | grep -v '^[[:space:]]*#' | tail -n1 | awk '{print tolower($2)}')"
      [ -z "$ROOT_LOGIN" ] && ROOT_LOGIN="(not_set)"
      append_detail "[proftpd] RootLogin=$ROOT_LOGIN"

      if echo "$ROOT_LOGIN" | grep -qi '^off$'; then
        append_detail "[proftpd] RootLogin off -> root login blocked"
      else
        VULNERABLE=1
        append_detail "[proftpd] UseFtpUsers off but RootLogin off NOT set -> root login may be allowed"
      fi
    else
      # ftpusers blacklist
      FU_FILE="/etc/ftpusers"
      [ ! -f "$FU_FILE" ] && FU_FILE="/etc/ftpd/ftpusers"
      add_target_file "$FU_FILE"

      if root_present_in_blacklist "$FU_FILE"; then
        append_detail "[proftpd] ftpusers blacklist has root -> root login blocked"
      else
        VULNERABLE=1
        append_detail "[proftpd] ftpusers blacklist missing root(or file missing) -> root login may be allowed"
      fi
    fi

    if systemctl is-active --quiet proftpd 2>/dev/null; then
      append_detail "[proftpd] service_active=Y"
    else
      append_detail "[proftpd] service_active=N"
    fi
  else
    VULNERABLE=1
    append_detail "[proftpd] detected but config_file=NOT_FOUND -> cannot verify root block policy"
  fi
fi

# -----------------------------
# 3) 일반 FTP(서비스 종류 확인이 어려운 경우) fallback
# -----------------------------
if [ "$FTP_DETECTED" -eq 0 ]; then
  # FTP 자체가 설치/사용되지 않는 환경일 가능성이 높음
  # 다만 ftpusers 파일이 있으면 root 차단 여부를 참고로 점검
  if [ -f "/etc/ftpusers" ] || [ -f "/etc/ftpd/ftpusers" ]; then
    FU_FILE="/etc/ftpusers"
    [ ! -f "$FU_FILE" ] && FU_FILE="/etc/ftpd/ftpusers"
    add_target_file "$FU_FILE"

    if root_present_in_blacklist "$FU_FILE"; then
      STATUS="PASS"
      REASON_LINE="FTP 서비스가 확인되지 않으며, ftpusers 파일에 root 차단 설정이 존재하여 이 항목에 대한 보안 위협이 없습니다."
      DETAIL_CONTENT="[fallback] ftp_service=not_detected but root_blocked=Y in $FU_FILE"
    else
      STATUS="FAIL"
      VULNERABLE=1
      REASON_LINE="FTP 서비스가 확인되지 않으나, ftpusers 파일에서 root 차단 설정을 확인할 수 없어 취약합니다. FTP를 사용하지 않는다면 서비스를 비활성화 상태로 유지하고, 사용한다면 root FTP 접속이 차단되도록 설정해야 합니다."
      DETAIL_CONTENT="[fallback] ftp_service=not_detected but root_blocked=NOT_CONFIRMED in $FU_FILE"
    fi
  else
    STATUS="PASS"
    REASON_LINE="FTP 서비스가 설치되어 있지 않아 점검 대상이 없습니다."
    DETAIL_CONTENT="none"
  fi
else
  if [ "$VULNERABLE" -eq 1 ]; then
    STATUS="FAIL"
    REASON_LINE="root 계정으로 FTP 접속이 허용될 수 있어 취약합니다. root 계정의 FTP 접속은 중요한 시스템 정보 및 파일 노출로 이어질 수 있으므로 ftpusers(user_list 포함) 또는 서비스 설정을 통해 root 접속을 차단해야 합니다."
  else
    STATUS="PASS"
    REASON_LINE="root 계정의 FTP 접속이 차단되어 있어 이 항목에 대한 보안 위협이 없습니다."
  fi

  DETAIL_CONTENT="$DETAIL_LINES"
  [ -z "$DETAIL_CONTENT" ] && DETAIL_CONTENT="none"
fi

# target_file 기본값 보정
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