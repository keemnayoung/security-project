#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.0
# @Author: 이가영
# @Last Updated: 2026-02-16
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-55
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : FTP 계정 shell 제한
# @Description : FTP 전용 계정(ftp)의 로그인 쉘을 제한(/sbin/nologin 또는 /bin/false)
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================


# 기본 변수
ID="U-55"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

TARGET_FILE="/etc/passwd"
CHECK_COMMAND='(command -v getent >/dev/null 2>&1 && getent passwd ftp) || awk -F: '\''$1=="ftp"{print; exit}'\'' /etc/passwd 2>/dev/null || echo "ftp_account_not_found"'
REASON_LINE=""
DETAIL_CONTENT=""
ERR=""

json_escape() { echo -n "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; :a;N;$!ba;s/\n/\\n/g'; }

pick_lock_shell() {
  [ -x /sbin/nologin ] && echo /sbin/nologin && return
  [ -x /usr/sbin/nologin ] && echo /usr/sbin/nologin && return
  [ -x /bin/false ] && echo /bin/false && return
  echo ""
}
is_locked_shell() { case "$1" in /bin/false|/sbin/nologin|/usr/sbin/nologin) return 0;; *) return 1;; esac; }

get_ftp_entry() {
  if command -v getent >/dev/null 2>&1; then
    getent passwd ftp 2>/dev/null
  else
    awk -F: '$1=="ftp"{print; exit}' "$TARGET_FILE" 2>/dev/null
  fi
}
get_ftp_shell() { echo "$1" | awk -F: '{print $7}'; }

# 조치 프로세스
if [ "$(id -u)" -ne 0 ]; then
  REASON_LINE="root 권한이 아니어서 ftp 계정의 로그인 쉘 제한을 적용할 수 없어 조치를 중단합니다."
  DETAIL_CONTENT="current=unknown"
elif [ ! -f "$TARGET_FILE" ]; then
  REASON_LINE="/etc/passwd 파일이 존재하지 않아 조치를 수행할 수 없어 조치가 완료되지 않았습니다."
  DETAIL_CONTENT="file_not_found"
else
  ENTRY="$(get_ftp_entry)"
  if [ -z "$ENTRY" ]; then
    IS_SUCCESS=1
    REASON_LINE="ftp 계정이 존재하지 않아 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
    DETAIL_CONTENT="ftp_account(after)=not_found"
  else
    CUR_SHELL="$(get_ftp_shell "$ENTRY")"
    if is_locked_shell "$CUR_SHELL"; then
      IS_SUCCESS=1
      REASON_LINE="ftp 계정의 로그인 쉘이 이미 제한되어 있어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
      DETAIL_CONTENT="ftp_shell(after)=$CUR_SHELL"
    else
      if ! command -v usermod >/dev/null 2>&1; then
        REASON_LINE="usermod 명령을 사용할 수 없어 ftp 계정 쉘 제한을 자동으로 수행하지 못해 조치가 완료되지 않았습니다."
        DETAIL_CONTENT="ftp_shell(after)=$CUR_SHELL\nusermod_not_found"
      else
        LOCK_SHELL="$(pick_lock_shell)"
        if [ -z "$LOCK_SHELL" ]; then
          REASON_LINE="nologin/false 실행 파일을 찾지 못해 ftp 계정 쉘 제한을 수행할 수 없어 조치가 완료되지 않았습니다."
          DETAIL_CONTENT="ftp_shell(after)=$CUR_SHELL\nlock_shell_not_found"
        else
          usermod -s "$LOCK_SHELL" ftp >/dev/null 2>&1 || ERR="usermod_failed"
          AFTER_ENTRY="$(get_ftp_entry)"
          AFTER_SHELL="$(get_ftp_shell "$AFTER_ENTRY")"
          DETAIL_CONTENT="ftp_shell(after)=$AFTER_SHELL"
          [ -n "$ERR" ] && DETAIL_CONTENT="$DETAIL_CONTENT\n$ERR"

          if is_locked_shell "$AFTER_SHELL"; then
            IS_SUCCESS=1
            REASON_LINE="ftp 계정의 로그인 쉘이 제한되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
          else
            REASON_LINE="조치를 수행했으나 ftp 계정의 로그인 쉘이 제한되지 않아 조치가 완료되지 않았습니다."
          fi
        fi
      fi
    fi
  fi
fi

# raw_evidence 구성
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE
$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

RAW_EVIDENCE_ESCAPED="$(json_escape "$RAW_EVIDENCE")"

echo ""
cat <<EOF
{
    "item_code": "$ID",
    "action_date": "$ACTION_DATE",
    "is_success": $IS_SUCCESS,
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
}
EOF