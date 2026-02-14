#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.1.0
# @Author: 이가영
# @Last Updated: 2026-02-14
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

CHECK_COMMAND='getent passwd ftp 2>/dev/null || echo "ftp_account_not_found"'
REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE="/etc/passwd"

ACTION_ERR_LOG=""
MODIFIED=0

append_err() {
  if [ -n "$ACTION_ERR_LOG" ]; then
    ACTION_ERR_LOG="${ACTION_ERR_LOG}\n$1"
  else
    ACTION_ERR_LOG="$1"
  fi
}

# (필수) root 권한 권장 안내(실패 원인 명확화용)
if [ "$(id -u)" -ne 0 ]; then
  ACTION_ERR_LOG="(주의) root 권한이 아니면 usermod가 실패할 수 있습니다."
fi

pick_lock_shell() {
  # Rocky 계열에서 /sbin/nologin 또는 /usr/sbin/nologin 존재 가능
  if [ -x /sbin/nologin ]; then
    echo "/sbin/nologin"
    return 0
  fi
  if [ -x /usr/sbin/nologin ]; then
    echo "/usr/sbin/nologin"
    return 0
  fi
  if [ -x /bin/false ]; then
    echo "/bin/false"
    return 0
  fi
  echo ""
  return 1
}

is_locked_shell() {
  case "$1" in
    /bin/false|/sbin/nologin|/usr/sbin/nologin) return 0 ;;
    *) return 1 ;;
  esac
}

########################################
# 조치 프로세스
########################################
if [ "$(id -u)" -ne 0 ]; then
  IS_SUCCESS=0
  REASON_LINE="root 권한이 아니어서 ftp 계정의 로그인 쉘 제한을 적용할 수 없어 조치를 중단합니다."
  DETAIL_CONTENT="$ACTION_ERR_LOG"
else
  if ! command -v getent >/dev/null 2>&1; then
    IS_SUCCESS=0
    REASON_LINE="getent 명령을 사용할 수 없어 ftp 계정 확인 및 조치를 수행할 수 없어 조치가 완료되지 않았습니다."
    DETAIL_CONTENT="getent_not_found"
  else
    if ! getent passwd ftp >/dev/null 2>&1; then
      IS_SUCCESS=1
      REASON_LINE="ftp 계정이 존재하지 않아 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
      DETAIL_CONTENT="ftp_account(after)=not_found"
    else
      CURRENT_SHELL="$(getent passwd ftp | awk -F: '{print $7}')"
      if is_locked_shell "$CURRENT_SHELL"; then
        IS_SUCCESS=1
        REASON_LINE="ftp 계정의 로그인 쉘이 이미 제한되어 있어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
        DETAIL_CONTENT="ftp_shell(after)=$CURRENT_SHELL"
      else
        if ! command -v usermod >/dev/null 2>&1; then
          IS_SUCCESS=0
          REASON_LINE="usermod 명령을 사용할 수 없어 ftp 계정 쉘 제한을 자동으로 수행하지 못해 조치가 완료되지 않았습니다."
          DETAIL_CONTENT="ftp_shell(after)=$CURRENT_SHELL\nusermod_not_found"
        else
          LOCK_SHELL="$(pick_lock_shell)"
          if [ -z "$LOCK_SHELL" ]; then
            IS_SUCCESS=0
            REASON_LINE="nologin/false 실행 파일을 찾지 못해 ftp 계정 쉘 제한을 수행할 수 없어 조치가 완료되지 않았습니다."
            DETAIL_CONTENT="ftp_shell(after)=$CURRENT_SHELL\nlock_shell_not_found"
          else
            usermod -s "$LOCK_SHELL" ftp >/dev/null 2>&1 || append_err "usermod 실패"
            MODIFIED=1

            AFTER_SHELL="$(getent passwd ftp | awk -F: '{print $7}')"
            DETAIL_CONTENT="ftp_shell(after)=$AFTER_SHELL"
            if [ -n "$ACTION_ERR_LOG" ]; then
              DETAIL_CONTENT="$DETAIL_CONTENT\n$ACTION_ERR_LOG"
            fi

            if is_locked_shell "$AFTER_SHELL"; then
              IS_SUCCESS=1
              REASON_LINE="ftp 계정의 로그인 쉘이 제한되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
            else
              IS_SUCCESS=0
              REASON_LINE="조치를 수행했으나 ftp 계정의 로그인 쉘이 제한되지 않아 조치가 완료되지 않았습니다."
            fi
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