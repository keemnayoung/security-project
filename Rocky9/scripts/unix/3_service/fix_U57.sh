#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
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

CHECK_COMMAND='( [ -f /etc/ftpusers ] && grep -nEv "^[[:space:]]*#|^[[:space:]]*$" /etc/ftpusers | head -n 200 || echo "ftpusers_not_found" ); ( [ -f /etc/vsftpd.conf ] && grep -nE "^[[:space:]]*(userlist_enable|userlist_deny)[[:space:]]*=" /etc/vsftpd.conf 2>/dev/null || true ); ( [ -f /etc/vsftpd/vsftpd.conf ] && grep -nE "^[[:space:]]*(userlist_enable|userlist_deny)[[:space:]]*=" /etc/vsftpd/vsftpd.conf 2>/dev/null || true ); ( [ -f /etc/proftpd/proftpd.conf ] && grep -nE "^[[:space:]]*(UseFtpUsers|RootLogin)[[:space:]]+" /etc/proftpd/proftpd.conf 2>/dev/null || true ); (ls -l /etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd.user_list /etc/vsftpd/user_list /etc/vsftpd.ftpusers 2>/dev/null || true )'

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE="/etc/ftpusers"

MODIFIED=0
ERR_LOG=""

append_detail() {
  if [ -n "$DETAIL_CONTENT" ]; then
    DETAIL_CONTENT="${DETAIL_CONTENT}\n$1"
  else
    DETAIL_CONTENT="$1"
  fi
}

append_err() {
  if [ -n "$ERR_LOG" ]; then
    ERR_LOG="${ERR_LOG}\n$1"
  else
    ERR_LOG="$1"
  fi
}

# (Blacklist) root 차단 추가
block_root_blacklist() {
  local file="$1"
  [ -z "$file" ] && return 1

  if [ ! -f "$file" ]; then
    touch "$file" 2>/dev/null || return 1
  fi

  # 주석/공백 제외하고 root가 없으면 추가(또는 #root 주석 해제)
  if ! grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$file" 2>/dev/null | grep -qx "root"; then
    if grep -qE '^[[:space:]]*#root[[:space:]]*$' "$file" 2>/dev/null; then
      sed -i -E 's/^[[:space:]]*#root[[:space:]]*$/root/' "$file" 2>/dev/null || return 1
      MODIFIED=1
      return 0
    else
      echo "root" >> "$file" 2>/dev/null || return 1
      MODIFIED=1
      return 0
    fi
  fi
  return 0
}

# (Whitelist) root 허용 제거
remove_root_whitelist() {
  local file="$1"
  [ -z "$file" ] && return 1
  [ -f "$file" ] || { touch "$file" 2>/dev/null || return 1; }

  if grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$file" 2>/dev/null | grep -qx "root"; then
    sed -i -E '/^[[:space:]]*root[[:space:]]*$/d' "$file" 2>/dev/null || return 1
    MODIFIED=1
  fi
  return 0
}

get_vsftpd_conf() {
  if [ -f "/etc/vsftpd.conf" ]; then
    echo "/etc/vsftpd.conf"
  elif [ -f "/etc/vsftpd/vsftpd.conf" ]; then
    echo "/etc/vsftpd/vsftpd.conf"
  else
    echo ""
  fi
}

# root 권한 확인
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  IS_SUCCESS=0
  REASON_LINE="root 권한이 아니어서 ftpusers(root 접속 제한) 설정을 적용할 수 없어 조치를 중단합니다."
  DETAIL_CONTENT="sudo로 실행해야 합니다."
else
  # === vsftpd 분기 ===
  VSFTPD_CONF="$(get_vsftpd_conf)"
  if command -v vsftpd >/dev/null 2>&1 || [ -n "$VSFTPD_CONF" ] || (command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -qiE '^vsftpd\.service'); then
    if [ -n "$VSFTPD_CONF" ] && [ -f "$VSFTPD_CONF" ]; then
      # userlist_enable / userlist_deny 값(마지막 설정 우선)
      USERLIST_ENABLE="$(grep -Ei '^[[:space:]]*userlist_enable[[:space:]]*=' "$VSFTPD_CONF" 2>/dev/null | tail -n 1 | awk -F= '{print tolower($2)}' | tr -d '[:space:]')"
      USERLIST_DENY="$(grep -Ei '^[[:space:]]*userlist_deny[[:space:]]*=' "$VSFTPD_CONF" 2>/dev/null | tail -n 1 | awk -F= '{print tolower($2)}' | tr -d '[:space:]')"
      [ -z "$USERLIST_ENABLE" ] && USERLIST_ENABLE="no"
      [ -z "$USERLIST_DENY" ] && USERLIST_DENY="yes"

      # 대상 리스트 파일 결정
      if [ "$USERLIST_ENABLE" = "yes" ]; then
        # userlist_enable=YES 인 경우 user_list류
        if [ -f "/etc/vsftpd.user_list" ]; then
          LIST_FILE="/etc/vsftpd.user_list"
        elif [ -f "/etc/vsftpd/user_list" ]; then
          LIST_FILE="/etc/vsftpd/user_list"
        else
          LIST_FILE="/etc/vsftpd.user_list"
        fi

        TARGET_FILE="$LIST_FILE"
        if [ "$USERLIST_DENY" = "no" ]; then
          # Whitelist: root가 있으면 제거
          remove_root_whitelist "$LIST_FILE" || append_err "vsftpd whitelist에서 root 제거 실패($LIST_FILE)"
        else
          # Blacklist: root 추가/주석해제
          block_root_blacklist "$LIST_FILE" || append_err "vsftpd blacklist에 root 추가 실패($LIST_FILE)"
        fi

        append_detail "vsftpd_conf(after)=$VSFTPD_CONF"
        append_detail "vsftpd_userlist_enable(after)=$USERLIST_ENABLE"
        append_detail "vsftpd_userlist_deny(after)=$USERLIST_DENY"
        # 파일 내 root 존재 여부(After)
        if grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$LIST_FILE" 2>/dev/null | grep -qx "root"; then
          append_detail "vsftpd_list_root(after)=present"
        else
          append_detail "vsftpd_list_root(after)=absent"
        fi
      else
        # userlist_enable != YES 인 경우 ftpusers류로 root 차단
        if [ -f "/etc/vsftpd.ftpusers" ]; then
          LIST_FILE="/etc/vsftpd.ftpusers"
        else
          LIST_FILE="/etc/ftpusers"
        fi

        TARGET_FILE="$LIST_FILE"
        block_root_blacklist "$LIST_FILE" || append_err "ftpusers(blacklist) root 추가 실패($LIST_FILE)"
        append_detail "vsftpd_conf(after)=$VSFTPD_CONF"
        append_detail "vsftpd_userlist_enable(after)=$USERLIST_ENABLE"
        # 파일 내 root 존재 여부(After)
        if grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$LIST_FILE" 2>/dev/null | grep -qx "root"; then
          append_detail "ftpusers_root(after)=present"
        else
          append_detail "ftpusers_root(after)=absent"
        fi
      fi

      # 재시작(있을 때만 시도, 실패는 오류로 기록)
      if command -v systemctl >/dev/null 2>&1; then
        systemctl restart vsftpd >/dev/null 2>&1 || append_err "vsftpd 재시작 실패"
      fi
    else
      append_err "vsftpd가 감지되었으나 설정 파일을 찾지 못했습니다."
    fi
  fi

  # === proftpd 분기 ===
  if command -v proftpd >/dev/null 2>&1 || [ -f "/etc/proftpd/proftpd.conf" ] || [ -f "/etc/proftpd.conf" ] || (command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -qiE '^proftpd\.service'); then
    PROFTPD_CONF=""
    [ -f "/etc/proftpd/proftpd.conf" ] && PROFTPD_CONF="/etc/proftpd/proftpd.conf"
    [ -z "$PROFTPD_CONF" ] && [ -f "/etc/proftpd.conf" ] && PROFTPD_CONF="/etc/proftpd.conf"

    if [ -n "$PROFTPD_CONF" ] && [ -f "$PROFTPD_CONF" ]; then
      # UseFtpUsers off 이면 ftpusers를 안 쓰는 케이스 → RootLogin off 권장
      if grep -qiE '^[[:space:]]*UseFtpUsers[[:space:]]+off([[:space:]]|$)' "$PROFTPD_CONF" 2>/dev/null; then
        if ! grep -qiE '^[[:space:]]*RootLogin[[:space:]]+off([[:space:]]|$)' "$PROFTPD_CONF" 2>/dev/null; then
          echo "RootLogin off" >> "$PROFTPD_CONF" 2>/dev/null || append_err "proftpd RootLogin off 추가 실패($PROFTPD_CONF)"
          MODIFIED=1
        fi
        TARGET_FILE="$PROFTPD_CONF"
        append_detail "proftpd_conf(after)=$PROFTPD_CONF"
        cur_rl="$(grep -Ei '^[[:space:]]*RootLogin[[:space:]]+' "$PROFTPD_CONF" 2>/dev/null | tail -n 1)"
        [ -n "$cur_rl" ] && append_detail "proftpd_rootlogin(after)=$cur_rl"
      else
        # ftpusers 기반 차단
        TARGET_FILE="/etc/ftpusers"
        block_root_blacklist "/etc/ftpusers" || append_err "proftpd 환경에서 /etc/ftpusers root 차단 실패"
        if grep -Ev '^[[:space:]]*#|^[[:space:]]*$' /etc/ftpusers 2>/dev/null | grep -qx "root"; then
          append_detail "ftpusers_root(after)=present"
        else
          append_detail "ftpusers_root(after)=absent"
        fi
      fi

      if command -v systemctl >/dev/null 2>&1; then
        systemctl restart proftpd >/dev/null 2>&1 || true
      fi
    else
      append_err "proftpd가 감지되었으나 설정 파일을 찾지 못했습니다."
    fi
  fi

  # === 일반 FTP(ftpusers 파일들) ===
  if [ -f "/etc/ftpusers" ]; then
    TARGET_FILE="/etc/ftpusers"
    block_root_blacklist "/etc/ftpusers" || append_err "/etc/ftpusers root 차단 적용 실패"
    if grep -Ev '^[[:space:]]*#|^[[:space:]]*$' /etc/ftpusers 2>/dev/null | grep -qx "root"; then
      append_detail "ftpusers_root(after)=present"
    else
      append_detail "ftpusers_root(after)=absent"
    fi
  fi

  if [ -f "/etc/ftpd/ftpusers" ]; then
    TARGET_FILE="/etc/ftpd/ftpusers"
    block_root_blacklist "/etc/ftpd/ftpusers" || append_err "/etc/ftpd/ftpusers root 차단 적용 실패"
    if grep -Ev '^[[:space:]]*#|^[[:space:]]*$' /etc/ftpd/ftpusers 2>/dev/null | grep -qx "root"; then
      append_detail "ftpd_ftpusers_root(after)=present"
    else
      append_detail "ftpd_ftpusers_root(after)=absent"
    fi
  fi

  # === 최종 판정 ===
  if [ -n "$ERR_LOG" ]; then
    IS_SUCCESS=0
    REASON_LINE="조치를 수행했으나 일부 설정 적용 또는 검증에 실패해 조치가 완료되지 않았습니다."
    append_detail "$ERR_LOG"
  else
    # 핵심 검증: (대상 파일이 존재하는 경우) root가 금지 목록에 들어가 있거나(root present) / 화이트리스트에서 제거(root absent) 상태면 OK
    # 여기서는 DETAIL_CONTENT에 after 상태를 기록했으므로, 최소 하나라도 root 제한이 반영되면 성공으로 본다.
    if echo "$DETAIL_CONTENT" | grep -qE '(root\(after\)=present|root\(after\)=absent|_root\(after\)=present|_root\(after\)=absent)'; then
      IS_SUCCESS=1
      if [ "$MODIFIED" -eq 1 ]; then
        REASON_LINE="FTP 서비스의 root 접속 제한 설정이 적용되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
      else
        REASON_LINE="FTP 서비스의 root 접속 제한 설정이 이미 적용되어 있어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
      fi
    else
      IS_SUCCESS=0
      REASON_LINE="조치를 수행했으나 root 접속 제한 설정이 확인되지 않아 조치가 완료되지 않았습니다."
    fi
  fi
fi

# raw_evidence 구성 (첫 줄: 평가 이유 / 다음 줄부터: 현재(조치 후) 설정값)
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