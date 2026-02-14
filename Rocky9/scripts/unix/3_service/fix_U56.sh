#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.2.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-56
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 하
# @Title : FTP 서비스 접근 제어 설정
# @Description : FTP 서비스 접근 제어 설정 보완
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-56"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND='(command -v systemctl >/dev/null 2>&1 && systemctl list-units --type=service 2>/dev/null | egrep -i "vsftpd|proftpd|xinetd|inetd" || true); (command -v getent >/dev/null 2>&1 && getent services ftp 2>/dev/null || true); (ls -l /etc/hosts.allow /etc/hosts.deny 2>/dev/null || true); (grep -nEv "^[[:space:]]*#|^[[:space:]]*$" /etc/hosts.allow 2>/dev/null || true); (grep -nEv "^[[:space:]]*#|^[[:space:]]*$" /etc/hosts.deny 2>/dev/null || true)'
REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE="N/A"

ACTION_ERR_LOG=""
MODIFIED=0
NEEDS_MANUAL=0
FTP_IN_USE=0
LOCAL_ONLY_TEMPLATE=0

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

has_non_comment_match() {
  local file="$1"
  local pattern="$2"
  grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$file" 2>/dev/null | grep -qE "$pattern"
}

ensure_owner_perm() {
  local file="$1"
  local owner="$2"
  local perm="$3"
  [ -f "$file" ] || return 0
  chown "$owner" "$file" 2>/dev/null || return 1
  chmod "$perm" "$file" 2>/dev/null || return 1
  return 0
}

ensure_hosts_control() {
  # tcp_wrappers 기반 접근제어 템플릿 구성
  # - hosts.allow에 데몬 라벨: 127.0.0.1 예시를 넣고(운영 반영은 수동)
  # - hosts.deny에 ALL:ALL 기본 차단
  local daemon_regex="$1"
  local daemon_label="$2"

  [ -f "/etc/hosts.allow" ] || touch "/etc/hosts.allow" 2>/dev/null || return 1
  [ -f "/etc/hosts.deny" ] || touch "/etc/hosts.deny" 2>/dev/null || return 1

  ensure_owner_perm "/etc/hosts.allow" root 644 || return 1
  ensure_owner_perm "/etc/hosts.deny" root 644 || return 1

  if ! has_non_comment_match "/etc/hosts.allow" "^(${daemon_regex})[[:space:]]*:"; then
    echo "${daemon_label}: 127.0.0.1" >> /etc/hosts.allow 2>/dev/null || return 1
    NEEDS_MANUAL=1
    LOCAL_ONLY_TEMPLATE=1
    append_detail "hosts.allow(after)=${daemon_label}: 127.0.0.1"
  else
    # 기존 설정이 있으면 현재 라인만 일부 기록
    cur_allow="$(grep -nEv '^[[:space:]]*#|^[[:space:]]*$' /etc/hosts.allow 2>/dev/null | grep -E "^(${daemon_regex})[[:space:]]*:" | tail -n 1)"
    [ -n "$cur_allow" ] && append_detail "hosts.allow(after)=$cur_allow"
  fi

  if ! has_non_comment_match "/etc/hosts.deny" '^ALL[[:space:]]*:[[:space:]]*ALL'; then
    echo "ALL: ALL" >> /etc/hosts.deny 2>/dev/null || return 1
    append_detail "hosts.deny(after)=ALL: ALL"
  else
    append_detail "hosts.deny(after)=ALL: ALL (exists)"
  fi

  return 0
}

# (필수) root 권한 권장 안내(실패 원인 명확화용)
if [ "$(id -u)" -ne 0 ]; then
  ACTION_ERR_LOG="(주의) root 권한이 아니면 설정 파일 수정/권한 변경이 실패할 수 있습니다."
fi

########################################
# 조치 프로세스
########################################
if [ "$(id -u)" -ne 0 ]; then
  IS_SUCCESS=0
  REASON_LINE="root 권한이 아니어서 FTP 접근 제어 설정을 적용할 수 없어 조치를 중단합니다."
  DETAIL_CONTENT="$ACTION_ERR_LOG"
else
  # vsftpd 설정 파일 탐색
  VSFTPD_CONF=""
  if [ -f "/etc/vsftpd.conf" ]; then
    VSFTPD_CONF="/etc/vsftpd.conf"
  elif [ -f "/etc/vsftpd/vsftpd.conf" ]; then
    VSFTPD_CONF="/etc/vsftpd/vsftpd.conf"
  fi

  # proftpd 설정 파일 탐색
  PROFTPD_CONF=""
  if [ -f "/etc/proftpd/proftpd.conf" ]; then
    PROFTPD_CONF="/etc/proftpd/proftpd.conf"
  elif [ -f "/etc/proftpd.conf" ]; then
    PROFTPD_CONF="/etc/proftpd.conf"
  fi

  # 서비스 사용 여부 판정(대략)
  if command -v systemctl >/dev/null 2>&1; then
    systemctl list-units --type=service 2>/dev/null | grep -qiE '\b(vsftpd|proftpd)(\.service)?\b' && FTP_IN_USE=1
    systemctl list-units --type=service 2>/dev/null | grep -qiE '\b(xinetd|inetd)(\.service)?\b' && true
  fi
  [ -n "$VSFTPD_CONF" ] && FTP_IN_USE=1
  [ -n "$PROFTPD_CONF" ] && FTP_IN_USE=1

  # inetd/xinetd 기반 FTP 단서
  if [ -f "/etc/inetd.conf" ] && has_non_comment_match "/etc/inetd.conf" '^[[:space:]]*ftp([[:space:]]|$)'; then
    FTP_IN_USE=1
  fi
  if [ -f "/etc/xinetd.d/ftp" ] && has_non_comment_match "/etc/xinetd.d/ftp" '^[[:space:]]*disable[[:space:]]*=[[:space:]]*no'; then
    FTP_IN_USE=1
  fi

  if [ "$FTP_IN_USE" -eq 0 ]; then
    IS_SUCCESS=1
    REASON_LINE="FTP 서비스가 비활성화되어 조치 대상이 없어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
    append_detail "ftp_in_use(after)=0"
  else
    append_detail "ftp_in_use(after)=1"

    ####################################
    # 1) vsftpd: tcp_wrappers=YES 적용 + hosts.allow/deny 템플릿
    ####################################
    if [ -n "$VSFTPD_CONF" ]; then
      TARGET_FILE="$VSFTPD_CONF"
      # tcp_wrappers=YES 강제
      if grep -Eq '^[[:space:]]*tcp_wrappers[[:space:]]*=' "$VSFTPD_CONF" 2>/dev/null; then
        sed -Ei 's/^[[:space:]]*tcp_wrappers[[:space:]]*=.*/tcp_wrappers=YES/' "$VSFTPD_CONF" 2>/dev/null || append_err "vsftpd tcp_wrappers 설정 변경 실패"
      else
        echo "tcp_wrappers=YES" >> "$VSFTPD_CONF" 2>/dev/null || append_err "vsftpd tcp_wrappers 설정 추가 실패"
      fi

      # 적용 상태(After) 기록
      cur_tw="$(grep -Ei '^[[:space:]]*tcp_wrappers[[:space:]]*=' "$VSFTPD_CONF" 2>/dev/null | tail -n 1 | sed 's/[[:space:]]//g')"
      [ -z "$cur_tw" ] && cur_tw="tcp_wrappers(after)=unknown"
      append_detail "vsftpd_conf(after)=$VSFTPD_CONF"
      append_detail "vsftpd_tcp_wrappers(after)=${cur_tw}"

      # hosts.allow/deny 템플릿
      if ensure_hosts_control "vsftpd|in\\.ftpd|ftpd" "vsftpd"; then
        MODIFIED=1
      else
        append_err "hosts.allow/hosts.deny 접근 제어 템플릿 구성 실패"
      fi

      # 재시작(실패해도 치명오류로만 기록)
      if command -v systemctl >/dev/null 2>&1; then
        systemctl restart vsftpd >/dev/null 2>&1 || append_err "vsftpd 재시작 실패"
      fi
    fi

    ####################################
    # 2) proftpd: 환경 의존(권장: <Limit LOGIN>) → 템플릿 제시 + 수동 검토
    ####################################
    if [ -n "$PROFTPD_CONF" ]; then
      TARGET_FILE="$PROFTPD_CONF"
      # 파일 권한 최소화(일반적인 권장)
      ensure_owner_perm "$PROFTPD_CONF" root 640 || append_err "proftpd.conf 권한/소유자 설정 실패"

      # <Limit LOGIN> 블록이 없거나 제어가 없으면 템플릿 추가(로컬만 허용 예시)
      LIMIT_BLOCK="$(sed -n '/<Limit LOGIN>/,/<\/Limit>/p' "$PROFTPD_CONF" 2>/dev/null)"
      if [ -z "$LIMIT_BLOCK" ] || ! echo "$LIMIT_BLOCK" | grep -qiE 'Allow[[:space:]]+from|Deny[[:space:]]+from|AllowUser|DenyUser'; then
        cat >> "$PROFTPD_CONF" <<'LIMIT_EOF'

<Limit LOGIN>
    Order Deny,Allow
    Allow from 127.0.0.1
    Deny from all
</Limit>
LIMIT_EOF
        NEEDS_MANUAL=1
        LOCAL_ONLY_TEMPLATE=1
        MODIFIED=1
      else
        # 현재 설정 일부 기록
        one_line="$(echo "$LIMIT_BLOCK" | grep -iE 'Allow[[:space:]]+from|Deny[[:space:]]+from|AllowUser|DenyUser' | head -n 1)"
        [ -n "$one_line" ] && append_detail "proftpd_limit_login(after)=$one_line"
      fi

      append_detail "proftpd_conf(after)=$PROFTPD_CONF"

      if command -v systemctl >/dev/null 2>&1; then
        systemctl restart proftpd >/dev/null 2>&1 || append_err "proftpd 재시작 실패"
      fi
    fi

    ####################################
    # 3) inetd/xinetd 기반 FTP: 접근제어는 hosts.allow/deny로 유도 → 수동 검토
    ####################################
    if [ -f "/etc/inetd.conf" ] && has_non_comment_match "/etc/inetd.conf" '^[[:space:]]*ftp([[:space:]]|$)'; then
      TARGET_FILE="/etc/inetd.conf"
      NEEDS_MANUAL=1
      ensure_hosts_control "in\\.ftpd|ftpd|vsftpd" "in.ftpd" || append_err "inetd 환경 hosts.allow/deny 적용 실패"
      append_detail "inetd_ftp(after)=enabled_in_inetd_conf"
    fi

    if [ -f "/etc/xinetd.d/ftp" ] && has_non_comment_match "/etc/xinetd.d/ftp" '^[[:space:]]*disable[[:space:]]*=[[:space:]]*no'; then
      TARGET_FILE="/etc/xinetd.d/ftp"
      NEEDS_MANUAL=1
      ensure_hosts_control "in\\.ftpd|ftpd|vsftpd" "in.ftpd" || append_err "xinetd 환경 hosts.allow/deny 적용 실패"
      append_detail "xinetd_ftp(after)=disable=no"
    fi

    ####################################
    # 최종 판정
    ####################################
    if [ -n "$ACTION_ERR_LOG" ]; then
      # 치명적 실패로 단정하지 않고, 설정 적용/검증이 불명확한 경우도 포함 → 실패 처리
      IS_SUCCESS=0
      REASON_LINE="조치를 수행했으나 일부 설정 적용 또는 검증에 실패해 조치가 완료되지 않았습니다."
    else
      if [ "$NEEDS_MANUAL" -eq 1 ]; then
        IS_SUCCESS=0
        REASON_LINE="FTP 접근 제어 설정에 로컬 예시 또는 환경 의존 설정이 포함되어 운영 반영을 위한 수동 검토가 필요하므로 조치가 완료되지 않았습니다."
      else
        IS_SUCCESS=1
        if [ "$MODIFIED" -eq 1 ]; then
          REASON_LINE="FTP 서비스 접근 제어 설정이 적용되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
        else
          REASON_LINE="FTP 서비스 접근 제어 설정이 이미 적절하여 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
        fi
      fi
    fi

    if [ "$LOCAL_ONLY_TEMPLATE" -eq 1 ]; then
      append_detail "note(after)=로컬(127.0.0.1) 예시가 포함되어 운영 허용 IP/호스트로 수동 조정이 필요합니다."
    fi
  fi
fi

# detail에 에러 로그를 마지막에 포함(현재/조치 후 정보만 유지)
if [ -n "$ACTION_ERR_LOG" ]; then
  append_detail "$ACTION_ERR_LOG"
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