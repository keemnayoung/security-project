#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-52
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : Telnet 서비스 비활성화
# @Description : 원격 접속 시 Telnet 프로토콜 사용 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-52 Telnet 서비스 비활성화

# 기본 변수
ID="U-52"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND='
( [ -f /etc/inetd.conf ] && grep -nEv "^[[:space:]]*#" /etc/inetd.conf | grep -nE "^[[:space:]]*telnet([[:space:]]|$)" || echo "inetd_telnet_not_found_or_commented" );
( [ -f /etc/xinetd.d/telnet ] && grep -nEv "^[[:space:]]*#" /etc/xinetd.d/telnet | grep -niE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*(no|yes)" || echo "xinetd_telnet_not_found" );
( command -v systemctl >/dev/null 2>&1 && (
    systemctl list-unit-files 2>/dev/null | grep -iE "^(telnet|telnetd|telnet.socket|telnet.service|telnetd.socket|telnetd.service)[[:space:]]" || echo "systemd_telnet_unit_not_found";
    systemctl is-active telnet.socket 2>/dev/null || true;
    systemctl is-active telnet.service 2>/dev/null || true;
    systemctl is-active telnetd.socket 2>/dev/null || true;
    systemctl is-active telnetd.service 2>/dev/null || true;
    systemctl is-active sshd.service 2>/dev/null || systemctl is-active ssh.service 2>/dev/null || true
  ) ) || echo "systemctl_not_found"
'

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE="N/A"

ACTION_ERR_LOG=""
MODIFIED=0

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
  ACTION_ERR_LOG="(주의) root 권한이 아니면 설정 파일 수정 및 서비스 중지/비활성화가 실패할 수 있습니다."
fi

restart_if_exists() {
  local svc="$1"
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl list-unit-files 2>/dev/null | grep -qiE "^${svc}\.service[[:space:]]" || return 0
  systemctl restart "${svc}.service" >/dev/null 2>&1 || return 1
  return 0
}

disable_unit_if_exists() {
  local unit="$1"
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl list-unit-files 2>/dev/null | grep -qiE "^${unit}[[:space:]]" || return 0
  systemctl stop "$unit" >/dev/null 2>&1 || true
  systemctl disable "$unit" >/dev/null 2>&1 || true
  systemctl mask "$unit" >/dev/null 2>&1 || true
  return 0
}

########################################
# 조치 프로세스
########################################
if [ "$(id -u)" -ne 0 ]; then
  IS_SUCCESS=0
  REASON_LINE="root 권한이 아니어서 Telnet 서비스 비활성화를 적용할 수 없어 조치를 중단합니다."
else
  # 1) [inetd] /etc/inetd.conf에서 telnet 활성 라인 주석 처리
  if [ -f "/etc/inetd.conf" ]; then
    if grep -Ev "^[[:space:]]*#" /etc/inetd.conf 2>/dev/null | grep -qE "^[[:space:]]*telnet([[:space:]]|$)"; then
      cp -a /etc/inetd.conf "/etc/inetd.conf.bak_$(date +%Y%m%d_%H%M%S)" 2>/dev/null || append_err "/etc/inetd.conf 백업 실패"
      sed -i 's/^\([[:space:]]*telnet\)/#\1/g' /etc/inetd.conf 2>/dev/null || append_err "/etc/inetd.conf telnet 주석 처리 실패"
      MODIFIED=1
      append_detail "inetd_telnet(after)=commented"
      # inetd 재시작(존재 시)
      if ! restart_if_exists inetd; then
        append_err "inetd 재시작 실패"
      fi
    else
      append_detail "inetd_telnet(after)=not_active"
    fi
  else
    append_detail "inetd_conf(after)=not_found"
  fi

  # 2) [xinetd] /etc/xinetd.d/telnet disable=yes로 설정
  if [ -f "/etc/xinetd.d/telnet" ]; then
    TARGET_FILE="/etc/xinetd.d/telnet"
    if grep -Ev "^[[:space:]]*#" /etc/xinetd.d/telnet 2>/dev/null | grep -qiE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no([[:space:]]|$)"; then
      cp -a /etc/xinetd.d/telnet "/etc/xinetd.d/telnet.bak_$(date +%Y%m%d_%H%M%S)" 2>/dev/null || append_err "/etc/xinetd.d/telnet 백업 실패"
      sed -Ei 's/^([[:space:]]*disable[[:space:]]*=[[:space:]]*)[Nn][Oo]([[:space:]]*(#.*)?)?$/\1yes\2/' /etc/xinetd.d/telnet 2>/dev/null \
        || append_err "/etc/xinetd.d/telnet disable=yes 변경 실패"
      MODIFIED=1
      append_detail "xinetd_telnet_disable(after)=yes"
      if ! restart_if_exists xinetd; then
        append_err "xinetd 재시작 실패"
      fi
    else
      # disable=no가 아니면 이미 제한된 것으로 간주(없거나 yes)
      AFTER_DISABLE="$(grep -nEv '^[[:space:]]*#' /etc/xinetd.d/telnet 2>/dev/null | grep -niE '^[[:space:]]*disable[[:space:]]*=' | head -n 1)"
      [ -z "$AFTER_DISABLE" ] && AFTER_DISABLE="disable_line_not_found"
      append_detail "xinetd_telnet_disable(after)=$AFTER_DISABLE"
    fi
  else
    append_detail "xinetd_telnet(after)=not_found"
  fi

  # 3) [systemd] telnet 관련 unit stop/disable/mask (서비스/소켓)
  disable_unit_if_exists "telnet.socket"
  disable_unit_if_exists "telnet.service"
  disable_unit_if_exists "telnetd.socket"
  disable_unit_if_exists "telnetd.service"
  append_detail "systemd_telnet_units(after)=disabled_if_exist"

  # 4) (안전) SSH는 강제 활성화하지 않고 상태만 근거로 기록
  if command -v systemctl >/dev/null 2>&1; then
    SSH_ACTIVE="$(systemctl is-active sshd.service 2>/dev/null || systemctl is-active ssh.service 2>/dev/null || echo unknown)"
    append_detail "ssh_status(after)=$SSH_ACTIVE"
  else
    append_detail "ssh_status(after)=systemctl_not_found"
  fi

  ########################################
  # 검증(조치 후 상태만)
  ########################################
  TELNET_ACTIVE=0

  # inetd 활성 라인 존재 여부
  if [ -f "/etc/inetd.conf" ]; then
    if grep -Ev "^[[:space:]]*#" /etc/inetd.conf 2>/dev/null | grep -qE "^[[:space:]]*telnet([[:space:]]|$)"; then
      TELNET_ACTIVE=1
    fi
  fi

  # xinetd disable=no 여부
  if [ -f "/etc/xinetd.d/telnet" ]; then
    if grep -Ev "^[[:space:]]*#" /etc/xinetd.d/telnet 2>/dev/null | grep -qiE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no([[:space:]]|$)"; then
      TELNET_ACTIVE=1
    fi
  fi

  # systemd 활성 여부(서비스/소켓)
  if command -v systemctl >/dev/null 2>&1; then
    systemctl is-active telnet.socket >/dev/null 2>&1 && TELNET_ACTIVE=1
    systemctl is-active telnet.service >/dev/null 2>&1 && TELNET_ACTIVE=1
    systemctl is-active telnetd.socket >/dev/null 2>&1 && TELNET_ACTIVE=1
    systemctl is-active telnetd.service >/dev/null 2>&1 && TELNET_ACTIVE=1
  fi

  if [ "$TELNET_ACTIVE" -eq 0 ]; then
    IS_SUCCESS=1
    if [ "$MODIFIED" -eq 1 ]; then
      REASON_LINE="Telnet 서비스가 비활성화되도록 설정이 적용되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
    else
      REASON_LINE="Telnet 서비스가 이미 비활성화된 상태로 확인되어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
    fi
  else
    IS_SUCCESS=0
    REASON_LINE="조치를 수행했으나 Telnet 서비스가 일부 경로에서 여전히 활성화 상태로 확인되어 조치가 완료되지 않았습니다."
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
