#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.0
# @Author: 이가영
# @Last Updated: 2026-02-15
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
( [ -f /etc/inetd.conf ] && grep -nEv "^[[:space:]]*#|^[[:space:]]*$" /etc/inetd.conf | grep -nE "^[[:space:]]*telnet([[:space:]]|$)" ) || echo "inetd_telnet_not_enabled_or_file_missing";
( [ -f /etc/xinetd.d/telnet ] && grep -nEvi "^[[:space:]]*#|^[[:space:]]*$" /etc/xinetd.d/telnet | grep -niE "^[[:space:]]*disable[[:space:]]*=" ) || echo "xinetd_disable_line_not_found_or_file_missing";
systemctl is-enabled telnet.socket 2>/dev/null || echo "telnet.socket_not_enabled_or_not_found";
systemctl is-active  telnet.socket 2>/dev/null || echo "telnet.socket_not_active_or_not_found";
systemctl is-enabled telnet.service 2>/dev/null || echo "telnet.service_not_enabled_or_not_found";
systemctl is-active  telnet.service 2>/dev/null || echo "telnet.service_not_active_or_not_found";
systemctl is-enabled telnetd.socket 2>/dev/null || echo "telnetd.socket_not_enabled_or_not_found";
systemctl is-active  telnetd.socket 2>/dev/null || echo "telnetd.socket_not_active_or_not_found";
systemctl is-enabled telnetd.service 2>/dev/null || echo "telnetd.service_not_enabled_or_not_found";
systemctl is-active  telnetd.service 2>/dev/null || echo "telnetd.service_not_active_or_not_found";
systemctl is-active sshd.service 2>/dev/null || systemctl is-active ssh.service 2>/dev/null || echo "ssh_not_active_or_not_found"
'

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""
ACTION_ERR_LOG=""
MODIFIED=0

add_detail(){ [ -n "${1:-}" ] && DETAIL_CONTENT="${DETAIL_CONTENT}${DETAIL_CONTENT:+\n}$1"; }
add_err(){ [ -n "${1:-}" ] && ACTION_ERR_LOG="${ACTION_ERR_LOG}${ACTION_ERR_LOG:+\n}$1"; }
add_target(){ [ -n "${1:-}" ] && TARGET_FILE="${TARGET_FILE}${TARGET_FILE:+, }$1"; }

unit_exists() {
  command -v systemctl >/dev/null 2>&1 || return 1
  systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$1"
}

restart_svc_if_exists() {
  unit_exists "$1" || return 0
  systemctl restart "$1" >/dev/null 2>&1 || return 1
  return 0
}

disable_mask_if_exists() {
  unit_exists "$1" || return 0
  systemctl stop "$1" >/dev/null 2>&1 || true
  systemctl disable "$1" >/dev/null 2>&1 || true
  systemctl mask "$1" >/dev/null 2>&1 || true
  return 0
}

# root 권한 확인
if [ "$(id -u)" -ne 0 ]; then
  REASON_LINE="root 권한이 아니어서 Telnet 서비스 비활성화를 적용할 수 없어 조치를 중단합니다."
  add_err "(주의) root 권한이 아니면 설정 파일 수정 및 서비스 중지/비활성화가 실패할 수 있습니다."
else
  # 1) inetd: /etc/inetd.conf 내 telnet 라인 주석 처리
  INETD="/etc/inetd.conf"
  add_target "$INETD"
  if [ -f "$INETD" ] && grep -nEv '^[[:space:]]*#|^[[:space:]]*$' "$INETD" 2>/dev/null | grep -qE '^[[:space:]]*telnet([[:space:]]|$)'; then
    cp -a "$INETD" "${INETD}.bak_$(date +%Y%m%d_%H%M%S)" 2>/dev/null || add_err "$INETD 백업 실패"
    sed -i 's/^[[:space:]]*telnet[[:space:]]/#&/g' "$INETD" 2>/dev/null || add_err "$INETD telnet 주석 처리 실패"
    MODIFIED=1
    add_detail "inetd_telnet(after)=commented_or_removed"
    restart_svc_if_exists "inetd.service" || add_err "inetd.service 재시작 실패"
  else
    add_detail "inetd_telnet(after)=not_enabled"
  fi

  # 2) xinetd: /etc/xinetd.d/telnet disable=yes 보장(없으면 삽입)
  XINETD="/etc/xinetd.d/telnet"
  add_target "$XINETD"
  if [ -f "$XINETD" ]; then
    cp -a "$XINETD" "${XINETD}.bak_$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true
    if grep -nEvi '^[[:space:]]*#|^[[:space:]]*$' "$XINETD" 2>/dev/null | grep -qiE '^[[:space:]]*disable[[:space:]]*=[[:space:]]*no\b'; then
      sed -Ei 's/^([[:space:]]*disable[[:space:]]*=[[:space:]]*)no\b/\1yes/I' "$XINETD" 2>/dev/null || add_err "$XINETD disable=yes 변경 실패"
      MODIFIED=1
    fi
    # disable 라인이 아예 없으면 취약 판정될 수 있으므로 삽입
    if ! grep -nEvi '^[[:space:]]*#|^[[:space:]]*$' "$XINETD" 2>/dev/null | grep -qiE '^[[:space:]]*disable[[:space:]]*='; then
      printf "\n  disable = yes\n" >> "$XINETD" 2>/dev/null || add_err "$XINETD disable=yes 삽입 실패"
      MODIFIED=1
    fi
    add_detail "xinetd_telnet_disable(after)=$(grep -nEvi '^[[:space:]]*#|^[[:space:]]*$' "$XINETD" 2>/dev/null | grep -iE '^[[:space:]]*disable[[:space:]]*=' | head -n 1 | tr '\n' ' ' )"
    restart_svc_if_exists "xinetd.service" || true
  else
    add_detail "xinetd_telnet(after)=not_found"
  fi

  # 3) systemd: telnet 관련 unit stop/disable/mask
  for u in telnet.socket telnet.service telnetd.socket telnetd.service; do
    disable_mask_if_exists "$u"
  done
  add_detail "systemd_telnet_units(after)=stopped_disabled_masked_if_exist"

  # 4) SSH 상태(강제 변경 없음)
  if command -v systemctl >/dev/null 2>&1; then
    SSH_ACTIVE="$(systemctl is-active sshd.service 2>/dev/null || systemctl is-active ssh.service 2>/dev/null || echo unknown)"
    add_detail "ssh_status(after)=$SSH_ACTIVE"
  else
    add_detail "ssh_status(after)=systemctl_not_found"
  fi

  # 5) 조치 후 검증(활성/활성화까지)
  TELNET_BAD=0

  # inetd: 주석 아닌 telnet 라인이 남아있으면 실패
  if [ -f "$INETD" ] && grep -nEv '^[[:space:]]*#|^[[:space:]]*$' "$INETD" 2>/dev/null | grep -qE '^[[:space:]]*telnet([[:space:]]|$)'; then
    TELNET_BAD=1
  fi

  # xinetd: disable=no 이거나 disable 라인이 없으면 실패(점검 기준 정합)
  if [ -f "$XINETD" ]; then
    if grep -nEvi '^[[:space:]]*#|^[[:space:]]*$' "$XINETD" 2>/dev/null | grep -qiE '^[[:space:]]*disable[[:space:]]*=[[:space:]]*no\b'; then
      TELNET_BAD=1
    fi
    if ! grep -nEvi '^[[:space:]]*#|^[[:space:]]*$' "$XINETD" 2>/dev/null | grep -qiE '^[[:space:]]*disable[[:space:]]*='; then
      TELNET_BAD=1
    fi
  fi

  # systemd: active 또는 enabled면 실패
  if command -v systemctl >/dev/null 2>&1; then
    for u in telnet.socket telnet.service telnetd.socket telnetd.service; do
      systemctl is-active --quiet "$u" 2>/dev/null && TELNET_BAD=1
      systemctl is-enabled "$u" 2>/dev/null | grep -qx "enabled" && TELNET_BAD=1
    done
  fi

  if [ "$TELNET_BAD" -eq 0 ]; then
    IS_SUCCESS=1
    if [ "$MODIFIED" -eq 1 ]; then
      REASON_LINE="Telnet 서비스가 비활성화되도록 설정이 적용되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
    else
      REASON_LINE="Telnet 서비스가 이미 비활성화된 상태로 확인되어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
    fi
  else
    IS_SUCCESS=0
    REASON_LINE="조치를 수행했으나 Telnet 서비스가 일부 경로에서 여전히 활성화(또는 활성화 설정) 상태로 확인되어 조치가 완료되지 않았습니다."
  fi
fi

# after 정보만 raw_evidence에 포함(에러 로그는 조치 결과 근거이므로 포함)
[ -n "$ACTION_ERR_LOG" ] && add_detail "$ACTION_ERR_LOG"
[ -z "$DETAIL_CONTENT" ] && DETAIL_CONTENT="none"
[ -z "$TARGET_FILE" ] && TARGET_FILE="/etc/inetd.conf, /etc/xinetd.d/telnet, systemd(telnet*.socket/service)"

RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

# escape (backslash/quote/newline)
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/\\/\\\\/g; s/"/\\"/g' \
  | sed ':a;N;$!ba;s/\n/\\n/g')

echo ""
cat <<EOF
{
    "item_code": "$ID",
    "action_date": "$ACTION_DATE",
    "is_success": $IS_SUCCESS,
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
}
EOF