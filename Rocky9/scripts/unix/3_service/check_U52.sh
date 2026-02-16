#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.1
# @Author: 이가영
# @Last Updated: 2026-02-15
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-52
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : Telnet 서비스 비활성화
# @Description : 원격 접속 시 Telnet 프로토콜 사용 여부 점검
# @Criteria_Good : 원격 접속 시 Telnet 프로토콜을 비활성화하고 있는 경우
# @Criteria_Bad : 원격 접속 시 Telnet 프로토콜을 사용하는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-52 Telnet 서비스 비활성화


# 기본 변수
ID="U-52"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""
CHECK_COMMAND='
( [ -f /etc/inetd.conf ] && grep -nEv "^[[:space:]]*#|^[[:space:]]*$" /etc/inetd.conf | grep -nE "^[[:space:]]*telnet([[:space:]]|$)" ) || echo "inetd_telnet_not_enabled_or_file_missing";
( [ -f /etc/xinetd.d/telnet ] && grep -nEv "^[[:space:]]*#|^[[:space:]]*$" /etc/xinetd.d/telnet | grep -niE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*(no|yes)\b" ) || echo "xinetd_telnet_disable_directive_not_found_or_file_missing";
systemctl is-enabled telnet.socket 2>/dev/null || echo "telnet.socket_not_enabled_or_not_found";
systemctl is-active telnet.socket 2>/dev/null || echo "telnet.socket_not_active_or_not_found";
systemctl is-enabled telnet.service 2>/dev/null || echo "telnet.service_not_enabled_or_not_found";
systemctl is-active telnet.service 2>/dev/null || echo "telnet.service_not_active_or_not_found";
systemctl is-active sshd 2>/dev/null || echo "sshd_not_active"
'

VULNERABLE=0
DETAIL_LINES=""

add_detail(){ [ -n "${1:-}" ] && DETAIL_LINES="${DETAIL_LINES}${DETAIL_LINES:+\n}$1"; }
add_target(){ [ -n "${1:-}" ] && TARGET_FILE="${TARGET_FILE}${TARGET_FILE:+, }$1"; }

# 1) inetd
INETD="/etc/inetd.conf"
if [ -f "$INETD" ]; then
  add_target "$INETD"
  if grep -nEv '^[[:space:]]*#|^[[:space:]]*$' "$INETD" 2>/dev/null | grep -qE '^[[:space:]]*telnet([[:space:]]|$)'; then
    VULNERABLE=1
    add_detail "[inetd] /etc/inetd.conf 에서 telnet 서비스 라인이 주석 처리되지 않아 활성화 상태입니다."
  else
    add_detail "[inetd] /etc/inetd.conf 에서 telnet 서비스 라인이 없거나 주석 처리되어 비활성화 상태입니다."
  fi
else
  add_detail "[inetd] /etc/inetd.conf 파일이 없어 inetd 기반 telnet 활성화 징후가 없습니다."
fi

# 2) xinetd
XINETD="/etc/xinetd.d/telnet"
if [ -f "$XINETD" ]; then
  add_target "$XINETD"
  # disable=no -> enabled, disable=yes -> disabled, 그 외/미기재 -> 취약(명확히 비활성화 아님)
  if grep -nEvi '^[[:space:]]*#|^[[:space:]]*$' "$XINETD" 2>/dev/null | grep -qiE '^[[:space:]]*disable[[:space:]]*=[[:space:]]*no\b'; then
    VULNERABLE=1
    add_detail "[xinetd] /etc/xinetd.d/telnet 에서 disable=no 로 설정되어 telnet 이 활성화 상태입니다."
  elif grep -nEvi '^[[:space:]]*#|^[[:space:]]*$' "$XINETD" 2>/dev/null | grep -qiE '^[[:space:]]*disable[[:space:]]*=[[:space:]]*yes\b'; then
    add_detail "[xinetd] /etc/xinetd.d/telnet 에서 disable=yes 로 설정되어 telnet 이 비활성화 상태입니다."
  else
    VULNERABLE=1
    add_detail "[xinetd] /etc/xinetd.d/telnet 에서 disable 설정이 명확하지 않아 telnet 이 활성화될 수 있어 취약합니다."
  fi
else
  add_detail "[xinetd] /etc/xinetd.d/telnet 파일이 없어 xinetd 기반 telnet 활성화 징후가 없습니다."
fi

# 3) systemd (active + enabled)
SYS_FIND=0
for u in telnet.socket telnet.service; do
  EN=$(systemctl is-enabled "$u" 2>/dev/null || true)
  AC=$(systemctl is-active  "$u" 2>/dev/null || true)

  if [ "$EN" = "enabled" ] || [ "$AC" = "active" ]; then
    VULNERABLE=1
    SYS_FIND=1
    add_detail "[systemd] $u 상태가 enabled/active 중 하나에 해당하여 telnet 이 활성화 상태입니다. (enabled=$EN, active=$AC)"
  fi
done
[ $SYS_FIND -eq 0 ] && add_detail "[systemd] telnet.socket/telnet.service 가 enabled 또는 active 상태가 아니어서 비활성화 상태입니다."

# 4) SSH (참고)
if systemctl is-active --quiet sshd 2>/dev/null; then
  add_detail "[ssh] sshd 가 실행 중입니다(원격 접속은 SSH 사용 권장)."
else
  add_detail "[ssh] sshd 가 실행 중이 아닙니다(원격 접속 정책에 따라 확인 필요)."
fi

# 5) 최종 판정 + 요구 문구
if [ $VULNERABLE -eq 1 ]; then
  STATUS="FAIL"
  REASON_LINE="Telnet이 어디서 어떻게 설정되어 있어 취약합니다. (inetd/xinetd/systemd 중 하나 이상에서 telnet 활성 징후 확인) 조치: /etc/inetd.conf의 telnet 라인을 주석/삭제, /etc/xinetd.d/telnet 은 disable=yes 로 설정 후 xinetd 재시작, systemd 는 telnet.socket(또는 service) stop 및 disable 하고, 원격 접속은 SSH로 전환하세요."
else
  STATUS="PASS"
  REASON_LINE="Telnet이 어디서 어떻게 설정되어 있어 이 항목에 대한 보안 위협이 없습니다. (inetd/xinetd/systemd에서 telnet 비활성화 상태 확인)"
fi

DETAIL_CONTENT="${DETAIL_LINES:-none}"
[ -z "$TARGET_FILE" ] && TARGET_FILE="/etc/inetd.conf, /etc/xinetd.d/telnet, systemd(telnet.socket/service)"

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
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF