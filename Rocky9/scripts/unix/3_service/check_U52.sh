#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
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
CHECK_COMMAND='grep -nE "^[[:space:]]*telnet" /etc/inetd.conf; grep -niE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no" /etc/xinetd.d/telnet; systemctl list-units --type=socket | grep -i telnet; systemctl list-units --type=service | grep -i telnet; systemctl is-active sshd'

VULNERABLE=0
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

# -----------------------------
# 1) inetd.conf 내 telnet 활성화 여부
# -----------------------------
INETD_FILE="/etc/inetd.conf"
if [ -f "$INETD_FILE" ]; then
  add_target_file "$INETD_FILE"
  if grep -v '^[[:space:]]*#' "$INETD_FILE" 2>/dev/null | grep -qE '^[[:space:]]*telnet\b'; then
    VULNERABLE=1
    append_detail "[inetd] telnet entry=ENABLED in $INETD_FILE"
  else
    append_detail "[inetd] telnet entry=NOT_FOUND(or commented) in $INETD_FILE"
  fi
else
  append_detail "[inetd] $INETD_FILE=NOT_FOUND"
fi

# -----------------------------
# 2) xinetd 설정(/etc/xinetd.d/telnet) 내 disable=no 여부
# -----------------------------
XINETD_TELNET="/etc/xinetd.d/telnet"
if [ -f "$XINETD_TELNET" ]; then
  add_target_file "$XINETD_TELNET"
  if grep -vi '^[[:space:]]*#' "$XINETD_TELNET" 2>/dev/null | grep -qiE '^[[:space:]]*disable[[:space:]]*=[[:space:]]*no\b'; then
    VULNERABLE=1
    append_detail "[xinetd] disable=no -> telnet ENABLED in $XINETD_TELNET"
  else
    append_detail "[xinetd] disable=no NOT_FOUND -> telnet likely disabled in $XINETD_TELNET"
  fi
else
  append_detail "[xinetd] $XINETD_TELNET=NOT_FOUND"
fi

# -----------------------------
# 3) systemd telnet socket/service 활성화 여부
# -----------------------------
TELNET_SOCKET_LIST="$(systemctl list-units --type=socket 2>/dev/null | grep -i telnet || true)"
TELNET_SERVICE_LIST="$(systemctl list-units --type=service 2>/dev/null | grep -i telnet || true)"

if [ -n "$TELNET_SOCKET_LIST" ]; then
  VULNERABLE=1
  append_detail "[systemd] telnet socket=FOUND | $(echo "$TELNET_SOCKET_LIST" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g')"
else
  append_detail "[systemd] telnet socket=NOT_FOUND"
fi

if [ -n "$TELNET_SERVICE_LIST" ]; then
  VULNERABLE=1
  append_detail "[systemd] telnet service=FOUND | $(echo "$TELNET_SERVICE_LIST" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g')"
else
  append_detail "[systemd] telnet service=NOT_FOUND"
fi

# -----------------------------
# 4) SSH 서비스 실행 여부(보조 정보: PASS/FAIL 판정에는 영향 주지 않음)
# -----------------------------
SSHD_ACTIVE="N"
systemctl is-active --quiet sshd 2>/dev/null && SSHD_ACTIVE="Y"
if [ "$SSHD_ACTIVE" = "Y" ]; then
  append_detail "[ssh] sshd_active=Y"
else
  append_detail "[ssh] sshd_active=N (verify remote access policy)"
fi

# -----------------------------
# 5) 최종 판정/문구(U-15~U-16 톤)
# -----------------------------
if [ $VULNERABLE -eq 1 ]; then
  STATUS="FAIL"
  REASON_LINE="Telnet 서비스가 활성화되어 있어 취약합니다. Telnet은 통신 내용이 평문으로 전송되어 계정 정보 및 접속 정보가 노출될 수 있으므로 서비스를 중지 및 비활성화하고, 원격 접속은 SSH로 전환해야 합니다."
else
  STATUS="PASS"
  REASON_LINE="Telnet 서비스가 비활성화되어 있어 이 항목에 대한 보안 위협이 없습니다."
fi

DETAIL_CONTENT="$DETAIL_LINES"
[ -z "$DETAIL_CONTENT" ] && DETAIL_CONTENT="none"

# target_file 기본값 보정
[ -z "$TARGET_FILE" ] && TARGET_FILE="/etc/inetd.conf, /etc/xinetd.d/telnet, systemd units"

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