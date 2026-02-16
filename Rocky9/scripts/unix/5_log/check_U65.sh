#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.2
# @Author: 권순형
# @Last Updated: 2026-02-16
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-65
# @Category    : 로그 관리
# @Platform    : Rocky Linux
# @Importance  : 중
# @Title       : NTP 및 시각 동기화 설정
# @Description : NTP 및 시각 동기화 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-65"
STATUS="FAIL"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/ntp.conf /etc/chrony.conf /etc/chrony/chrony.conf"
CHECK_COMMAND='
(systemctl is-active ntp 2>/dev/null || true);
(systemctl is-active ntpd 2>/dev/null || true);
(systemctl is-active chrony 2>/dev/null || true);
(systemctl is-active chronyd 2>/dev/null || true);
(command -v ntpq >/dev/null 2>&1 && ntpq -pn 2>/dev/null | head -n 30 || echo "ntpq_cmd_not_found");
(command -v chronyc >/dev/null 2>&1 && chronyc sources -v 2>/dev/null | head -n 40 || echo "chronyc_cmd_not_found");
( [ -f /etc/ntp.conf ] && grep -nE "^[[:space:]]*(server|pool)[[:space:]]+" /etc/ntp.conf 2>/dev/null | head -n 20 || echo "ntp_conf_no_server_pool_or_not_found");
for f in /etc/chrony.conf /etc/chrony/chrony.conf; do
  [ -f "$f" ] && (echo "### $f"; grep -nE "^[[:space:]]*(server|pool)[[:space:]]+" "$f" 2>/dev/null | head -n 20) || true;
done
'

REASON_LINE=""
DETAIL_CONTENT=""

json_escape() {
  echo "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g'
}

active_unit() { # first active unit name among args
  for u in "$@"; do
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active "$u" >/dev/null 2>&1; then
      echo "$u"
      return 0
    fi
  done
  echo ""
  return 1
}

conf_path() { # first existing file among args
  for f in "$@"; do
    [ -f "$f" ] && { echo "$f"; return 0; }
  done
  echo ""
  return 1
}

has_server_pool() {
  local f="$1"
  [ -n "$f" ] && grep -qE '^[[:space:]]*(server|pool)[[:space:]]+' "$f" 2>/dev/null
}

# ---- NTP 점검 ----
NTP_UNIT="$(active_unit ntp ntpd)"
NTP_CONF="$(conf_path /etc/ntp.conf)"
NTP_SYNC="no"
NTP_CONF_OK="no"
NTP_SUMMARY=""

if [ -n "$NTP_UNIT" ]; then
  NTP_SUMMARY+="ntp_service=active($NTP_UNIT)\n"
  if command -v ntpq >/dev/null 2>&1; then
    if ntpq -pn 2>/dev/null | grep -Eq '^[\*\+]'; then NTP_SYNC="yes"; fi
    NTP_SUMMARY+="ntp_sync=${NTP_SYNC}\n"
  else
    NTP_SUMMARY+="ntpq_cmd=missing\n"
  fi
else
  NTP_SUMMARY+="ntp_service=inactive\n"
fi

if [ -n "$NTP_CONF" ] && has_server_pool "$NTP_CONF"; then
  NTP_CONF_OK="yes"
  NTP_SUMMARY+="ntp_conf=${NTP_CONF} (server/pool=present)\n"
  NTP_SUMMARY+="ntp_conf_lines:\n$(grep -nE '^[[:space:]]*(server|pool)[[:space:]]+' "$NTP_CONF" 2>/dev/null | head -n 10)\n"
else
  NTP_SUMMARY+="ntp_conf=${NTP_CONF:-not_found} (server/pool=missing)\n"
fi

NTP_OK=0
[ -n "$NTP_UNIT" ] && [ "$NTP_CONF_OK" = "yes" ] && [ "$NTP_SYNC" = "yes" ] && NTP_OK=1

# ---- Chrony 점검 ----
CHRONY_UNIT="$(active_unit chrony chronyd)"
CHRONY_CONF="$(conf_path /etc/chrony.conf /etc/chrony/chrony.conf)"
CHRONY_SYNC="no"
CHRONY_CONF_OK="no"
CHRONY_SUMMARY=""

if [ -n "$CHRONY_UNIT" ]; then
  CHRONY_SUMMARY+="chrony_service=active($CHRONY_UNIT)\n"
  if command -v chronyc >/dev/null 2>&1; then
    if chronyc sources -v 2>/dev/null | grep -Eq '^\^\*'; then CHRONY_SYNC="yes"; fi
    CHRONY_SUMMARY+="chrony_sync=${CHRONY_SYNC}\n"
  else
    CHRONY_SUMMARY+="chronyc_cmd=missing\n"
  fi
else
  CHRONY_SUMMARY+="chrony_service=inactive\n"
fi

if [ -n "$CHRONY_CONF" ] && has_server_pool "$CHRONY_CONF"; then
  CHRONY_CONF_OK="yes"
  CHRONY_SUMMARY+="chrony_conf=${CHRONY_CONF} (server/pool=present)\n"
  CHRONY_SUMMARY+="chrony_conf_lines:\n$(grep -nE '^[[:space:]]*(server|pool)[[:space:]]+' "$CHRONY_CONF" 2>/dev/null | head -n 10)\n"
else
  CHRONY_SUMMARY+="chrony_conf=${CHRONY_CONF:-not_found} (server/pool=missing)\n"
fi

CHRONY_OK=0
[ -n "$CHRONY_UNIT" ] && [ "$CHRONY_CONF_OK" = "yes" ] && [ "$CHRONY_SYNC" = "yes" ] && CHRONY_OK=1

# ---- 최종 판단/문구(요청 반영) ----
if [ "$NTP_OK" -eq 1 ] || [ "$CHRONY_OK" -eq 1 ]; then
  STATUS="PASS"
  if [ "$CHRONY_OK" -eq 1 ]; then
    REASON_LINE="(Chrony) $CHRONY_UNIT 서비스가 활성화되어 있고($CHRONY_UNIT=active), $CHRONY_CONF 에 server/pool 설정이 존재하며(라인 확인), chronyc sources -v 에서 동기화 소스(^*)가 확인되어 이 항목에 대한 보안 위협이 없습니다."
  else
    REASON_LINE="(NTP) $NTP_UNIT 서비스가 활성화되어 있고($NTP_UNIT=active), $NTP_CONF 에 server/pool 설정이 존재하며(라인 확인), ntpq -pn 에서 동기화 대상(* 또는 +)이 확인되어 이 항목에 대한 보안 위협이 없습니다."
  fi
else
  STATUS="FAIL"
  REASON_LINE="NTP/Chrony가 비활성(inactive)이거나, 설정 파일($TARGET_FILE)에서 server/pool 설정 또는 동기화 상태(ntpq/chronyc)가 확인되지 않아 로그 시간 신뢰성이 떨어질 수 있어 취약합니다. 조치: (1) Chrony 또는 NTP 중 하나 설치/활성화, (2) /etc/chrony.conf 또는 /etc/chrony/chrony.conf(또는 /etc/ntp.conf)에 'server|pool <NTP서버>' 추가, (3) systemctl restart chronyd(또는 ntpd/ntp) 후 chronyc sources -v(또는 ntpq -pn)로 동기화 확인."
fi

DETAIL_CONTENT="NTP:\n${NTP_SUMMARY}\nChrony:\n${CHRONY_SUMMARY}"

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
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF