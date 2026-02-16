#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.0
# @Author: 이가영
# @Last Updated: 2026-02-15
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-59
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상 
# @Title : 안전한 SNMP 버전 사용
# @Description : 안전한 SNMP 버전 사용 여부 점검
# @Criteria_Good : SNMP 서비스를 v3 이상으로 사용하는 경우
# @Criteria_Bad : SNMP 서비스를 v2 이하로 사용하는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-59 안전한 SNMP 버전 사용

# 기본 변수
ID="U-59"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

CHECK_COMMAND='systemctl is-active snmpd; systemctl is-enabled snmpd; pgrep -a -x snmpd; grep -nEv "^[[:space:]]*#|^[[:space:]]*$" /etc/snmp/snmpd.conf /usr/share/snmp/snmpd.conf 2>/dev/null | grep -nE "^(rouser|rwuser|createUser|com2sec|rocommunity|rwcommunity)\b"'

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""

# helpers
append_line() { DETAIL_CONTENT="${DETAIL_CONTENT:+$DETAIL_CONTENT\n}$1"; }
add_file() { TARGET_FILE="${TARGET_FILE:+$TARGET_FILE, }$1"; }
count_lines() { echo "$1" | sed '/^$/d' | wc -l | tr -d ' '; }

# 1) SNMP 실행 여부
ACTIVE="$(systemctl is-active snmpd 2>/dev/null || echo unknown)"
ENABLED="$(systemctl is-enabled snmpd 2>/dev/null || echo unknown)"
PROC_LINE="$(pgrep -a -x snmpd 2>/dev/null | head -n 1 || true)"

SNMP_RUNNING=0
if [ "$ACTIVE" = "active" ] || [ -n "$PROC_LINE" ]; then SNMP_RUNNING=1; fi

append_line "[systemd] snmpd_active=$ACTIVE snmpd_enabled=$ENABLED"
append_line "[process] ${PROC_LINE:-snmpd_not_running}"

# 2) 미실행이면 PASS(점검대상 없음)
if [ "$SNMP_RUNNING" -eq 0 ]; then
  STATUS="PASS"
  REASON_LINE="systemd/프로세스 기준으로 SNMP(snmpd)가 비활성화되어 있어 이 항목에 대한 보안 위협이 없습니다."
  TARGET_FILE="/etc/snmp/snmpd.conf, /usr/share/snmp/snmpd.conf"

else
  # 3) 설정 파일에서 v3 / v1v2c 흔적 확인
  CONFS=("/etc/snmp/snmpd.conf" "/usr/share/snmp/snmpd.conf")
  FOUND_CONF=0
  V3_FOUND=0
  V12C_FOUND=0

  for f in "${CONFS[@]}"; do
    if [ -f "$f" ]; then
      FOUND_CONF=1
      add_file "$f"

      EFFECTIVE="$(grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$f" 2>/dev/null || true)"
      V3_LINES="$(echo "$EFFECTIVE" | grep -E '^(rouser|rwuser|createUser)\b' || true)"
      V12C_LINES="$(echo "$EFFECTIVE" | grep -E '^(com2sec|rocommunity|rwcommunity)\b' || true)"

      if [ -n "$V3_LINES" ]; then
        V3_FOUND=1
        append_line "[conf] $f snmpv3_config=FOUND (lines=$(count_lines "$V3_LINES"))"
      else
        append_line "[conf] $f snmpv3_config=NOT_FOUND"
      fi

      if [ -n "$V12C_LINES" ]; then
        V12C_FOUND=1
        append_line "[conf] $f snmpv1/v2c_config=FOUND (lines=$(count_lines "$V12C_LINES"))"
      else
        append_line "[conf] $f snmpv1/v2c_config=NOT_FOUND"
      fi
    else
      append_line "[conf] $f=NOT_FOUND"
    fi
  done

  # 4) 판정
  if [ "$FOUND_CONF" -eq 0 ]; then
    STATUS="FAIL"
    REASON_LINE="SNMP 서비스(snmpd)가 실행 중이나 snmpd.conf 위치를 확인할 수 없어 안전한 SNMPv3 사용 여부를 검증할 수 없어 취약합니다. 조치: snmpd.conf 경로를 확인한 뒤 SNMPv1/v2c(com2sec/rocommunity/rwcommunity)를 비활성화하고 SNMPv3(createUser/rouser/rwuser)로만 구성하거나, SNMP를 사용하지 않으면 서비스를 중지/비활성화하세요."
    TARGET_FILE="/etc/snmp/snmpd.conf, /usr/share/snmp/snmpd.conf"
  else
    if [ "$V3_FOUND" -eq 1 ] && [ "$V12C_FOUND" -eq 0 ]; then
      STATUS="PASS"
      REASON_LINE="snmpd.conf에서 createUser/rouser/rwuser 기반으로 SNMPv3만 사용하도록 설정되어 있어 이 항목에 대한 보안 위협이 없습니다."
    else
      STATUS="FAIL"
      if [ "$V12C_FOUND" -eq 1 ]; then
        REASON_LINE="snmpd.conf에서 com2sec/rocommunity/rwcommunity(SNMPv1/v2c) 설정이 확인되어 취약합니다. 조치: 해당 v1/v2c 설정을 제거/주석 처리하고 SNMPv3(createUser 생성 후 rouser/rwuser로 권한 부여)만 사용하도록 재구성하세요."
      else
        REASON_LINE="SNMP 서비스(snmpd)가 실행 중인데 snmpd.conf에서 SNMPv3(createUser/rouser/rwuser) 설정이 확인되지 않아 취약합니다. 조치: SNMPv1/v2c 사용을 중단하고 SNMPv3 사용자(createUser)와 권한(rouser/rwuser)을 구성하거나, SNMP를 사용하지 않으면 서비스를 중지/비활성화하세요."
      fi
    fi
  fi
fi

[ -z "$DETAIL_CONTENT" ] && DETAIL_CONTENT="none"
[ -z "$TARGET_FILE" ] && TARGET_FILE="N/A"

# raw_evidence (첫 줄: 평가 이유 / 다음 줄: 상세)
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

# JSON escape (따옴표/줄바꿈)
RAW_EVIDENCE_ESCAPED="$(echo "$RAW_EVIDENCE" | sed 's/\\/\\\\/g; s/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g')"

echo ""
cat <<EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF