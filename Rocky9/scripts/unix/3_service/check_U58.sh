#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-58
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : 불필요한 SNMP 서비스 구동 점검
# @Description : SNMP 서비스 활성화 여부 점검
# @Criteria_Good : SNMP 서비스를 사용하지 않는 경우
# @Criteria_Bad :  SNMP 서비스를 사용하는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-58 불필요한 SNMP 서비스 구동 점검

# 기본 변수
ID="U-58"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE="/usr/sbin/snmpd"
CHECK_COMMAND='systemctl is-enabled snmpd; systemctl is-active snmpd; systemctl list-units --type=service | grep -n snmpd; pgrep -a -x snmpd; command -v snmpd'

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

# 1) 서비스/프로세스 활성화 여부 확인 (Rocky 9/10: systemd 기준)
SNMP_ACTIVE="N"
SNMP_ENABLED="N"
SNMP_PROC="N"

# systemctl is-active
if systemctl is-active --quiet snmpd 2>/dev/null; then
  SNMP_ACTIVE="Y"
fi

# systemctl is-enabled
if systemctl is-enabled --quiet snmpd 2>/dev/null; then
  SNMP_ENABLED="Y"
fi

# 프로세스 확인(보조)
if pgrep -x snmpd >/dev/null 2>&1; then
  SNMP_PROC="Y"
fi

append_detail "[systemd] snmpd_active=$SNMP_ACTIVE snmpd_enabled=$SNMP_ENABLED"
append_detail "[process] snmpd_running=$SNMP_PROC"

# 2) 바이너리 경로(참고 증적)
if command -v snmpd >/dev/null 2>&1; then
  SNMP_BIN="$(command -v snmpd)"
  [ -n "$SNMP_BIN" ] && TARGET_FILE="$SNMP_BIN"
  append_detail "[binary] snmpd_path=$SNMP_BIN"
else
  append_detail "[binary] snmpd_command=NOT_FOUND"
fi

# 3) 최종 판정(업무상 필요 여부는 자동판단 불가 → 활성화면 취약으로 처리)
if [ "$SNMP_ACTIVE" = "Y" ] || [ "$SNMP_ENABLED" = "Y" ] || [ "$SNMP_PROC" = "Y" ]; then
  STATUS="FAIL"
  VULNERABLE=1
  REASON_LINE="SNMP 서비스(snmpd)가 활성화되어 있어 불필요한 경우 시스템 정보가 노출될 수 있으므로 취약합니다. 운영·모니터링 목적 등으로 실제 사용 여부를 확인한 뒤, 불필요하면 서비스를 중지 및 비활성화해야 합니다."
else
  STATUS="PASS"
  REASON_LINE="SNMP 서비스(snmpd)가 비활성화되어 있어 이 항목에 대한 보안 위협이 없습니다."
fi

DETAIL_CONTENT="$DETAIL_LINES"
[ -z "$DETAIL_CONTENT" ] && DETAIL_CONTENT="none"

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