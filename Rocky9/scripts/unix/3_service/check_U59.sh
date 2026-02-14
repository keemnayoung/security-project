#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-14
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

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""
CHECK_COMMAND='systemctl is-active snmpd; systemctl is-enabled snmpd; pgrep -a -x snmpd; grep -nE "^(rouser|rwuser|createUser|com2sec|rocommunity|rwcommunity)" /etc/snmp/snmpd.conf /usr/share/snmp/snmpd.conf 2>/dev/null'

VULNERABLE=0
SNMP_RUNNING=0
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

# 1) SNMP 서비스 실행 여부 확인
ACTIVE="N"
ENABLED="N"
PROC="N"

if systemctl is-active --quiet snmpd 2>/dev/null; then
  ACTIVE="Y"
  SNMP_RUNNING=1
fi

if systemctl is-enabled --quiet snmpd 2>/dev/null; then
  ENABLED="Y"
fi

if pgrep -x snmpd >/dev/null 2>&1; then
  PROC="Y"
  SNMP_RUNNING=1
fi

append_detail "[systemd] snmpd_active=$ACTIVE snmpd_enabled=$ENABLED"
append_detail "[process] snmpd_running=$PROC"

# 2) 실행 중이 아니면 PASS(점검 대상 없음)
if [ "$SNMP_RUNNING" -eq 0 ]; then
  STATUS="PASS"
  REASON_LINE="SNMP 서비스가 비활성화되어 있어 점검 대상이 없습니다."
  DETAIL_CONTENT="$DETAIL_LINES"
  [ -z "$DETAIL_CONTENT" ] && DETAIL_CONTENT="none"

  # 기본 target_file(참고)
  TARGET_FILE="/etc/snmp/snmpd.conf, /usr/share/snmp/snmpd.conf"
else
  # 3) 설정 파일 기반으로 SNMPv3 사용 여부 점검
  CONF_FILES=("/etc/snmp/snmpd.conf" "/usr/share/snmp/snmpd.conf")
  FOUND_CONF=0

  V3_FOUND=0
  V12C_FOUND=0

  for conf in "${CONF_FILES[@]}"; do
    if [ -f "$conf" ]; then
      FOUND_CONF=1
      add_target_file "$conf"

      # 주석/공백 제외한 유효 라인만 대상으로 판단
      V3_LINES="$(grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$conf" 2>/dev/null | grep -E '^(rouser|rwuser|createUser)\b' || true)"
      V12C_LINES="$(grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$conf" 2>/dev/null | grep -E '^(com2sec|rocommunity|rwcommunity)\b' || true)"

      if [ -n "$V3_LINES" ]; then
        V3_FOUND=1
        # 너무 길어질 수 있어 라인 수로 요약
        append_detail "[conf] $conf snmpv3_user_config=FOUND (lines=$(echo "$V3_LINES" | wc -l | tr -d ' '))"
      else
        append_detail "[conf] $conf snmpv3_user_config=NOT_FOUND"
      fi

      if [ -n "$V12C_LINES" ]; then
        V12C_FOUND=1
        append_detail "[conf] $conf snmpv1/v2c_config=FOUND (lines=$(echo "$V12C_LINES" | wc -l | tr -d ' '))"
      else
        append_detail "[conf] $conf snmpv1/v2c_config=NOT_FOUND"
      fi
    else
      append_detail "[conf] $conf=NOT_FOUND"
    fi
  done

  # 4) 최종 판정(보수적으로)
  # - SNMPv3 설정이 확인되면 PASS(단, v1/v2c 설정이 함께 있으면 정책상 혼재 가능 → FAIL로 보고)
  # - SNMPv3 설정이 없고 v1/v2c 설정이 있으면 FAIL
  # - 설정 파일을 찾지 못하면 확인 불가 → FAIL(실행 중인데 정책 검증 불가)
  if [ "$FOUND_CONF" -eq 0 ]; then
    STATUS="FAIL"
    VULNERABLE=1
    REASON_LINE="SNMP 서비스가 실행 중이나 설정 파일을 확인할 수 없어 안전한 SNMP 버전(SNMPv3) 사용 여부를 검증할 수 없으므로 취약합니다. snmpd.conf 위치를 확인하고 SNMPv1/v2c를 비활성화한 뒤 SNMPv3로 구성해야 합니다."
  else
    if [ "$V3_FOUND" -eq 1 ] && [ "$V12C_FOUND" -eq 0 ]; then
      STATUS="PASS"
      REASON_LINE="SNMPv3 사용자 설정이 확인되어 안전한 SNMP 버전(SNMPv3)을 사용하고 있어 이 항목에 대한 보안 위협이 없습니다."
    elif [ "$V3_FOUND" -eq 1 ] && [ "$V12C_FOUND" -eq 1 ]; then
      STATUS="FAIL"
      VULNERABLE=1
      REASON_LINE="SNMPv3 설정이 존재하나 SNMPv1/v2c 설정도 함께 존재하여 보안 수준이 낮은 버전이 사용될 수 있으므로 취약합니다. SNMPv1/v2c(com2sec/rocommunity/rwcommunity) 설정을 제거 또는 비활성화하고 SNMPv3만 사용하도록 정리해야 합니다."
    else
      STATUS="FAIL"
      VULNERABLE=1
      REASON_LINE="SNMPv3 사용자 설정이 확인되지 않아 SNMPv1/v2c 사용이 추정되므로 취약합니다. SNMPv1/v2c를 비활성화하고 SNMPv3(rouser/rwuser/createUser) 기반으로 구성해야 합니다."
    fi
  fi

  DETAIL_CONTENT="$DETAIL_LINES"
  [ -z "$DETAIL_CONTENT" ] && DETAIL_CONTENT="none"
fi

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