#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-07
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-61
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : SNMP Access Control 설정
# @Description : SNMP 접근 제어 설정 여부 점검
# @Criteria_Good : SNMP 서비스에 접근 제어 설정이 되어 있는 경우
# @Criteria_Bad : SNMP 서비스에 접근 제어 설정이 되어 있지 않은 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-61 SNMP Access Control 설정

# 기본 변수
ID="U-61"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""
CHECK_COMMAND='systemctl is-active snmpd; systemctl is-enabled snmpd; pgrep -a -x snmpd; grep -nE "^(agentAddress|com2sec|rocommunity|rwcommunity|rouser|rwuser)" /etc/snmp/snmpd.conf /usr/share/snmp/snmpd.conf 2>/dev/null'

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

# 2) SNMP 미실행이면 점검 대상 없음(PASS)
if [ "$SNMP_RUNNING" -eq 0 ]; then
  STATUS="PASS"
  REASON_LINE="SNMP 서비스가 비활성화되어 있어 점검 대상이 없습니다."
  DETAIL_CONTENT="$DETAIL_LINES"
  [ -z "$DETAIL_CONTENT" ] && DETAIL_CONTENT="none"
  TARGET_FILE="/etc/snmp/snmpd.conf, /usr/share/snmp/snmpd.conf"
else
  # 3) 설정 파일에서 접근 제어 관련 항목 점검
  CONF_FILES=("/etc/snmp/snmpd.conf" "/usr/share/snmp/snmpd.conf")
  FOUND_CONF=0

  # 취약 판단 플래그
  COM2SEC_FOUND=0
  COM2SEC_DEFAULT_FOUND=0

  RO_RW_FOUND=0
  RO_RW_NO_NET_RESTRICT=0

  AGENTADDR_FOUND=0
  AGENTADDR_WIDE=0

  # SNMPv3는 community 기반 접근 제어가 아니므로,
  # v3만 쓰는 환경은 이 항목에서 "확인된 접근 제어"로 PASS 가능하도록 참고로만 수집
  V3_USER_FOUND=0

  for conf in "${CONF_FILES[@]}"; do
    if [ -f "$conf" ]; then
      FOUND_CONF=1
      add_target_file "$conf"

      # 주석/공백 제외한 유효 라인만 대상으로 증적 수집
      CLEAN="$(grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$conf" 2>/dev/null || true)"

      # agentAddress 점검: 0.0.0.0 또는 :: 또는 생략(=기본 listen) 등은 광범위 가능성
      AGENT_LINES="$(echo "$CLEAN" | grep -E '^agentAddress\b' || true)"
      if [ -n "$AGENT_LINES" ]; then
        AGENTADDR_FOUND=1
        # 단순 기준(보수적): 0.0.0.0 / :: / udp:161 / udp6:161 같이 전체 수신 형태가 있으면 광범위로 판단
        if echo "$AGENT_LINES" | grep -qE '0\.0\.0\.0|::|udp:161|udp6:161'; then
          AGENTADDR_WIDE=1
          append_detail "[check] $conf agentAddress=WIDE_LISTEN"
        else
          append_detail "[check] $conf agentAddress=RESTRICTED"
        fi
      else
        append_detail "[check] $conf agentAddress=NOT_SET"
      fi

      # com2sec: com2sec <secname> <source> <community>
      COM2SEC_LINES="$(echo "$CLEAN" | grep -E '^com2sec\b' || true)"
      if [ -n "$COM2SEC_LINES" ]; then
        COM2SEC_FOUND=1
        # source 자리에 default가 있으면 전체 허용으로 취약
        if echo "$COM2SEC_LINES" | awk '{print $3}' | grep -qx "default"; then
          COM2SEC_DEFAULT_FOUND=1
          append_detail "[check] $conf com2sec_source=default(WIDE_OPEN)"
        else
          append_detail "[check] $conf com2sec_source=RESTRICTED"
        fi
      else
        append_detail "[check] $conf com2sec=NOT_FOUND"
      fi

      # rocommunity/rwcommunity: rocommunity <community> [source[/mask]]
      RO_RW_LINES="$(echo "$CLEAN" | grep -E '^(rocommunity|rwcommunity)\b' || true)"
      if [ -n "$RO_RW_LINES" ]; then
        RO_RW_FOUND=1
        while IFS= read -r line; do
          # 필드 수가 2개면 (community만) -> 네트워크 제한 없음(취약)
          nf="$(echo "$line" | awk '{print NF}')"
          if [ -n "$nf" ] && [ "$nf" -le 2 ]; then
            RO_RW_NO_NET_RESTRICT=1
            append_detail "[check] $conf ro/rwcommunity=NO_SOURCE_RESTRICTION"
          else
            append_detail "[check] $conf ro/rwcommunity=RESTRICTED"
          fi
        done <<< "$RO_RW_LINES"
      else
        append_detail "[check] $conf ro/rwcommunity=NOT_FOUND"
      fi

      # SNMPv3 사용자 설정(참고)
      V3_LINES="$(echo "$CLEAN" | grep -E '^(rouser|rwuser|createUser)\b' || true)"
      if [ -n "$V3_LINES" ]; then
        V3_USER_FOUND=1
        append_detail "[check] $conf snmpv3_user_config=FOUND"
      else
        append_detail "[check] $conf snmpv3_user_config=NOT_FOUND"
      fi
    else
      append_detail "[conf] $conf=NOT_FOUND"
    fi
  done

  # 4) 최종 판정(보수적)
  if [ "$FOUND_CONF" -eq 0 ]; then
    STATUS="FAIL"
    VULNERABLE=1
    REASON_LINE="SNMP 서비스가 실행 중이나 설정 파일을 확인할 수 없어 접근 제어 정책을 검증할 수 없으므로 취약합니다. snmpd.conf 위치 및 include 설정을 확인한 뒤 접근 허용 대상을 제한해야 합니다."
  else
    # 취약 조건
    if [ "$COM2SEC_DEFAULT_FOUND" -eq 1 ]; then
      VULNERABLE=1
    fi
    if [ "$RO_RW_NO_NET_RESTRICT" -eq 1 ]; then
      VULNERABLE=1
    fi

    # agentAddress는 설정이 없을 수도 있으나, 넓게 리슨이면 위험도가 커서 취약 근거로 반영
    if [ "$AGENTADDR_WIDE" -eq 1 ]; then
      VULNERABLE=1
    fi

    # 접근제어 관련 설정이 하나도 안 보이면(특히 v1/v2c 흔적도 없고 v3도 없으면) 확인 불가로 FAIL
    ANY_ACCESS_HINT=0
    [ "$COM2SEC_FOUND" -eq 1 ] && ANY_ACCESS_HINT=1
    [ "$RO_RW_FOUND" -eq 1 ] && ANY_ACCESS_HINT=1
    [ "$V3_USER_FOUND" -eq 1 ] && ANY_ACCESS_HINT=1

    if [ "$ANY_ACCESS_HINT" -eq 0 ]; then
      STATUS="FAIL"
      VULNERABLE=1
      REASON_LINE="SNMP 서비스가 실행 중이나 접근 제어 관련 설정(com2sec/rocommunity/rwcommunity/rouser 등)을 확인할 수 없어 모든 호스트에서 접근이 허용될 가능성을 배제할 수 없으므로 취약합니다. 설정 include 경로를 확인하고 허용 네트워크/호스트를 제한해야 합니다."
    else
      if [ "$VULNERABLE" -eq 1 ]; then
        STATUS="FAIL"
        REASON_LINE="SNMP 접근 제어가 미흡하여 비인가 호스트에서 시스템 정보에 접근할 수 있는 위험이 있으므로 취약합니다. com2sec의 source를 default가 아닌 관리망/특정 호스트로 제한하고, rocommunity/rwcommunity에는 반드시 source 제한을 추가해야 합니다."
      else
        STATUS="PASS"
        REASON_LINE="SNMP 접근 제어 설정이 확인되어 허용 대상이 제한되어 있으므로 이 항목에 대한 보안 위협이 없습니다."
      fi
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