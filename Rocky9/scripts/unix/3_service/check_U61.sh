#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.0
# @Author: 이가영
# @Last Updated: 2026-02-16
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

set -u
set -o pipefail

# 기본 변수
ID="U-61"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""
CHECK_COMMAND='(command -v systemctl >/dev/null 2>&1 && systemctl is-active snmpd 2>/dev/null || echo "systemctl_or_snmpd_not_found"); (command -v systemctl >/dev/null 2>&1 && systemctl is-enabled snmpd 2>/dev/null || true); (pgrep -a -x snmpd 2>/dev/null || echo "snmpd_process_not_found"); (grep -nE "^[[:space:]]*(agentAddress|com2sec|rocommunity|rwcommunity|rouser|rwuser|createUser)\b" /etc/snmp/snmpd.conf /usr/share/snmp/snmpd.conf 2>/dev/null || echo "snmpd_conf_not_found_or_no_directives")'

# 1) SNMP 실행 여부
SNMP_RUNNING=0
ACTIVE="N"; ENABLED="N"; PROC="N"

if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet snmpd 2>/dev/null; then ACTIVE="Y"; SNMP_RUNNING=1; fi
if command -v systemctl >/dev/null 2>&1 && systemctl is-enabled --quiet snmpd 2>/dev/null; then ENABLED="Y"; fi
if pgrep -x snmpd >/dev/null 2>&1; then PROC="Y"; SNMP_RUNNING=1; fi

DETAIL_CONTENT="[systemd] snmpd_active=${ACTIVE} snmpd_enabled=${ENABLED}\n[process] snmpd_running=${PROC}"

# 2) SNMP 미사용이면 PASS
if [ "$SNMP_RUNNING" -eq 0 ]; then
  STATUS="PASS"
  REASON_LINE="systemd/프로세스 기준으로 SNMP 서비스가 비활성화되어 있어 이 항목에 대한 보안 위협이 없습니다."
  TARGET_FILE="/etc/snmp/snmpd.conf, /usr/share/snmp/snmpd.conf"
else
  # 3) 설정 파일 점검(가이드 핵심: 접근 제어 설정 여부)
  CONF_FILES=(/etc/snmp/snmpd.conf /usr/share/snmp/snmpd.conf)
  FOUND=0

  OK_HINT=0
  VULN=0

  COM2SEC_OK=0; COM2SEC_WIDE=0
  COMM_OK=0; COMM_WIDE=0; COMM_NO_SRC=0
  V3_OK=0
  AGENT_WIDE=0

  for f in "${CONF_FILES[@]}"; do
    [ -f "$f" ] || continue
    FOUND=1
    TARGET_FILE="${TARGET_FILE:+$TARGET_FILE, }$f"

    CLEAN="$(grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$f" 2>/dev/null || true)"

    # agentAddress(참고): 0.0.0.0/::/udp:161 등 광범위 리슨은 위험도 상승
    AG="$(echo "$CLEAN" | grep -E '^[[:space:]]*agentAddress\b' || true)"
    if [ -n "$AG" ] && echo "$AG" | grep -qE '0\.0\.0\.0|::|udp:161|udp6:161'; then
      AGENT_WIDE=1
    fi

    # com2sec <secname> <source> <community>
    C2="$(echo "$CLEAN" | grep -E '^[[:space:]]*com2sec\b' || true)"
    if [ -n "$C2" ]; then
      OK_HINT=1
      while IFS= read -r line; do
        src="$(echo "$line" | awk '{print $3}')"
        comm="$(echo "$line" | awk '{print $4}')"
        if echo "$src" | grep -qE '^(default|0\.0\.0\.0(/0)?|::(/0)?)$'; then
          COM2SEC_WIDE=1
          [ "$comm" = "public" ] || [ "$comm" = "private" ] && COM2SEC_WIDE=1
        else
          COM2SEC_OK=1
        fi
      done <<< "$C2"
    fi

    # rocommunity/rwcommunity <community> [source[/mask]]
    CR="$(echo "$CLEAN" | grep -E '^[[:space:]]*(rocommunity|rwcommunity)\b' || true)"
    if [ -n "$CR" ]; then
      OK_HINT=1
      while IFS= read -r line; do
        nf="$(echo "$line" | awk '{print NF}')"
        comm="$(echo "$line" | awk '{print $2}')"
        src="$(echo "$line" | awk '{print $3}')"
        if [ -z "$nf" ] || [ "$nf" -le 2 ]; then
          COMM_NO_SRC=1
        else
          if echo "$src" | grep -qE '^(default|0\.0\.0\.0(/0)?|::(/0)?)$'; then
            COMM_WIDE=1
          else
            COMM_OK=1
          fi
        fi
        if [ "$comm" = "public" ] || [ "$comm" = "private" ]; then
          # public/private 자체는 즉시 취약이라기보다, 제한이 없거나 광범위면 취약 근거 강화
          [ "$nf" -le 2 ] && COMM_NO_SRC=1
        fi
      done <<< "$CR"
    fi

    # SNMPv3 사용자(rouser/rwuser/createUser) 존재 시 접근 제어 힌트로 인정
    V3="$(echo "$CLEAN" | grep -E '^[[:space:]]*(rouser|rwuser|createUser)\b' || true)"
    if [ -n "$V3" ]; then
      OK_HINT=1
      V3_OK=1
    fi
  done

  if [ "$FOUND" -eq 0 ]; then
    STATUS="FAIL"
    REASON_LINE="SNMP 서비스가 실행 중이나 snmpd.conf를 확인할 수 없어(파일 미존재/경로 상이) 접근 제어 설정을 검증할 수 있어 취약합니다."
    DETAIL_CONTENT="${DETAIL_CONTENT}\n[conf] /etc/snmp/snmpd.conf,/usr/share/snmp/snmpd.conf=NOT_FOUND"
    DETAIL_CONTENT="${DETAIL_CONTENT}\n[조치] /etc/snmp/snmpd.conf에 com2sec 또는 rocommunity/rwcommunity에 '허용 네트워크'를 지정하고 snmpd를 재시작하세요. (예: com2sec <sec> <허용대역> <community> / rocommunity <community> <허용대역>)"
  else
    # 취약 조건(가이드 핵심: 접근 제어 미설정/미흡)
    [ "$OK_HINT" -eq 0 ] && VULN=1
    [ "$COM2SEC_WIDE" -eq 1 ] && VULN=1
    [ "$COMM_NO_SRC" -eq 1 ] && VULN=1
    [ "$COMM_WIDE" -eq 1 ] && VULN=1
    [ "$AGENT_WIDE" -eq 1 ] && VULN=1

    # 상세 요약(짧게)
    DETAIL_CONTENT="${DETAIL_CONTENT}\n[summary] com2sec_ok=${COM2SEC_OK} com2sec_wide=${COM2SEC_WIDE} ro_rw_ok=${COMM_OK} ro_rw_no_src=${COMM_NO_SRC} ro_rw_wide=${COMM_WIDE} snmpv3_user=${V3_OK} agentAddress_wide=${AGENT_WIDE}"

    if [ "$VULN" -eq 1 ]; then
      STATUS="FAIL"
      REASON_LINE="snmpd.conf에서 com2sec/rocommunity/rwcommunity 접근 제어가 없거나(source 미지정), default(전체) 등으로 광범위 허용되어 취약합니다."
      DETAIL_CONTENT="${DETAIL_CONTENT}\n[조치] (Redhat계열) com2sec의 source를 관리망/특정 호스트로 제한하세요. (Debian계열) rocommunity/rwcommunity 뒤에 <허용 네트워크>를 추가하세요. 적용 후 'systemctl restart snmpd'로 재시작하세요."
    else
      STATUS="PASS"
      REASON_LINE="snmpd.conf에서 com2sec 또는 rocommunity/rwcommunity(또는 SNMPv3 사용자)가 확인되고 허용 대상(source)이 제한되어 있어 이 항목에 대한 보안 위협이 없습니다."
    fi
  fi
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

# JSON 저장을 위한 escape 처리 (백슬래시/따옴표/줄바꿈)
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/\\/\\\\/g; s/"/\\"/g' \
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