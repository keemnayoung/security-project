#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-60
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : SNMP Community String 복잡성 설정
# @Description : SNMP Community String 복잡성 설정 여부 점검
# @Criteria_Good : SNMP Community String 기본값인 "public", "private"이 아닌 영문자, 숫자 포함 10자리 이상 또는 영문자, 숫자, 특수문자 포함 8자리 이상인 경우
# @Criteria_Bad :  아래의 내용 중 하나라도 해당되는 경우
                   # 1. SNMP Community String 기본값인 "public", "private"일 경우
                   # 2. 영문자, 숫자 포함 10자리 미만인 경우
                   # 3. 영문자, 숫자, 특수문자 포함 8자리 미만인 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-60 SNMP Community String 복잡성 설정

set -u

# 기본 변수
ID="U-60"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""
CHECK_COMMAND='systemctl is-active snmpd 2>/dev/null; systemctl is-enabled snmpd 2>/dev/null; pgrep -a -x snmpd 2>/dev/null; grep -nE "^[[:space:]]*(com2sec|rocommunity|rwcommunity|createUser)\b" /etc/snmp/snmpd.conf /usr/share/snmp/snmpd.conf /var/lib/net-snmp/snmpd.conf 2>/dev/null'

DETAIL_LINES=""

append_detail() {
  [ -n "${1:-}" ] && DETAIL_LINES="${DETAIL_LINES}${DETAIL_LINES:+\\n}$1"
}

add_target() {
  [ -n "${1:-}" ] || return 0
  case ",$TARGET_FILE," in
    *,"$1",*) : ;;
    *) TARGET_FILE="${TARGET_FILE}${TARGET_FILE:+, }$1" ;;
  esac
}

mask_token() {
  local s="${1:-}" n="${#s}"
  if [ "$n" -le 3 ]; then
    echo "***"
  else
    echo "${s:0:2}***${s: -2}"
  fi
}

# 복잡성 판정(가이드 기준)
# - 취약: public/private 또는 (길이<8) 또는 (영문+숫자만이고 길이<10)
is_weak_token() {
  local s="${1:-}" low
  low="$(echo "$s" | tr '[:upper:]' '[:lower:]')"
  [[ "$low" =~ ^(public|private)$ ]] && return 0
  [ "${#s}" -lt 8 ] && return 0
  echo "$s" | grep -qE '^[A-Za-z0-9]+$' && [ "${#s}" -lt 10 ] && return 0
  return 1
}

# 1) SNMP 실행 여부
SNMP_RUNNING=0
ACTIVE="N"; ENABLED="N"; PROC="N"

if command -v systemctl >/dev/null 2>&1; then
  systemctl is-active --quiet snmpd 2>/dev/null && ACTIVE="Y" && SNMP_RUNNING=1
  systemctl is-enabled --quiet snmpd 2>/dev/null && ENABLED="Y"
fi
pgrep -x snmpd >/dev/null 2>&1 && PROC="Y" && SNMP_RUNNING=1

append_detail "[systemd] snmpd_active=$ACTIVE snmpd_enabled=$ENABLED"
append_detail "[process] snmpd_running=$PROC"

# 2) 미실행이면 PASS(점검대상 없음)
if [ "$SNMP_RUNNING" -eq 0 ]; then
  STATUS="PASS"
  REASON_LINE="SNMP 서비스가 비활성화되어 있어 점검 대상이 없으며, 이 항목에 대한 보안 위협이 없습니다."
  TARGET_FILE="/etc/snmp/snmpd.conf, /usr/share/snmp/snmpd.conf, /var/lib/net-snmp/snmpd.conf"
  DETAIL_CONTENT="$DETAIL_LINES"
  [ -z "$DETAIL_CONTENT" ] && DETAIL_CONTENT="none"
else
  # 3) 설정 파싱(v1/v2c community + v3 createUser)
  CONF_LIST="/etc/snmp/snmpd.conf /usr/share/snmp/snmpd.conf /var/lib/net-snmp/snmpd.conf"
  FOUND_ANY_CONF=0
  FOUND_V12=0
  FOUND_V3=0
  WEAK_FOUND=0

  for conf in $CONF_LIST; do
    if [ -f "$conf" ]; then
      FOUND_ANY_CONF=1
      add_target "$conf"

      # 주석/공백 제외 후 필요한 키만
      LINES="$(grep -nEv '^[[:space:]]*#|^[[:space:]]*$' "$conf" 2>/dev/null | grep -nE '^[[:space:]]*(com2sec|rocommunity|rwcommunity|createUser)\b' || true)"
      if [ -z "$LINES" ]; then
        append_detail "[conf] $conf relevant_lines=NOT_FOUND"
        continue
      fi

      append_detail "[conf] $conf relevant_lines=FOUND (count=$(echo "$LINES" | wc -l | tr -d ' '))"

      while IFS= read -r line; do
        # "N:내용" 형태 -> 내용만
        body="${line#*:}"
        key="$(echo "$body" | awk '{print $1}' | tr '[:upper:]' '[:lower:]')"

        # v1/v2c
        if [[ "$key" =~ ^(com2sec|rocommunity|rwcommunity)$ ]]; then
          FOUND_V12=1
          if [ "$key" = "com2sec" ]; then
            comm="$(echo "$body" | awk '{print $4}')"
          else
            comm="$(echo "$body" | awk '{print $2}')"
          fi
          [ -z "${comm:-}" ] && append_detail "[parse] $conf | $key community=NOT_PARSED" && continue

          if is_weak_token "$comm"; then
            WEAK_FOUND=1
            append_detail "[check] $conf | $key community=WEAK($(mask_token "$comm"))"
          else
            append_detail "[check] $conf | $key community=OK($(mask_token "$comm"))"
          fi

        # v3
        elif [ "$key" = "createuser" ]; then
          FOUND_V3=1
          # createUser <user> <authproto> <authpass> [<privproto> <privpass>]
          authpass="$(echo "$body" | awk '{print $4}')"
          privpass="$(echo "$body" | awk '{print $6}')"

          if [ -n "${authpass:-}" ]; then
            if is_weak_token "$authpass"; then
              WEAK_FOUND=1
              append_detail "[check] $conf | createUser authpass=WEAK($(mask_token "$authpass"))"
            else
              append_detail "[check] $conf | createUser authpass=OK($(mask_token "$authpass"))"
            fi
          else
            append_detail "[parse] $conf | createUser authpass=NOT_FOUND"
          fi

          if [ -n "${privpass:-}" ]; then
            if is_weak_token "$privpass"; then
              WEAK_FOUND=1
              append_detail "[check] $conf | createUser privpass=WEAK($(mask_token "$privpass"))"
            else
              append_detail "[check] $conf | createUser privpass=OK($(mask_token "$privpass"))"
            fi
          fi
        fi
      done <<< "$LINES"
    else
      append_detail "[conf] $conf=NOT_FOUND"
    fi
  done

  # 4) 최종 판정 + 문구(요청 반영)
  if [ "$FOUND_ANY_CONF" -eq 0 ]; then
    STATUS="FAIL"
    REASON_LINE="SNMP 서비스가 실행 중이나 설정 파일을 확인할 수 없어 취약합니다. (어디서 어떻게 설정되어 있는지 확인 불가) 조치: snmpd.conf 위치/권한을 확인한 뒤 Community String 또는 SNMPv3 인증 비밀번호를 복잡하게 설정하고 snmpd를 재시작하세요."
  elif [ "$FOUND_V12" -eq 0 ] && [ "$FOUND_V3" -eq 0 ]; then
    STATUS="FAIL"
    REASON_LINE="SNMP 서비스가 실행 중이나 Community String(com2sec/rocommunity/rwcommunity) 및 SNMPv3(createUser) 설정을 확인할 수 없어 취약합니다. 조치: /etc/snmp/snmpd.conf 및 /var/lib/net-snmp/snmpd.conf에서 설정을 확인하고, 불필요 시 SNMP 비활성화 또는 인증정보를 복잡하게 설정하세요."
  elif [ "$WEAK_FOUND" -eq 1 ]; then
    STATUS="FAIL"
    REASON_LINE="SNMP 인증정보(Community String 또는 SNMPv3 인증 비밀번호)가 단순하거나 기본값(public/private)으로 설정되어 있어 취약합니다. 조치: 기본값을 제거하고 (영문+숫자 10자 이상) 또는 (영문/숫자/특수문자 포함 8자 이상)으로 변경 후 snmpd 재시작하세요."
  else
    STATUS="PASS"
    REASON_LINE="설정 파일에서 SNMP 인증정보(Community String 또는 SNMPv3 인증 비밀번호)가 복잡성 기준을 충족하도록 설정되어 있어 이 항목에 대한 보안 위협이 없습니다."
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