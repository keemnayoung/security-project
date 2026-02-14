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

# 기본 변수
ID="U-60"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE="/etc/snmp/snmpd.conf"
CHECK_COMMAND='systemctl is-active snmpd; systemctl is-enabled snmpd; pgrep -a -x snmpd; grep -nE "^(com2sec|rocommunity|rwcommunity)" /etc/snmp/snmpd.conf /usr/share/snmp/snmpd.conf 2>/dev/null'

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

mask_token() {
  # 민감값(community)을 그대로 남기지 않기 위해 마스킹:
  # - 길이 3 이하: "***"
  # - 그 이상: 앞 2글자 + "***" + 뒤 2글자
  local s="$1"
  local n="${#s}"
  if [ "$n" -le 3 ]; then
    echo "***"
  else
    local head="${s:0:2}"
    local tail="${s: -2}"
    echo "${head}***${tail}"
  fi
}

is_weak_default() {
  # public/private (대소문자 무시)
  echo "$1" | tr '[:upper:]' '[:lower:]' | grep -qE '^(public|private)$'
}

is_too_simple() {
  # "복잡성"을 엄격히 측정하기는 어렵기 때문에,
  # 최소 기준으로 아래 중 하나면 "단순"로 간주(보수적):
  # - 길이 8 미만
  # - 영문/숫자만으로 구성되며 길이 10 미만(예: password1 수준)
  # (조직 정책에 따라 조정 가능)
  local s="$1"
  local n="${#s}"

  if [ "$n" -lt 8 ]; then
    return 0
  fi

  if echo "$s" | grep -qE '^[A-Za-z0-9]+$' && [ "$n" -lt 10 ]; then
    return 0
  fi

  return 1
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

  # 참고 target_file
  TARGET_FILE="/etc/snmp/snmpd.conf, /usr/share/snmp/snmpd.conf"
else
  # 3) 설정 파일에서 community 추출(v1/v2c 흔적)
  CONF_FILES=("/etc/snmp/snmpd.conf" "/usr/share/snmp/snmpd.conf")
  FOUND_CONF=0
  FOUND_COMM=0
  FOUND_WEAK=0
  FOUND_SIMPLE=0

  for conf in "${CONF_FILES[@]}"; do
    if [ -f "$conf" ]; then
      FOUND_CONF=1
      add_target_file "$conf"

      # 주석/공백 제외
      LINES="$(grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$conf" 2>/dev/null | grep -E '^(com2sec|rocommunity|rwcommunity)\b' || true)"
      if [ -z "$LINES" ]; then
        append_detail "[conf] $conf community_config=NOT_FOUND"
        continue
      fi

      append_detail "[conf] $conf community_config=FOUND (lines=$(echo "$LINES" | wc -l | tr -d ' '))"

      # com2sec: 보통 4번째 필드가 community (com2sec <secname> <source> <community>)
      # rocommunity/rwcommunity: 보통 2번째 필드가 community
      while IFS= read -r line; do
        key="$(echo "$line" | awk '{print $1}' | tr '[:upper:]' '[:lower:]')"
        comm=""
        if [ "$key" = "com2sec" ]; then
          comm="$(echo "$line" | awk '{print $4}')"
        else
          comm="$(echo "$line" | awk '{print $2}')"
        fi

        # comm이 비어있거나 옵션/호스트가 들어간 형태면 스킵(그래도 흔적은 남김)
        if [ -z "$comm" ]; then
          append_detail "[parse] $conf | $key community=NOT_PARSED | line=$(echo "$line" | tr '\t' ' ')"
          continue
        fi

        FOUND_COMM=1

        # 약한 기본값(public/private)
        if is_weak_default "$comm"; then
          FOUND_WEAK=1
          append_detail "[check] $conf | $key community=WEAK_DEFAULT($(mask_token "$comm"))"
          continue
        fi

        # 단순 문자열(보수적 규칙)
        if is_too_simple "$comm"; then
          FOUND_SIMPLE=1
          append_detail "[check] $conf | $key community=SIMPLE($(mask_token "$comm"))) "
        else
          append_detail "[check] $conf | $key community=OK($(mask_token "$comm"))"
        fi
      done <<< "$LINES"
    else
      append_detail "[conf] $conf=NOT_FOUND"
    fi
  done

  # 4) 최종 판정
  if [ "$FOUND_CONF" -eq 0 ]; then
    STATUS="FAIL"
    VULNERABLE=1
    REASON_LINE="SNMP 서비스가 실행 중이나 설정 파일을 확인할 수 없어 Community String 복잡성 정책을 검증할 수 없으므로 취약합니다. snmpd.conf 위치를 확인하고 기본값(public/private) 사용 여부 및 복잡성 기준을 점검해야 합니다."
  else
    if [ "$FOUND_COMM" -eq 0 ]; then
      # v1/v2c community가 안 보이면(=v3만 쓰거나 별도 include 등) 단정 어렵지만,
      # U-60은 community 복잡성 항목이므로 "확인 필요"로 FAIL(보수적) 처리
      STATUS="FAIL"
      VULNERABLE=1
      REASON_LINE="SNMP 서비스가 실행 중이나 Community String 설정(com2sec/rocommunity/rwcommunity)을 확인할 수 없어 복잡성 정책 준수 여부를 판단할 수 없으므로 취약합니다. SNMPv1/v2c 사용 여부 및 설정 include 경로를 확인해야 합니다."
    elif [ "$FOUND_WEAK" -eq 1 ]; then
      STATUS="FAIL"
      VULNERABLE=1
      REASON_LINE="SNMP Community String에 추측 가능한 기본값(public/private)이 사용되어 시스템 정보가 노출될 수 있으므로 취약합니다. 기본값을 제거하고 조직 보안 정책에 부합하는 복잡한 문자열로 변경해야 합니다."
    elif [ "$FOUND_SIMPLE" -eq 1 ]; then
      STATUS="FAIL"
      VULNERABLE=1
      REASON_LINE="SNMP Community String 복잡성이 미흡하여 추측 공격에 노출될 수 있으므로 취약합니다. 영문/숫자/특수문자를 조합한 충분히 긴 문자열로 변경해야 합니다."
    else
      STATUS="PASS"
      REASON_LINE="SNMP Community String이 기본값(public/private)이 아니며 복잡성 기준에 부합하여 이 항목에 대한 보안 위협이 없습니다."
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