#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-59
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상 
# @Title : 안전한 SNMP 버전 사용
# @Description : 안전한 SNMP 버전 사용 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-59 안전한 SNMP 버전 사용

# 기본 변수
ID="U-59"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND='(command -v systemctl >/dev/null 2>&1 && systemctl is-active snmpd 2>/dev/null || echo "systemctl_or_snmpd_not_found"); (pgrep -a -x snmpd 2>/dev/null || echo "snmpd_process_not_found"); (ls -l /etc/snmp/snmpd.conf /usr/share/snmp/snmpd.conf 2>/dev/null || true); (grep -inE "^[[:space:]]*(rouser|rwuser|createUser)[[:space:]]+" /etc/snmp/snmpd.conf /usr/share/snmp/snmpd.conf 2>/dev/null || echo "snmpv3_directives_not_found"); (grep -inE "^[[:space:]]*(rocommunity|rwcommunity|com2sec)[[:space:]]+" /etc/snmp/snmpd.conf /usr/share/snmp/snmpd.conf 2>/dev/null || echo "snmpv1v2_directives_not_found")'

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE="/etc/snmp/snmpd.conf"

append_detail() {
  if [ -n "$DETAIL_CONTENT" ]; then
    DETAIL_CONTENT="${DETAIL_CONTENT}\n$1"
  else
    DETAIL_CONTENT="$1"
  fi
}

has_non_comment_match() {
  local file="$1"
  local pattern="$2"
  [ -f "$file" ] || return 1
  grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$file" 2>/dev/null | grep -qE "$pattern"
}

# root 권한 확인(파일 읽기/서비스 확인은 가능하지만, 본 항목은 원칙적으로 root로 점검/조치 권장)
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  IS_SUCCESS=0
  REASON_LINE="root 권한이 아니어서 SNMP 설정 점검 결과를 신뢰하기 어려워 조치가 완료되지 않았습니다."
  DETAIL_CONTENT="sudo로 실행해야 합니다."
else
  HAS_SYSTEMCTL=0
  command -v systemctl >/dev/null 2>&1 && HAS_SYSTEMCTL=1

  SNMP_ACTIVE=0
  SNMP_PROC=0

  if [ "$HAS_SYSTEMCTL" -eq 1 ]; then
    systemctl is-active snmpd >/dev/null 2>&1 && SNMP_ACTIVE=1
  fi
  pgrep -x snmpd >/dev/null 2>&1 && SNMP_PROC=1

  # SNMP 미사용이면 양호
  if [ "$SNMP_ACTIVE" -eq 0 ] && [ "$SNMP_PROC" -eq 0 ]; then
    IS_SUCCESS=1
    REASON_LINE="SNMP(snmpd) 서비스가 비활성화되어 있어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
    append_detail "snmpd_service_active(after)=inactive_or_not_running"
    append_detail "snmpd_process(after)=not_running"
    append_detail "snmp_conf_checked=not_applicable"
  else
    # 설정 파일 후보
    CONF_A="/etc/snmp/snmpd.conf"
    CONF_B="/usr/share/snmp/snmpd.conf"
    CONF=""

    if [ -f "$CONF_A" ]; then
      CONF="$CONF_A"
    elif [ -f "$CONF_B" ]; then
      CONF="$CONF_B"
    fi

    if [ -z "$CONF" ]; then
      IS_SUCCESS=0
      REASON_LINE="SNMP(snmpd) 서비스가 실행 중이나 snmpd.conf 파일을 찾지 못해 조치가 완료되지 않았습니다."
      append_detail "snmpd_service_active(after)=$([ "$SNMP_ACTIVE" -eq 1 ] && echo active || echo inactive)"
      append_detail "snmpd_process(after)=$([ "$SNMP_PROC" -eq 1 ] && echo running || echo not_running)"
      append_detail "snmp_conf_file(after)=not_found"
    else
      TARGET_FILE="$CONF"

      # SNMPv3 지시자(rouser/rwuser/createUser) 존재 여부
      V3_OK=0
      if has_non_comment_match "$CONF" '^[[:space:]]*(rouser|rwuser|createUser)[[:space:]]+'; then
        V3_OK=1
      fi

      # v1/v2 지시자(community/com2sec) 존재 여부(참고 정보)
      V12_FOUND=0
      if has_non_comment_match "$CONF" '^[[:space:]]*(rocommunity|rwcommunity|com2sec)[[:space:]]+'; then
        V12_FOUND=1
      fi

      # (조치 후 상태만 기록) - 실제 조치 대신 현 상태 기록 + 수동 안내
      append_detail "snmp_conf_file(after)=$CONF"
      append_detail "snmpv3_directives_present(after)=$([ "$V3_OK" -eq 1 ] && echo yes || echo no)"
      append_detail "snmpv1v2_directives_present(after)=$([ "$V12_FOUND" -eq 1 ] && echo yes || echo no)"

      if [ "$HAS_SYSTEMCTL" -eq 1 ]; then
        systemctl is-active snmpd >/dev/null 2>&1 && append_detail "snmpd_service_active(after)=active" || append_detail "snmpd_service_active(after)=inactive"
      else
        append_detail "snmpd_service_active(after)=systemctl_not_found"
      fi
      pgrep -x snmpd >/dev/null 2>&1 && append_detail "snmpd_process(after)=running" || append_detail "snmpd_process(after)=not_running"

      if [ "$V3_OK" -eq 1 ]; then
        IS_SUCCESS=1
        REASON_LINE="SNMPv3 설정이 확인되어 안전한 SNMP 버전을 사용 중이므로 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
      else
        IS_SUCCESS=0
        REASON_LINE="SNMP(snmpd) 서비스가 실행 중이며 SNMPv3 설정이 확인되지 않아 조치가 완료되지 않았습니다. SNMPv3로 구성하고 v1/v2 community 설정은 제거(주석/삭제)해야 합니다."
        append_detail "manual_guide(after)=SNMPv3 사용자 생성 예시: net-snmp-create-v3-user -ro -A <AUTH_PASS> -X <PRIV_PASS> -a SHA -x AES <USER>; 적용 후 systemctl restart snmpd. v1/v2 설정(rocommunity/rwcommunity/com2sec)은 주석 처리 또는 삭제"
      fi
    fi
  fi
fi

# raw_evidence 구성 (첫 줄: 평가 이유 / 다음 줄부터: 현재(조치 후) 상태)
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

# JSON escape 처리 (따옴표, 줄바꿈)
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/"/\\"/g' \
  | sed ':a;N;$!ba;s/\n/\\n/g')

# DB 저장용 JSON 출력
echo ""
cat << EOF
{
    "item_code": "$ID",
    "action_date": "$ACTION_DATE",
    "is_success": $IS_SUCCESS,
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
}
EOF