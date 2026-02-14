#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로그램
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-60
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : SNMP Community String 복잡성 설정
# @Description : SNMP Community String 복잡성 설정 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-60 SNMP Community String 복잡성 설정

# 기본 변수
ID="U-60"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND='(command -v systemctl >/dev/null 2>&1 && systemctl is-active snmpd 2>/dev/null || echo "systemctl_or_snmpd_not_found"); (pgrep -a -x snmpd 2>/dev/null || echo "snmpd_process_not_found"); (ls -l /etc/snmp/snmpd.conf /usr/share/snmp/snmpd.conf 2>/dev/null || true); (grep -inE "^[[:space:]]*(rocommunity|rwcommunity|com2sec)[[:space:]]+" /etc/snmp/snmpd.conf /usr/share/snmp/snmpd.conf 2>/dev/null || echo "community_directives_not_found"); (grep -inE "^[[:space:]]*(rocommunity|rwcommunity|com2sec).*(public|private)\\b" /etc/snmp/snmpd.conf /usr/share/snmp/snmpd.conf 2>/dev/null || echo "weak_public_private_not_found")'

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

# root 권한 확인
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  IS_SUCCESS=0
  REASON_LINE="root 권한이 아니어서 SNMP 설정 점검/조치를 수행할 수 없어 조치가 완료되지 않았습니다."
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

  # 설정 파일 후보 결정
  CONF_A="/etc/snmp/snmpd.conf"
  CONF_B="/usr/share/snmp/snmpd.conf"
  CONF=""

  if [ -f "$CONF_A" ]; then
    CONF="$CONF_A"
  elif [ -f "$CONF_B" ]; then
    CONF="$CONF_B"
  fi

  # SNMP 미사용 → 조치 대상 없음(비활성 상태 유지가 목표)
  if [ "$SNMP_ACTIVE" -eq 0 ] && [ "$SNMP_PROC" -eq 0 ]; then
    IS_SUCCESS=1
    REASON_LINE="SNMP(snmpd) 서비스가 비활성화되어 있어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
    append_detail "snmpd_service_active(after)=inactive_or_not_running"
    append_detail "snmpd_process(after)=not_running"
    append_detail "snmp_conf_checked=not_applicable"
  else
    # SNMP 사용 중인데 설정 파일이 없으면 실패
    if [ -z "$CONF" ]; then
      IS_SUCCESS=0
      REASON_LINE="SNMP(snmpd) 서비스가 실행 중이나 snmpd.conf 파일을 찾지 못해 조치가 완료되지 않았습니다."
      append_detail "snmpd_service_active(after)=$([ "$SNMP_ACTIVE" -eq 1 ] && echo active || echo inactive)"
      append_detail "snmpd_process(after)=$([ "$SNMP_PROC" -eq 1 ] && echo running || echo not_running)"
      append_detail "snmp_conf_file(after)=not_found"
    else
      TARGET_FILE="$CONF"

      # (현재 설정만 기록) community 관련 지시자 존재 여부
      COMMUNITY_PRESENT=0
      has_non_comment_match "$CONF" '^[[:space:]]*(rocommunity|rwcommunity|com2sec)[[:space:]]+' && COMMUNITY_PRESENT=1

      # 취약 community(public/private) 탐지
      WEAK_FOUND=0
      has_non_comment_match "$CONF" '^[[:space:]]*com2sec[[:space:]].*(public|private)\b' && WEAK_FOUND=1
      has_non_comment_match "$CONF" '^[[:space:]]*(rocommunity|rwcommunity)[[:space:]].*(public|private)\b' && WEAK_FOUND=1

      append_detail "snmp_conf_file(after)=$CONF"
      append_detail "community_directives_present(after)=$([ "$COMMUNITY_PRESENT" -eq 1 ] && echo yes || echo no)"
      append_detail "weak_public_private_found(after)=$([ "$WEAK_FOUND" -eq 1 ] && echo yes || echo no)"

      if [ "$HAS_SYSTEMCTL" -eq 1 ]; then
        systemctl is-active snmpd >/dev/null 2>&1 && append_detail "snmpd_service_active(after)=active" || append_detail "snmpd_service_active(after)=inactive"
      else
        append_detail "snmpd_service_active(after)=systemctl_not_found"
      fi
      pgrep -x snmpd >/dev/null 2>&1 && append_detail "snmpd_process(after)=running" || append_detail "snmpd_process(after)=not_running"

      if [ "$COMMUNITY_PRESENT" -eq 0 ]; then
        # v1/v2 community 기반 설정 자체가 없으면(또는 v3만 쓰는 케이스) 이 항목 관점에서는 양호로 처리
        IS_SUCCESS=1
        REASON_LINE="SNMP Community String 설정이 발견되지 않아(또는 SNMPv3 기반 구성으로 추정되어) 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
        append_detail "note(after)=rocommunity/rwcommunity/com2sec 설정이 없어 community string 기반 접근이 확인되지 않았습니다."
      else
        if [ "$WEAK_FOUND" -eq 1 ]; then
          IS_SUCCESS=0
          REASON_LINE="SNMP 서비스가 사용 중이며 취약한 Community String(public/private)이 확인되어 조치가 완료되지 않았습니다. 정책에 맞는 복잡한 문자열로 수동 변경이 필요합니다."
          append_detail "manual_guide(after)=snmpd.conf의 rocommunity/rwcommunity/com2sec에서 public/private를 제거하고 복잡한 문자열로 변경(예: 영문+숫자 10자 이상 또는 영문+숫자+특수문자 8자 이상) 후 systemctl restart snmpd"
        else
          IS_SUCCESS=1
          REASON_LINE="SNMP Community String이 취약값(public/private)으로 설정되어 있지 않아 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
        fi
      fi
    fi
  fi
fi

# raw_evidence 구성
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