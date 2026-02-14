#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-61
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : SNMP Access Control 설정
# @Description : SNMP 접근 제어 설정 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-61 SNMP Access Control 설정

# 기본 변수
ID="U-61"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND='(command -v systemctl >/dev/null 2>&1 && systemctl is-active snmpd 2>/dev/null || echo "systemctl_or_snmpd_not_found"); (pgrep -a -x snmpd 2>/dev/null || echo "snmpd_process_not_found"); (ls -l /etc/snmp/snmpd.conf /usr/share/snmp/snmpd.conf 2>/dev/null || true); (grep -inE "^[[:space:]]*com2sec[[:space:]]+" /etc/snmp/snmpd.conf /usr/share/snmp/snmpd.conf 2>/dev/null || echo "com2sec_not_found"); (grep -inE "^[[:space:]]*(rocommunity|rwcommunity)[[:space:]]+" /etc/snmp/snmpd.conf /usr/share/snmp/snmpd.conf 2>/dev/null || echo "ro_rwcommunity_not_found")'

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

  # SNMP 미사용 → 조치 대상 없음
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

      MODIFIED=0
      NEEDS_MANUAL=0

      # 1) com2sec default → 127.0.0.1 로 제한(있을 때만)
      if has_non_comment_match "$CONF" '^[[:space:]]*com2sec[[:space:]]+[^#[:space:]]+[[:space:]]+default([[:space:]]|$)'; then
        cp -a "$CONF" "${CONF}.bak_$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true
        sed -i -E 's/^([[:space:]]*com2sec[[:space:]]+[^#[:space:]]+[[:space:]]+)default([[:space:]]+)/\1127.0.0.1\2/' "$CONF" 2>/dev/null || true
        MODIFIED=1
      fi

      # 2) rocommunity/rwcommunity에 네트워크 제한이 없는 단일 필드 형태면 수동 필요
      # 예: rocommunity public   (소스/네트워크 없음)
      if has_non_comment_match "$CONF" '^[[:space:]]*(rocommunity|rwcommunity)[[:space:]]+[^#[:space:]]+[[:space:]]*$'; then
        NEEDS_MANUAL=1
      fi

      # (현재/조치 후 상태만 기록)
      append_detail "snmp_conf_file(after)=$CONF"
      if [ "$HAS_SYSTEMCTL" -eq 1 ]; then
        systemctl is-active snmpd >/dev/null 2>&1 && append_detail "snmpd_service_active(after)=active" || append_detail "snmpd_service_active(after)=inactive"
      else
        append_detail "snmpd_service_active(after)=systemctl_not_found"
      fi
      pgrep -x snmpd >/dev/null 2>&1 && append_detail "snmpd_process(after)=running" || append_detail "snmpd_process(after)=not_running"

      # 조치 후 관련 라인 요약(바뀐/현재 설정만)
      COM2SEC_AFTER="$(grep -inE '^[[:space:]]*com2sec[[:space:]]+' "$CONF" 2>/dev/null | head -n 5)"
      [ -n "$COM2SEC_AFTER" ] && append_detail "com2sec_lines(after)=$(echo "$COM2SEC_AFTER" | tr '\n' '|' )" || append_detail "com2sec_lines(after)=not_found"

      RO_RW_AFTER="$(grep -inE '^[[:space:]]*(rocommunity|rwcommunity)[[:space:]]+' "$CONF" 2>/dev/null | head -n 5)"
      [ -n "$RO_RW_AFTER" ] && append_detail "ro_rwcommunity_lines(after)=$(echo "$RO_RW_AFTER" | tr '\n' '|' )" || append_detail "ro_rwcommunity_lines(after)=not_found"

      # 결과 판단
      if [ "$NEEDS_MANUAL" -eq 1 ]; then
        IS_SUCCESS=0
        REASON_LINE="SNMP 접근 제어 설정에서 네트워크 제한이 없는 rocommunity/rwcommunity 항목이 확인되어 조치가 완료되지 않았습니다. 허용할 네트워크 대역을 수동으로 제한해야 합니다."
        append_detail "manual_guide(after)=예) rocommunity <community> 127.0.0.1 또는 rocommunity <community> 192.168.1.0/24 형태로 제한 후 systemctl restart snmpd"
      else
        # com2sec default가 있었고 변경했으면 재시작 시도(실패 시 FAIL)
        if [ "$MODIFIED" -eq 1 ]; then
          if systemctl restart snmpd >/dev/null 2>&1; then
            append_detail "snmpd_restart(after)=success"
            IS_SUCCESS=1
            REASON_LINE="SNMP 접근 제어 설정이 로컬(127.0.0.1) 기준으로 제한되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
          else
            append_detail "snmpd_restart(after)=failed"
            IS_SUCCESS=0
            REASON_LINE="SNMP 설정을 수정했으나 snmpd 서비스 재시작에 실패하여 조치가 완료되지 않았습니다."
            append_detail "manual_guide(after)=snmpd.conf 구문 오류 여부를 확인하고 systemctl restart snmpd 를 수동 수행해야 합니다."
          fi
        else
          # 변경 사항이 없어도 ro/rwcommunity 네트워크 제한 문제가 없으면 양호 처리
          IS_SUCCESS=1
          REASON_LINE="SNMP 접근 제어 설정이 확인되었으며, 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
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