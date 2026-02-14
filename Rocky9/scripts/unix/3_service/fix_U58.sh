#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-58
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : 불필요한 SNMP 서비스 구동 점검
# @Description : SNMP 서비스 활성화 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-58 불필요한 SNMP 서비스 구동 점검

# 기본 변수
ID="U-58"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND='(command -v systemctl >/dev/null 2>&1 && systemctl status snmpd 2>/dev/null | sed -n "1,12p" || echo "systemctl_not_found"); (pgrep -a -x snmpd 2>/dev/null || echo "snmpd_process_not_found"); (rpm -q net-snmp 2>/dev/null || true); (command -v snmpd >/dev/null 2>&1 && snmpd -v 2>&1 | head -n 1 || true)'

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE="/usr/sbin/snmpd"

append_detail() {
  if [ -n "$DETAIL_CONTENT" ]; then
    DETAIL_CONTENT="${DETAIL_CONTENT}\n$1"
  else
    DETAIL_CONTENT="$1"
  fi
}

# root 권한 확인
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  IS_SUCCESS=0
  REASON_LINE="root 권한이 아니어서 SNMP(snmpd) 서비스 중지/비활성화 조치를 수행할 수 없어 조치가 완료되지 않았습니다."
  DETAIL_CONTENT="sudo로 실행해야 합니다."
else
  HAS_SYSTEMCTL=0
  command -v systemctl >/dev/null 2>&1 && HAS_SYSTEMCTL=1

  WAS_ACTIVE=0
  WAS_ENABLED=0
  WAS_RUNNING_PROC=0

  # 현재 상태 수집(현재/조치 후에 포함할 최소 데이터로만 사용)
  if [ "$HAS_SYSTEMCTL" -eq 1 ]; then
    systemctl is-active snmpd >/dev/null 2>&1 && WAS_ACTIVE=1
    systemctl is-enabled snmpd >/dev/null 2>&1 && WAS_ENABLED=1
  fi
  pgrep -x snmpd >/dev/null 2>&1 && WAS_RUNNING_PROC=1

  MODIFIED=0

  # 1) systemd 서비스 중지/비활성화/마스킹(가능 시)
  if [ "$HAS_SYSTEMCTL" -eq 1 ]; then
    if systemctl list-unit-files 2>/dev/null | grep -qE '^snmpd\.service'; then
      if systemctl stop snmpd >/dev/null 2>&1; then
        MODIFIED=1
      fi
      if systemctl disable snmpd >/dev/null 2>&1; then
        MODIFIED=1
      fi
      # 재활성화 방지(가능 시)
      if systemctl mask snmpd >/dev/null 2>&1; then
        MODIFIED=1
      fi
    fi
  fi

  # 2) 잔존 프로세스 종료(서비스가 아니어도 떠 있을 수 있음)
  if pgrep -x snmpd >/dev/null 2>&1; then
    pkill -x snmpd >/dev/null 2>&1 || true
    sleep 1
    if pgrep -x snmpd >/dev/null 2>&1; then
      pkill -9 -x snmpd >/dev/null 2>&1 || true
    fi
    MODIFIED=1
  fi

  # 3) 최종 상태 수집(조치 후/현재만 기록)
  AFTER_ACTIVE="unknown"
  AFTER_ENABLED="unknown"
  AFTER_MASKED="unknown"

  if [ "$HAS_SYSTEMCTL" -eq 1 ]; then
    systemctl is-active snmpd >/dev/null 2>&1 && AFTER_ACTIVE="active" || AFTER_ACTIVE="inactive"
    systemctl is-enabled snmpd >/dev/null 2>&1 && AFTER_ENABLED="enabled" || AFTER_ENABLED="disabled"
    # masked 여부는 is-enabled 결과가 masked로 나올 수 있어 함께 확인
    if systemctl is-enabled snmpd 2>/dev/null | grep -qi '^masked$'; then
      AFTER_MASKED="masked"
    else
      # unit-file이 없으면 not-found가 나올 수 있음
      AFTER_MASKED="$(systemctl is-enabled snmpd 2>/dev/null | tr -d '\r' | head -n 1)"
      [ -z "$AFTER_MASKED" ] && AFTER_MASKED="unknown"
    fi
  else
    AFTER_ACTIVE="systemctl_not_found"
    AFTER_ENABLED="systemctl_not_found"
    AFTER_MASKED="systemctl_not_found"
  fi

  if pgrep -a -x snmpd >/dev/null 2>&1; then
    AFTER_PROC="running"
    AFTER_PROC_LIST="$(pgrep -a -x snmpd 2>/dev/null | head -n 5)"
  else
    AFTER_PROC="not_running"
    AFTER_PROC_LIST="snmpd_process_not_found"
  fi

  append_detail "snmpd_service_active(after)=$AFTER_ACTIVE"
  append_detail "snmpd_service_enabled(after)=$AFTER_ENABLED"
  append_detail "snmpd_service_masked(after)=$AFTER_MASKED"
  append_detail "snmpd_process(after)=$AFTER_PROC"
  append_detail "snmpd_process_list(after)=$AFTER_PROC_LIST"

  # 4) 최종 판정(서비스가 active이거나 프로세스가 남아있으면 실패)
  STILL_ACTIVE=0
  STILL_PROC=0

  [ "$AFTER_ACTIVE" = "active" ] && STILL_ACTIVE=1
  [ "$AFTER_PROC" = "running" ] && STILL_PROC=1

  if [ "$STILL_ACTIVE" -eq 0 ] && [ "$STILL_PROC" -eq 0 ]; then
    IS_SUCCESS=1
    if [ "$MODIFIED" -eq 1 ] || [ "$WAS_ACTIVE" -eq 1 ] || [ "$WAS_ENABLED" -eq 1 ] || [ "$WAS_RUNNING_PROC" -eq 1 ]; then
      REASON_LINE="불필요한 SNMP(snmpd) 서비스를 중지하고 비활성화하여 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
    else
      REASON_LINE="SNMP(snmpd) 서비스가 이미 비활성화 상태로 유지되어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
    fi
  else
    IS_SUCCESS=0
    REASON_LINE="조치를 수행했으나 SNMP(snmpd) 서비스가 여전히 활성 상태이거나 프로세스가 남아 있어 조치가 완료되지 않았습니다."
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