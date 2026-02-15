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

set -u

# 기본 변수
ID="U-58"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

UNITS=("snmpd" "snmptrapd")
PROCS=("snmpd" "snmptrapd")

CHECK_COMMAND='systemctl is-active snmpd snmptrapd 2>/dev/null; systemctl is-enabled snmpd snmptrapd 2>/dev/null; systemctl list-unit-files 2>/dev/null | grep -E "^(snmpd|snmptrapd)\.service"; pgrep -a -x snmpd 2>/dev/null; pgrep -a -x snmptrapd 2>/dev/null; command -v snmpd 2>/dev/null; command -v snmptrapd 2>/dev/null'

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE="/usr/sbin/snmpd"

append_detail(){ [ -n "${1:-}" ] || return 0; DETAIL_CONTENT="${DETAIL_CONTENT}${DETAIL_CONTENT:+\n}$1"; }

# root 권한 확인
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  IS_SUCCESS=0
  REASON_LINE="root 권한이 아니어서 SNMP(snmpd/snmptrapd) 서비스 중지/비활성화 조치를 수행할 수 없어 조치가 완료되지 않았습니다."
  DETAIL_CONTENT="sudo로 실행해야 합니다."
else
  HAS_SYSTEMCTL=0; command -v systemctl >/dev/null 2>&1 && HAS_SYSTEMCTL=1

  MODIFIED=0

  # 1) systemd 서비스 중지/비활성화/마스킹(가능 시)
  if [ "$HAS_SYSTEMCTL" -eq 1 ]; then
    for u in "${UNITS[@]}"; do
      if systemctl list-unit-files 2>/dev/null | grep -qE "^${u}\.service"; then
        systemctl stop "$u" >/dev/null 2>&1 && MODIFIED=1
        systemctl disable "$u" >/dev/null 2>&1 && MODIFIED=1
        systemctl mask "$u" >/dev/null 2>&1 && MODIFIED=1
      fi
    done
  fi

  # 2) 잔존 프로세스 종료(서비스가 아니어도 떠 있을 수 있음)
  for p in "${PROCS[@]}"; do
    if pgrep -x "$p" >/dev/null 2>&1; then
      pkill -x "$p" >/dev/null 2>&1 || true
      sleep 1
      pgrep -x "$p" >/dev/null 2>&1 && pkill -9 -x "$p" >/dev/null 2>&1 || true
      MODIFIED=1
    fi
  done

  # 3) 조치 후 상태 수집(조치 후/현재만 기록)
  STILL_BAD=0

  if [ "$HAS_SYSTEMCTL" -eq 1 ]; then
    for u in "${UNITS[@]}"; do
      a="$(systemctl is-active "$u" 2>/dev/null || echo unknown)"
      e="$(systemctl is-enabled "$u" 2>/dev/null | head -n 1 | tr -d '\r')"
      [ -z "$e" ] && e="unknown"
      append_detail "[systemd-after] ${u}: active=${a}, enabled=${e}"
      # active 이거나 enabled(또는 masked가 아닌 enabled류)면 실패로 간주
      [ "$a" = "active" ] && STILL_BAD=1
      [ "$e" = "enabled" ] && STILL_BAD=1
    done
  else
    append_detail "[systemd-after] systemctl_not_found"
    # systemctl 없는 환경이면 프로세스만으로 판단
  fi

  for p in "${PROCS[@]}"; do
    if pgrep -a -x "$p" >/dev/null 2>&1; then
      append_detail "[process-after] ${p}: running=Y, list=$(pgrep -a -x "$p" 2>/dev/null | head -n 3 | tr '\n' ';')"
      STILL_BAD=1
    else
      append_detail "[process-after] ${p}: running=N"
    fi
  done

  # 바이너리 경로(참고 증적)
  SNMPD_BIN="$(command -v snmpd 2>/dev/null || true)"
  SNMPTRAPD_BIN="$(command -v snmptrapd 2>/dev/null || true)"
  [ -n "$SNMPD_BIN" ] && TARGET_FILE="$SNMPD_BIN"
  append_detail "[binary] snmpd_path=${SNMPD_BIN:-NOT_FOUND}, snmptrapd_path=${SNMPTRAPD_BIN:-NOT_FOUND}"

  # 4) 최종 판정
  if [ "$STILL_BAD" -eq 0 ]; then
    IS_SUCCESS=1
    REASON_LINE="불필요한 SNMP(snmpd/snmptrapd) 서비스를 중지하고 비활성화하여 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
    [ "$MODIFIED" -eq 0 ] && REASON_LINE="SNMP(snmpd/snmptrapd) 서비스가 이미 비활성화 상태로 유지되어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
  else
    IS_SUCCESS=0
    REASON_LINE="조치를 수행했으나 SNMP(snmpd/snmptrapd) 서비스가 여전히 활성 상태이거나 자동기동(enabled)이 남아 있거나 프로세스가 잔존하여 조치가 완료되지 않았습니다."
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

# JSON escape 처리 (백슬래시/따옴표/줄바꿈)
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/\\/\\\\/g; s/"/\\"/g' \
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