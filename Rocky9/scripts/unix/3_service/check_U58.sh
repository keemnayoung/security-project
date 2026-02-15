#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-58
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : 불필요한 SNMP 서비스 구동 점검
# @Description : SNMP 서비스 활성화 여부 점검
# @Criteria_Good : SNMP 서비스를 사용하지 않는 경우
# @Criteria_Bad :  SNMP 서비스를 사용하는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-58 불필요한 SNMP 서비스 구동 점검

set -u

# 기본 변수
ID="U-58"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/usr/sbin/snmpd"
CHECK_COMMAND='systemctl is-active snmpd snmptrapd; systemctl is-enabled snmpd snmptrapd; systemctl list-units --type=service | grep -nE "(snmpd|snmptrapd)"; pgrep -a -x snmpd; pgrep -a -x snmptrapd; command -v snmpd; command -v snmptrapd'

# 점검 대상(불필요 SNMP 서비스 범위)
UNITS=("snmpd" "snmptrapd")
PROCS=("snmpd" "snmptrapd")

DETAIL_CONTENT=""
ACTIVE_HIT=0
ENABLED_HIT=0
PROC_HIT=0

# systemd 상태 수집
for u in "${UNITS[@]}"; do
  a="$(systemctl is-active "$u" 2>/dev/null || echo "unknown")"
  e="$(systemctl is-enabled "$u" 2>/dev/null || echo "unknown")"
  DETAIL_CONTENT="${DETAIL_CONTENT}[systemd] ${u}: active=${a}, enabled=${e}\n"

  # active/enabled가 정확히 잡히는 경우만 취약 판단에 반영(unknown은 미설치/미로드 가능)
  [ "$a" = "active" ] && ACTIVE_HIT=1
  [ "$e" = "enabled" ] && ENABLED_HIT=1
done

# 프로세스 확인(보조)
for p in "${PROCS[@]}"; do
  if pgrep -x "$p" >/dev/null 2>&1; then
    PROC_HIT=1
    DETAIL_CONTENT="${DETAIL_CONTENT}[process] ${p}: running=Y\n"
  else
    DETAIL_CONTENT="${DETAIL_CONTENT}[process] ${p}: running=N\n"
  fi
done

# 바이너리 경로(참고 증적)
SNMPD_BIN="$(command -v snmpd 2>/dev/null || true)"
SNMPTRAPD_BIN="$(command -v snmptrapd 2>/dev/null || true)"
[ -n "$SNMPD_BIN" ] && TARGET_FILE="$SNMPD_BIN"
DETAIL_CONTENT="${DETAIL_CONTENT}[binary] snmpd_path=${SNMPD_BIN:-NOT_FOUND}, snmptrapd_path=${SNMPTRAPD_BIN:-NOT_FOUND}"

# 최종 판정
if [ $ACTIVE_HIT -eq 1 ] || [ $ENABLED_HIT -eq 1 ] || [ $PROC_HIT -eq 1 ]; then
  STATUS="FAIL"
  REASON_LINE="systemd에서 snmpd/snmptrapd 서비스가 active 또는 enabled(또는 프로세스 실행) 상태로 확인되어 취약합니다. 조치: 불필요 시 'systemctl stop snmpd snmptrapd' 후 'systemctl disable snmpd snmptrapd'로 중지 및 비활성화하세요."
else
  STATUS="PASS"
  REASON_LINE="systemd에서 snmpd/snmptrapd 서비스가 비활성(inactive)이고 비활성화(disabled)되어 있어 이 항목에 대한 보안 위협이 없습니다."
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