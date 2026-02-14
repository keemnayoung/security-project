#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-44
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : tftp, talk 서비스 비활성화
# @Description : tftp, talk, ntalk 서비스의 활성화 여부 점검
# @Criteria_Good : tftp, talk, ntalk 서비스가 비활성화된 경우
# @Criteria_Bad : tftp, talk, ntalk 서비스가 활성화된 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-44 tftp, talk 서비스 비활성화

# 기본 변수
ID="U-44"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="N/A"
CHECK_COMMAND='( [ -f /etc/inetd.conf ] && grep -nEv "^[[:space:]]*#" /etc/inetd.conf | grep -nEi "^[[:space:]]*(tftp|talk|ntalk)([[:space:]]|$)" || true ); ( [ -d /etc/xinetd.d ] && for f in /etc/xinetd.d/tftp /etc/xinetd.d/talk /etc/xinetd.d/ntalk; do [ -f "$f" ] && grep -nEv "^[[:space:]]*#" "$f" | grep -nqiE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no([[:space:]]|$)" && echo "$f:disable=no"; done || true ); ( systemctl list-units --type=service --type=socket 2>/dev/null | grep -Ei "(tftp|talk|ntalk)" | awk "{print \$1}" | head -n 20 || true )'

DETAIL_CONTENT=""
REASON_LINE=""

DETAILS=()

add_detail() {
  local msg="$1"
  [ -z "$msg" ] && return 0
  DETAILS+=("$msg")
}

VULNERABLE=0

# 1) inetd 점검
if [ -f "/etc/inetd.conf" ]; then
  if grep -nEv "^[[:space:]]*#" /etc/inetd.conf 2>/dev/null | grep -nEi "^[[:space:]]*(tftp|talk|ntalk)([[:space:]]|$)" >/dev/null 2>&1; then
    VULNERABLE=1
    add_detail "/etc/inetd.conf에서 tftp/talk/ntalk 서비스 라인이 주석 처리되지 않고 존재합니다."
  fi
fi

# 2) xinetd 점검 (disable=no 이면 취약)
if [ -d "/etc/xinetd.d" ]; then
  for svc in tftp talk ntalk; do
    f="/etc/xinetd.d/$svc"
    if [ -f "$f" ]; then
      if grep -nEv "^[[:space:]]*#" "$f" 2>/dev/null | grep -qiE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no([[:space:]]|$)"; then
        VULNERABLE=1
        add_detail "$f 에서 disable=no 로 설정되어 있습니다."
      fi
    fi
  done
fi

# 3) systemd 점검 (서비스/소켓)
SYSTEMD_UNITS=$(systemctl list-units --type=service --type=socket 2>/dev/null | grep -Ei "(tftp|talk|ntalk)" | awk '{print $1}' | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g' | sed 's/[[:space:]]$//')
if [ -n "$SYSTEMD_UNITS" ]; then
  # 존재 자체가 항상 "활성"은 아니지만, list-units에 잡히면 대개 로드/활성 상태이므로 점검 근거로 사용
  VULNERABLE=1
  add_detail "systemd에서 관련 유닛이 활성/로드 상태로 확인됩니다: ${SYSTEMD_UNITS}"
fi

if [ "$VULNERABLE" -eq 1 ]; then
  STATUS="FAIL"
  REASON_LINE="tftp/talk/ntalk 서비스가 활성화되어 있으면 불필요한 서비스 노출로 인해 침해 가능성이 증가하므로 취약합니다. 실제 사용 여부를 확인한 뒤 불필요하면 중지/비활성화가 필요합니다."
  DETAIL_CONTENT=$(printf "%s\n" "${DETAILS[@]}")
else
  STATUS="PASS"
  REASON_LINE="tftp/talk/ntalk 서비스가 활성화된 정황이 확인되지 않아 이 항목에 대한 보안 위협이 없습니다."
  DETAIL_CONTENT="no_tftp_talk_ntalk_active"
fi

# raw_evidence 구성 (첫 줄: 평가 이유 / 다음 줄부터: 현재 설정값)
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
