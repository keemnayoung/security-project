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

# 1. 항목 정보 정의
ID="U-44"
CATEGORY="서비스 관리"
TITLE="tftp, talk 서비스 비활성화"
IMPORTANCE="상"
TARGET_FILE="N/A"

# 2. 진단 로직
STATUS="PASS"
VULNERABLE=0
FINDINGS=""

SERVICES=("tftp" "talk" "ntalk")

# systemd에서 실제로 흔한 유닛 후보(서비스/소켓)
SYSTEMD_UNITS=(
  "tftp.service"
  "tftp.socket"
  "talk.service"
  "ntalk.service"
  "talkd.service"
  "ntalkd.service"
)

# 점검 경로(증거용)
CHECK_PATHS="/etc/inetd.conf, /etc/xinetd.d/{tftp,talk,ntalk}, systemd(service/socket)"

# [inetd] /etc/inetd.conf 내 서비스 활성화 여부 확인(주석 제외)
if [ -f "/etc/inetd.conf" ]; then
  for svc in "${SERVICES[@]}"; do
    if grep -v "^[[:space:]]*#" /etc/inetd.conf 2>/dev/null | grep -qE "^[[:space:]]*${svc}\b"; then
      VULNERABLE=1
      FINDINGS="${FINDINGS}/etc/inetd.conf에서 ${svc} 서비스 라인이 주석 처리되지 않아 활성화되어 있습니다. "
    fi
  done
fi

# [xinetd] /etc/xinetd.d/ 내 disable=no 설정 여부 확인
if [ -d "/etc/xinetd.d" ]; then
  for svc in "${SERVICES[@]}"; do
    if [ -f "/etc/xinetd.d/${svc}" ]; then
      if grep -qiE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no\b" "/etc/xinetd.d/${svc}" 2>/dev/null; then
        VULNERABLE=1
        FINDINGS="${FINDINGS}/etc/xinetd.d/${svc}에서 disable=no로 설정되어 있어 활성화되어 있습니다. "
      fi
    fi
  done
fi

# [systemd] 활성(active) 뿐 아니라 enabled(부팅 자동기동)까지 점검 + socket 포함
if command -v systemctl >/dev/null 2>&1; then
  # 1) enabled 여부(list-unit-files/is-enabled) 점검
  for unit in "${SYSTEMD_UNITS[@]}"; do
    # unit 파일이 존재하는 경우만 의미 있게 체크
    if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$unit"; then
      if systemctl is-enabled --quiet "$unit" 2>/dev/null; then
        VULNERABLE=1
        FINDINGS="${FINDINGS}systemd에서 ${unit} 유닛이 enabled(부팅 시 자동기동) 상태라 취약합니다. "
      fi
      if systemctl is-active --quiet "$unit" 2>/dev/null; then
        VULNERABLE=1
        FINDINGS="${FINDINGS}systemd에서 ${unit} 유닛이 active(현재 동작) 상태라 취약합니다. "
      fi
    fi
  done
fi

# 결과 판단용 EVIDENCE(내부용)
if [ $VULNERABLE -eq 1 ]; then
  STATUS="FAIL"
else
  STATUS="PASS"
fi

# 3. 최종 출력 형식(scan_history)

SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

CHECK_COMMAND="( [ -f /etc/inetd.conf ] && grep -v '^[[:space:]]*#' /etc/inetd.conf | egrep '^[[:space:]]*(tftp|talk|ntalk)\\b' ); ( [ -d /etc/xinetd.d ] && egrep -i '^[[:space:]]*disable[[:space:]]*=[[:space:]]*no\\b' /etc/xinetd.d/{tftp,talk,ntalk} 2>/dev/null ); ( command -v systemctl >/dev/null 2>&1 && ( systemctl list-unit-files 2>/dev/null | egrep '^(tftp\\.(service|socket)|talk(.*)\\.service|ntalk(.*)\\.service)[[:space:]]' ; for u in tftp.service tftp.socket talk.service ntalk.service talkd.service ntalkd.service; do systemctl is-enabled \"\$u\" 2>/dev/null | sed \"s/^/\$u enabled: /\"; systemctl is-active \"\$u\" 2>/dev/null | sed \"s/^/\$u active: /\"; done ) )"

REASON_LINE=""
DETAIL_CONTENT=""

if [ "$STATUS" = "PASS" ]; then
  REASON_LINE="${CHECK_PATHS}에서 tftp/talk/ntalk 관련 설정이 비활성화(주석 처리/disable!=no/systemd enabled·active 아님)되어 있어 이 항목에 대한 보안 위협이 없습니다."
  DETAIL_CONTENT="(점검 경로) ${CHECK_PATHS}\n(판정 결과) inetd.conf에 활성 라인이 없고, xinetd에서 disable=no 설정이 없으며, systemd(service/socket)에서 enabled 또는 active 상태의 관련 유닛이 확인되지 않았습니다."
else
  REASON_LINE="${CHECK_PATHS}에서 tftp/talk/ntalk 관련 설정이 활성화되어 있어 취약합니다."
  DETAIL_CONTENT="(점검 경로) ${CHECK_PATHS}\n(판정 근거) ${FINDINGS}\n(간단 조치) 1) /etc/inetd.conf 해당 서비스 라인 주석 처리 후 inetd 재기동 2) /etc/xinetd.d/{tftp,talk,ntalk}에서 disable=yes로 변경 후 xinetd 재기동 3) systemd 사용 시: systemctl disable --now <service|socket> 로 중지 및 비활성화 후 재점검"
fi

escape_json_str() {
  # 백슬래시 -> \\ , 줄바꿈 -> \n, 따옴표 -> \"
  printf '%s' "$1" | sed ':a;N;$!ba;s/\\/\\\\/g;s/\n/\\n/g;s/"/\\"/g'
}

TARGET_FILE_FOR_EVIDENCE="$CHECK_PATHS"

RAW_EVIDENCE_JSON="$(cat <<EOF
{
  "command":"$(escape_json_str "$CHECK_COMMAND")",
  "detail":"$(escape_json_str "${REASON_LINE}\n${DETAIL_CONTENT}")",
  "target_file":"$(escape_json_str "$TARGET_FILE_FOR_EVIDENCE")"
}
EOF
)"

RAW_EVIDENCE_ESCAPED="$(escape_json_str "$RAW_EVIDENCE_JSON")"

# JSON 출력 직전 빈 줄(프로젝트 규칙)
echo ""
cat <<EOF
{
  "item_code": "$ID",
  "status": "$STATUS",
  "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
  "scan_date": "$SCAN_DATE"
}
EOF
