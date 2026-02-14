#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-38
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : DoS 공격에 취약한 서비스 비활성화
# @Description : 사용하지 않는 DoS 공격에 취약한 서비스의 실행 여부 점검
# @Criteria_Good : DoS 공격에 취약한 서비스가 비활성화된 경우
# @Criteria_Bad : DoS 공격에 취약한 서비스가 활성화된 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-38 DoS 공격에 취약한 서비스 비활성화

# 기본 변수
ID="U-38"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/inetd.conf /etc/xinetd.d/(echo|discard|daytime|chargen) systemd"
CHECK_COMMAND='[ -f /etc/inetd.conf ] && grep -nEv "^[[:space:]]*#" /etc/inetd.conf | egrep -n "^[[:space:]]*(echo|discard|daytime|chargen)[[:space:]]" || echo "inetd_not_found_or_no_active_rules"; for f in /etc/xinetd.d/echo /etc/xinetd.d/discard /etc/xinetd.d/daytime /etc/xinetd.d/chargen; do [ -f "$f" ] && grep -nEv "^[[:space:]]*#" "$f" | grep -niE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no([[:space:]]|$)" && echo "ACTIVE:$f"; done; systemctl list-unit-files --type=service 2>/dev/null | grep -E "(^| )(echo|discard|daytime|chargen)@" || true; systemctl list-units --type=service 2>/dev/null | grep -E "(echo|discard|daytime|chargen)" || true'

DETAIL_CONTENT=""
REASON_LINE=""
FOUND_LIST=()

add_found() {
  local msg="$1"
  [ -n "$msg" ] && FOUND_LIST+=("$msg")
}

# DoS 취약 서비스 목록
DOS_SERVICES=("echo" "discard" "daytime" "chargen")

# 1) inetd(/etc/inetd.conf) : 주석 제외 후 해당 서비스 라인이 존재하면 취약
if [ -f "/etc/inetd.conf" ]; then
  for svc in "${DOS_SERVICES[@]}"; do
    if grep -Ev "^[[:space:]]*#" /etc/inetd.conf 2>/dev/null | grep -qE "^[[:space:]]*${svc}([[:space:]]|$)"; then
      STATUS="FAIL"
      add_found"/etc/inetd.conf: ${svc} 서비스 활성 라인 존재"
    fi
  done
fi

# 2) xinetd(/etc/xinetd.d/<svc>) : disable = no 이면 취약
if [ -d "/etc/xinetd.d" ]; then
  for svc in "${DOS_SERVICES[@]}"; do
    f="/etc/xinetd.d/$svc"
    if [ -f "$f" ]; then
      if grep -Ev "^[[:space:]]*#" "$f" 2>/dev/null | grep -qiE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no([[:space:]]|$)"; then
        STATUS="FAIL"
        add_found "$f: disable=no"
      fi
    fi
  done
fi

# 3) systemd : echo/discard/daytime/chargen 관련 소켓/서비스가 활성(loaded/active)면 취약
# (현장 OS/구성에 따라 서비스명이 다를 수 있어, 매칭 범위를 넓게 가져감)
SYSTEMD_ACTIVE=$(systemctl list-units --type=service --type=socket 2>/dev/null | grep -E "(echo|discard|daytime|chargen)" | awk '{print $1" "$4}' | head -n 20)
if [ -n "$SYSTEMD_ACTIVE" ]; then
  STATUS="FAIL"
  add_found "systemd: 관련 unit 활성/로딩 감지 -> $(echo "$SYSTEMD_ACTIVE" | tr '\n' '; ' | sed 's/; $//')"
fi

# 결과 정리
if [ "$STATUS" = "PASS" ]; then
  REASON_LINE="DoS 공격에 취약한 서비스(echo, discard, daytime, chargen)가 비활성화되어 서비스 거부(DoS) 공격에 악용될 가능성이 없으므로 이 항목에 대한 보안 위협이 없습니다."
  DETAIL_CONTENT="none"
else
  REASON_LINE="DoS 공격에 취약한 서비스(echo, discard, daytime, chargen)가 활성화되어 서비스 거부(DoS) 공격에 악용될 수 있으므로 취약합니다. 아래 항목을 비활성화(disable=yes 또는 관련 unit 중지/비활성)해야 합니다."
  DETAIL_CONTENT=$(printf "%s\n" "${FOUND_LIST[@]}")
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