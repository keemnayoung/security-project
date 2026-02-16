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

DOS_SERVICES=("echo" "discard" "daytime" "chargen")

TARGET_FILE="/etc/inetd.conf
/etc/xinetd.d/(echo|discard|daytime|chargen)
systemd(echo|discard|daytime|chargen 및 -dgram/-stream 변형 unit)"

CHECK_COMMAND='
# [inetd]
[ -f /etc/inetd.conf ] && grep -nEv "^[[:space:]]*#" /etc/inetd.conf 2>/dev/null | egrep -n "^[[:space:]]*(echo|discard|daytime|chargen)([[:space:]]|$)" || echo "inetd_conf_not_found_or_no_active";
# [xinetd]
for f in /etc/xinetd.d/echo /etc/xinetd.d/discard /etc/xinetd.d/daytime /etc/xinetd.d/chargen; do
  [ -f "$f" ] && echo "xinetd_file:$f" && grep -nEv "^[[:space:]]*#" "$f" 2>/dev/null | grep -niE "^[[:space:]]*disable([[:space:]]*=)?[[:space:]]*" | head -n 2 || true;
done;
# [systemd]
(command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files --type=service --type=socket 2>/dev/null | grep -Ei "^(echo|discard|daytime|chargen)(-dgram|-stream)?\.(service|socket)[[:space:]]") || echo "systemd_units_not_found";
(command -v systemctl >/dev/null 2>&1 && systemctl list-units --type=service --type=socket 2>/dev/null | grep -Ei "^(echo|discard|daytime|chargen)(-dgram|-stream)?\.(service|socket)[[:space:]]") || true
'

REASON_LINE=""
DETAIL_CONTENT=""
FOUND_LIST=()

add_found() {
  local msg="$1"
  [ -n "$msg" ] && FOUND_LIST+=("$msg")
}

# 1) inetd: /etc/inetd.conf 주석 제외 후 서비스 라인 존재 시 취약
if [ -f "/etc/inetd.conf" ]; then
  for svc in "${DOS_SERVICES[@]}"; do
    if grep -Ev "^[[:space:]]*#" /etc/inetd.conf 2>/dev/null | grep -qE "^[[:space:]]*${svc}([[:space:]]|$)"; then
      STATUS="FAIL"
      add_found "/etc/inetd.conf: ${svc} 활성 라인 존재(주석 제외)"
    fi
  done
fi

# 2) xinetd: disable=no 형태면 취약(대소문자/형식 다양성 대응)
if [ -d "/etc/xinetd.d" ]; then
  for svc in "${DOS_SERVICES[@]}"; do
    f="/etc/xinetd.d/$svc"
    if [ -f "$f" ]; then
      if grep -Ev "^[[:space:]]*#" "$f" 2>/dev/null | grep -qiE "^[[:space:]]*disable([[:space:]]*=)?[[:space:]]*no([[:space:]]|$)"; then
        STATUS="FAIL"
        add_found "$f: disable=no(서비스 활성)"
      fi
    fi
  done
fi

# 3) systemd: 해당 unit이 active 또는 enabled면 취약 (unit 후보: 기본 + -dgram/-stream)
SYSTEMD_FOUND=""
if command -v systemctl >/dev/null 2>&1; then
  for base in "${DOS_SERVICES[@]}"; do
    for suf in "" "-dgram" "-stream"; do
      for typ in "socket" "service"; do
        unit="${base}${suf}.${typ}"

        # unit 존재 여부(없으면 스킵)
        if systemctl list-unit-files --type=service --type=socket 2>/dev/null | grep -qiE "^${unit}[[:space:]]"; then
          if systemctl is-active "$unit" >/dev/null 2>&1; then
            SYSTEMD_FOUND="${SYSTEMD_FOUND}${unit}(active) "
          else
            EN_STATE="$(systemctl is-enabled "$unit" 2>/dev/null || true)"
            if [ "$EN_STATE" = "enabled" ] || [ "$EN_STATE" = "enabled-runtime" ]; then
              SYSTEMD_FOUND="${SYSTEMD_FOUND}${unit}(${EN_STATE}) "
            fi
          fi
        fi
      done
    done
  done
fi

if [ -n "$SYSTEMD_FOUND" ]; then
  STATUS="FAIL"
  add_found "systemd: ${SYSTEMD_FOUND% }"
fi

# 결과 정리 (요구 문구 반영)
if [ "$STATUS" = "PASS" ]; then
  REASON_LINE="(/etc/inetd.conf, /etc/xinetd.d, systemd)에서 DoS 공격에 취약한 서비스(echo/discard/daytime/chargen)가 비활성화(주석 처리 또는 disable!=no, 관련 unit 비활성) 상태로 확인되어 이 항목에 대한 보안 위협이 없습니다."
  DETAIL_CONTENT="확인 결과: inetd 활성 라인 없음, xinetd에서 disable=no 미검출, systemd 관련 socket/service 활성/enable 미검출"
else
  REASON_LINE="(/etc/inetd.conf, /etc/xinetd.d, systemd)에서 DoS 공격에 취약한 서비스(echo/discard/daytime/chargen)가 활성 상태로 확인되어 취약합니다. 조치: inetd는 해당 라인 주석 처리 후 inetd 재시작, xinetd는 disable=yes로 변경 후 xinetd 재시작, systemd는 관련 socket/service stop 및 disable 하십시오."
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