#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-34
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : Finger 서비스 비활성화
# @Description : Finger 서비스 비활성화 여부 점검
# @Criteria_Good : Finger 서비스가 비활성화된 경우
# @Criteria_Bad : Finger 서비스가 활성화된 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-34 Finger 서비스 비활성화


# 기본 변수
ID="U-34"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

INETD_CONF="/etc/inetd.conf"
XINETD_FINGER="/etc/xinetd.d/finger"

TARGET_FILE="$INETD_CONF $XINETD_FINGER finger.socket finger.service"

CHECK_COMMAND='( [ -f /etc/inetd.conf ] && grep -nEv "^[[:space:]]*#" /etc/inetd.conf | grep -nE "^[[:space:]]*finger([[:space:]]|$)" || echo "inetd_finger_not_found_or_commented" ); ( [ -f /etc/xinetd.d/finger ] && grep -nEv "^[[:space:]]*#" /etc/xinetd.d/finger | grep -niE "^[[:space:]]*disable[[:space:]]*=" || echo "xinetd_finger_disable_line_not_found_or_file_missing" ); ( command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | awk '\''tolower($1) ~ /^finger\.(socket|service)$/ {print $1,$2}'\'' || echo "systemd_finger_unit_not_found" ); ( command -v systemctl >/dev/null 2>&1 && (systemctl is-enabled finger.socket 2>/dev/null || true) && (systemctl is-active finger.socket 2>/dev/null || true) && (systemctl is-enabled finger.service 2>/dev/null || true) && (systemctl is-active finger.service 2>/dev/null || true) || echo "systemctl_not_available" )'

REASON_LINE=""
DETAIL_CONTENT=""

VULN=0
DETAIL_LINES=""

# 1) inetd 기반 점검: finger 라인이 주석 없이 존재하면 취약
if [ -f "$INETD_CONF" ]; then
  INETD_ACTIVE_LINES=$(grep -nEv "^[[:space:]]*#" "$INETD_CONF" 2>/dev/null | grep -nE "^[[:space:]]*finger([[:space:]]|$)" || true)
  if [ -n "$INETD_ACTIVE_LINES" ]; then
    VULN=1
    DETAIL_LINES+="$INETD_CONF: finger 서비스가 주석 처리되지 않고 설정되어 있습니다.\n"
    DETAIL_LINES+="(활성 라인)\n$INETD_ACTIVE_LINES\n"
  else
    DETAIL_LINES+="$INETD_CONF: finger 서비스 활성 설정이 확인되지 않습니다(없음 또는 주석 처리).\n"
  fi
else
  DETAIL_LINES+="$INETD_CONF: 파일이 존재하지 않습니다.\n"
fi

# 2) xinetd 기반 점검:
#    - /etc/xinetd.d/finger 가 존재할 때 disable = yes 가 명시되어 있지 않으면 취약(= disable=no 또는 disable 미설정 포함)
if [ -f "$XINETD_FINGER" ]; then
  # 주석 제외한 disable 라인(마지막 기준)
  DISABLE_LINE_RAW=$(grep -nEv '^[[:space:]]*#' "$XINETD_FINGER" 2>/dev/null | tr -d '\r' < /etc/xinetd.d/finger | grep -nEv '^[[:space:]]*#' | grep -niE '[[:space:]]*disable[[:space:]]*=' | tail -n 1 || true)
  DISABLE_VAL=$(printf "%s" "$DISABLE_LINE_RAW" | awk -F= '{gsub(/[[:space:]]/,"",$2); print tolower($2)}')

  if [ -z "$DISABLE_LINE_RAW" ]; then
    # disable 라인이 없으면 기본값으로 활성화될 수 있으므로 취약 처리
    VULN=1
    DETAIL_LINES+="$XINETD_FINGER: disable 설정 라인이 없어 finger 서비스가 활성화될 수 있습니다(취약).\n"
    DETAIL_LINES+="(조치 권장) disable = yes 를 명시하세요.\n"
  else
    if [ "$DISABLE_VAL" = "yes" ]; then
      DETAIL_LINES+="$XINETD_FINGER: $DISABLE_LINE_RAW (비활성화 설정 확인).\n"
    else
      VULN=1
      DETAIL_LINES+="$XINETD_FINGER: $DISABLE_LINE_RAW (disable=yes가 아니어서 활성화 상태로 판단, 취약).\n"
      DETAIL_LINES+="(조치 권장) disable = yes 로 변경하세요.\n"
    fi
  fi
else
  DETAIL_LINES+="$XINETD_FINGER: 파일이 존재하지 않습니다.\n"
fi

# 3) systemd 유닛 기반 점검(환경에 따라 존재 가능): enabled/active면 취약
if command -v systemctl >/dev/null 2>&1; then
  # 유닛 존재 여부
  HAS_FINGER_UNIT=$(systemctl list-unit-files 2>/dev/null | awk 'tolower($1) ~ /^finger\.(socket|service)$/{print $1}' | head -n 1 || true)
  if [ -n "$HAS_FINGER_UNIT" ]; then
    for u in finger.socket finger.service; do
      if systemctl list-unit-files 2>/dev/null | awk '{print tolower($1)}' | grep -qx "$(echo "$u" | tr 'A-Z' 'a-z')"; then
        ENA=$(systemctl is-enabled "$u" 2>/dev/null || echo "unknown")
        ACT=$(systemctl is-active "$u" 2>/dev/null || echo "unknown")
        DETAIL_LINES+="systemd: $u (is-enabled=$ENA, is-active=$ACT)\n"
        if [ "$ENA" = "enabled" ] || [ "$ACT" = "active" ]; then
          VULN=1
        fi
      fi
    done
  else
    DETAIL_LINES+="systemd: finger.socket/finger.service 유닛이 확인되지 않습니다.\n"
  fi
else
  DETAIL_LINES+="systemctl: 명령을 사용할 수 없습니다.\n"
fi

# 최종 판정 및 문구(요청하신 형태)
if [ "$VULN" -eq 1 ]; then
  STATUS="FAIL"
  REASON_LINE="(취약) $INETD_CONF 또는 $XINETD_FINGER 또는 systemd에서 Finger 서비스가 활성화(또는 활성화될 수 있도록) 설정되어 있어 취약합니다. 조치: inetd는 finger 라인을 주석 처리하고, xinetd는 $XINETD_FINGER에 disable = yes 로 설정 후 xinetd를 재시작(systemctl restart xinetd)하세요."
else
  STATUS="PASS"
  REASON_LINE="(양호) $INETD_CONF 및 $XINETD_FINGER, systemd에서 Finger 서비스가 비활성화(또는 미구성)로 설정되어 있어 이 항목에 대한 보안 위협이 없습니다."
fi

# detail 정리(끝 공백 제거)
DETAIL_CONTENT="$(printf "%b" "$DETAIL_LINES" | sed 's/[[:space:]]*$//')"

# raw_evidence 구성 (첫 줄: 평가 이유 / 다음 줄부터: 현재 설정값)
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE
$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

# JSON escape 처리 (따옴표, 줄바꿈)
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/"/\\"/g' \
  | sed ':a;N;$!ba;s/\n/\\n/g')

# scan_history 저장용 JSON 출력 (JSON 직전 공백 라인 1줄 필수)
echo ""
cat <<EOF
{
  "item_code": "$ID",
  "status": "$STATUS",
  "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
  "scan_date": "$SCAN_DATE"
}
EOF