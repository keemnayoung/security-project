#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-44
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : tftp, talk 서비스 비활성화
# @Description : tftp, talk, ntalk 서비스의 활성화 여부 점검 
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-44 tftp, talk 서비스 비활성화

# 1. 항목 정보 정의
ID="U-44"
CATEGORY="서비스 관리"
TITLE="tftp, talk 서비스 비활성화"
IMPORTANCE="상"
TARGET_FILE="N/A"

# 2. 기본 변수(프로젝트 조치 스크립트 표준)
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND=""
REASON_LINE=""
DETAIL_CONTENT=""
ACTION_ERR_LOG=""

SERVICES=("tftp" "talk" "ntalk")

# systemd에서 흔한 유닛 후보(서비스/소켓)
SYSTEMD_UNITS_CANDIDATES=(
  "tftp.service"
  "tftp.socket"
  "talk.service"
  "ntalk.service"
  "talkd.service"
  "ntalkd.service"
)

# 유틸: JSON escape (백슬래시/줄바꿈/따옴표)
escape_json_str() {
  printf '%s' "$1" | sed ':a;N;$!ba;s/\\/\\\\/g;s/\n/\\n/g;s/"/\\"/g'
}

# 유틸: systemd unit 존재 여부
unit_exists() {
  local u="$1"
  command -v systemctl >/dev/null 2>&1 || return 1
  systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$u"
}

# -----------------------------
# 조치 1) inetd: /etc/inetd.conf 주석 처리 + 재시작 시도
# -----------------------------
INETD_CHANGED=0
if [ -f "/etc/inetd.conf" ]; then
  for svc in "${SERVICES[@]}"; do
    if grep -v "^[[:space:]]*#" /etc/inetd.conf 2>/dev/null | grep -qE "^[[:space:]]*${svc}\b"; then
      INETD_CHANGED=1
      break
    fi
  done

  if [ $INETD_CHANGED -eq 1 ]; then
    cp -p /etc/inetd.conf "/etc/inetd.conf.bak_$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true

    # 이미 주석인 라인은 건드리지 않고, 시작이 서비스명인 활성 라인만 주석 처리
    for svc in "${SERVICES[@]}"; do
      sed -i -E "s/^([[:space:]]*)(${svc}\b)/#\1\2/" /etc/inetd.conf 2>/dev/null || true
    done

    # 재시작(가능한 경우만)
    systemctl restart inetd 2>/dev/null || killall -HUP inetd 2>/dev/null || true
  fi
fi

# -----------------------------
# 조치 2) xinetd: disable=no -> yes, disable 라인 없으면 yes 삽입 + 재시작 시도
# -----------------------------
XINETD_CHANGED=0
if [ -d "/etc/xinetd.d" ]; then
  for svc in "${SERVICES[@]}"; do
    CONF="/etc/xinetd.d/${svc}"
    if [ -f "$CONF" ]; then
      # backup
      cp -p "$CONF" "${CONF}.bak_$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true

      if grep -qiE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no\b" "$CONF" 2>/dev/null; then
        sed -i -E 's/^[[:space:]]*disable[[:space:]]*=[[:space:]]*no\b/        disable = yes/I' "$CONF" 2>/dev/null || true
        XINETD_CHANGED=1
      else
        # disable 라인이 아예 없으면(최소 보완) disable=yes를 블록 내에 삽입
        if ! grep -qiE "^[[:space:]]*disable[[:space:]]*=" "$CONF" 2>/dev/null; then
          if grep -q "}" "$CONF" 2>/dev/null; then
            sed -i -E '0,/}/s/}/        disable = yes\n}/' "$CONF" 2>/dev/null || true
          else
            printf '\n        disable = yes\n' >> "$CONF" 2>/dev/null || true
          fi
          XINETD_CHANGED=1
        fi
      fi
    fi
  done

  if [ $XINETD_CHANGED -eq 1 ]; then
    systemctl restart xinetd 2>/dev/null || true
  fi
fi

# -----------------------------
# 조치 3) systemd: service+socket 포함, enabled/active 모두 stop+disable
# -----------------------------
SYSTEMD_CHANGED=0
SYSTEMD_FOUND_UNITS=""

if command -v systemctl >/dev/null 2>&1; then
  # list-unit-files 기반으로 실제 존재하는 유닛만 추출(서비스/소켓)
  for u in "${SYSTEMD_UNITS_CANDIDATES[@]}"; do
    if unit_exists "$u"; then
      SYSTEMD_FOUND_UNITS="${SYSTEMD_FOUND_UNITS}${u} "
    fi
  done

  # 추가로 이름에 tftp/talk/ntalk가 포함된 유닛 파일도 수집(최소 확장)
  EXTRA_UNITS=$(systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -E '(^|/)(tftp|talk|ntalk).*\.((service)|(socket))$' | tr '\n' ' ')
  SYSTEMD_FOUND_UNITS="${SYSTEMD_FOUND_UNITS}${EXTRA_UNITS}"

  # 중복 제거
  SYSTEMD_FOUND_UNITS=$(printf "%s\n" $SYSTEMD_FOUND_UNITS 2>/dev/null | awk 'NF{seen[$0]=1} END{for(k in seen) print k}' | tr '\n' ' ')

  for u in $SYSTEMD_FOUND_UNITS; do
    # active면 stop, enabled면 disable (둘 다 시도)
    if systemctl is-active --quiet "$u" 2>/dev/null; then
      systemctl stop "$u" 2>/dev/null || true
      SYSTEMD_CHANGED=1
    fi
    if systemctl is-enabled --quiet "$u" 2>/dev/null; then
      systemctl disable "$u" 2>/dev/null || true
      SYSTEMD_CHANGED=1
    fi
  done
fi

# -----------------------------
# 최종 검증(조치 이후 상태만 수집)
# -----------------------------
AFTER_INETD_ACTIVE=""
AFTER_XINETD_DISABLE_NO=""
AFTER_SYSTEMD_BAD=""

# inetd after
if [ -f "/etc/inetd.conf" ]; then
  AFTER_INETD_ACTIVE=$(grep -nEv '^[[:space:]]*#|^[[:space:]]*$' /etc/inetd.conf 2>/dev/null | grep -nE '^[[:space:]]*(tftp|talk|ntalk)\b' 2>/dev/null)
fi

# xinetd after
if [ -d "/etc/xinetd.d" ]; then
  AFTER_XINETD_DISABLE_NO=$(grep -nEi '^[[:space:]]*disable[[:space:]]*=[[:space:]]*no\b' /etc/xinetd.d/{tftp,talk,ntalk} 2>/dev/null)
fi

# systemd after (enabled or active) - service/socket 모두
if command -v systemctl >/dev/null 2>&1; then
  for u in $SYSTEMD_FOUND_UNITS; do
    if systemctl is-enabled --quiet "$u" 2>/dev/null; then
      AFTER_SYSTEMD_BAD="${AFTER_SYSTEMD_BAD}${u}(enabled) "
    fi
    if systemctl is-active --quiet "$u" 2>/dev/null; then
      AFTER_SYSTEMD_BAD="${AFTER_SYSTEMD_BAD}${u}(active) "
    fi
  done
fi

# 성공/실패 판정
if [ -n "$AFTER_INETD_ACTIVE" ] || [ -n "$AFTER_XINETD_DISABLE_NO" ] || [ -n "$AFTER_SYSTEMD_BAD" ]; then
  IS_SUCCESS=0
  REASON_LINE="tftp/talk/ntalk 비활성화 조치가 일부 완료되지 않았습니다. 조치 후에도 활성 설정이 남아있어 중단합니다."
else
  IS_SUCCESS=1
  REASON_LINE="tftp/talk/ntalk 서비스가 조치 후 inetd/xinetd/systemd 어디에서도 활성화되어 있지 않아 조치가 완료되었습니다."
fi

# 조치 로그(요약)
ACTION_LOG=""
[ $INETD_CHANGED -eq 1 ] && ACTION_LOG="${ACTION_LOG}inetd.conf 주석 처리 적용. "
[ $XINETD_CHANGED -eq 1 ] && ACTION_LOG="${ACTION_LOG}xinetd disable=yes 적용. "
[ $SYSTEMD_CHANGED -eq 1 ] && ACTION_LOG="${ACTION_LOG}systemd 유닛 stop/disable 적용. "
[ -z "$ACTION_LOG" ] && ACTION_LOG="변경할 활성 설정이 확인되지 않아 추가 조치 없이 종료했습니다."

# detail(조치 이후 설정만)
DETAIL_CONTENT="(조치 요약) ${ACTION_LOG}
(조치 후 확인) /etc/inetd.conf 활성 라인: ${AFTER_INETD_ACTIVE:-없음}
(조치 후 확인) /etc/xinetd.d disable=no: ${AFTER_XINETD_DISABLE_NO:-없음}
(조치 후 확인) systemd enabled/active: ${AFTER_SYSTEMD_BAD:-없음}"

# raw_evidence.command는 재검증 커맨드로 고정
CHECK_COMMAND="( [ -f /etc/inetd.conf ] && grep -nEv '^[[:space:]]*#|^[[:space:]]*$' /etc/inetd.conf | grep -nE '^[[:space:]]*(tftp|talk|ntalk)\\b' || true ); ( [ -d /etc/xinetd.d ] && grep -nEi '^[[:space:]]*disable[[:space:]]*=[[:space:]]*no\\b' /etc/xinetd.d/{tftp,talk,ntalk} 2>/dev/null || true ); ( command -v systemctl >/dev/null 2>&1 && ( systemctl list-unit-files 2>/dev/null | egrep '(^|/)(tftp|talk|ntalk).*\\.(service|socket)[[:space:]]' || true; for u in tftp.service tftp.socket talk.service ntalk.service talkd.service ntalkd.service; do systemctl is-enabled \"\$u\" 2>/dev/null | sed \"s/^/\$u enabled: /\"; systemctl is-active \"\$u\" 2>/dev/null | sed \"s/^/\$u active: /\"; done ) )"

TARGET_FILE_FOR_EVIDENCE="/etc/inetd.conf, /etc/xinetd.d/{tftp,talk,ntalk}, systemd(service/socket)"

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
  "action_date": "$ACTION_DATE",
  "is_success": $IS_SUCCESS,
  "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
}
EOF