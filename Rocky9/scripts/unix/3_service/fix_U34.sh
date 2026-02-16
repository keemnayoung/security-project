#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.1
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-34
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : Finger 서비스 비활성화
# @Description : Finger 서비스 비활성화 여부 보완
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-34 Finger 서비스 비활성화

# 기본 변수
ID="U-34"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND='(command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -Ei "^(finger|fingerd)\.(service|socket)[[:space:]]") || echo "systemd_units_not_found"; ( [ -f /etc/inetd.conf ] && grep -nEv "^[[:space:]]*#" /etc/inetd.conf 2>/dev/null | grep -nE "^[[:space:]]*finger([[:space:]]|$)" ) || echo "inetd_no_active_finger"; ( [ -f /etc/xinetd.d/finger ] && grep -nEv "^[[:space:]]*#" /etc/xinetd.d/finger 2>/dev/null | grep -niE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*(no|yes)([[:space:]]|$)" ) || echo "xinetd_finger_not_found_or_no_disable"'

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE="/etc/inetd.conf
/etc/xinetd.d/finger
systemd(finger/fingerd)"

ACTION_ERR_LOG=""

# (필수) root 권한 권장 안내(실패 원인 명확화용)
if [ "$(id -u)" -ne 0 ]; then
  ACTION_ERR_LOG="(주의) root 권한이 아니면 sed/systemctl 조치가 실패할 수 있습니다."
fi

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
MODIFIED=0

# 로그 누적 함수
append_err() {
  if [ -n "$ACTION_ERR_LOG" ]; then
    ACTION_ERR_LOG="${ACTION_ERR_LOG}\n$1"
  else
    ACTION_ERR_LOG="$1"
  fi
}

append_detail() {
  if [ -n "$DETAIL_CONTENT" ]; then
    DETAIL_CONTENT="${DETAIL_CONTENT}\n$1"
  else
    DETAIL_CONTENT="$1"
  fi
}

# systemd 조치(있을 때만): stop/disable/mask
disable_systemd_unit_if_exists() {
  local unit="$1"
  command -v systemctl >/dev/null 2>&1 || return 0

  # unit 존재 확인(없으면 통과)
  systemctl list-unit-files 2>/dev/null | grep -qiE "^${unit}[[:space:]]" || return 0

  # stop/disable/mask는 실패해도 로그만 남기고 진행
  systemctl stop "$unit" 2>/dev/null || append_err "systemctl stop ${unit} 실패"
  systemctl disable "$unit" 2>/dev/null || append_err "systemctl disable ${unit} 실패"
  systemctl mask "$unit" 2>/dev/null || append_err "systemctl mask ${unit} 실패"
  MODIFIED=1
}

# xinetd restart(있을 때만)
restart_xinetd_if_exists() {
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl list-unit-files 2>/dev/null | grep -qE "^xinetd\.service" || return 0
  systemctl restart xinetd 2>/dev/null || append_err "systemctl restart xinetd 실패"
}

# inetd restart(있을 때만) - 환경별 inetd/inetd.service 차이 방어
restart_inetd_if_exists() {
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl list-unit-files 2>/dev/null | grep -qE "^inetd\.service" || return 0
  systemctl restart inetd 2>/dev/null || append_err "systemctl restart inetd 실패"
}

############################
# 1) systemd 기반 finger/fingerd 비활성화
############################
disable_systemd_unit_if_exists "finger.socket"
disable_systemd_unit_if_exists "finger.service"
disable_systemd_unit_if_exists "fingerd.service"
disable_systemd_unit_if_exists "fingerd.socket"

############################
# 2) inetd: /etc/inetd.conf에서 finger 활성 라인 주석 처리
############################
if [ -f "/etc/inetd.conf" ]; then
  if grep -Ev "^[[:space:]]*#" /etc/inetd.conf 2>/dev/null | grep -qE "^[[:space:]]*finger([[:space:]]|$)"; then
    cp -a /etc/inetd.conf "/etc/inetd.conf.bak_${TIMESTAMP}" 2>/dev/null || append_err "inetd.conf 백업 실패"

    # [보완] 이미 주석(#)인 라인은 제외하고, 활성 finger 라인만 주석 처리
    # - 라인 시작에 공백이 있을 수 있으므로 ^[[:space:]]*finger 를 대상으로 함
    sed -i -E '/^[[:space:]]*#/! s/^([[:space:]]*finger([[:space:]]|$))/#\1/' /etc/inetd.conf 2>/dev/null \
      || append_err "inetd.conf finger 라인 주석 처리 실패"

    MODIFIED=1
    restart_inetd_if_exists
  fi
fi

############################
# 3) xinetd: /etc/xinetd.d/finger disable=yes 표준화(없으면 추가)
############################
if [ -f "/etc/xinetd.d/finger" ]; then
  cp -a /etc/xinetd.d/finger "/etc/xinetd.d/finger.bak_${TIMESTAMP}" 2>/dev/null || append_err "xinetd finger 파일 백업 실패"

  # [보완] disable 라인이 존재하면 값이 무엇이든 disable = yes로 표준화(대소문자/공백/기타값 방어)
  if grep -nEv "^[[:space:]]*#" /etc/xinetd.d/finger 2>/dev/null | grep -qiE "^[[:space:]]*disable[[:space:]]*="; then
    sed -i -E 's/^[[:space:]]*disable[[:space:]]*=.*/\tdisable = yes/I' /etc/xinetd.d/finger 2>/dev/null \
      || append_err "xinetd finger disable 라인 표준화(disable=yes) 실패"
    MODIFIED=1
    restart_xinetd_if_exists
  else
    # [보완] disable 라인이 없으면 service finger 블록 내에 추가 시도
    # 1) service finger { ... } 구조가 있으면 마지막 '}' 직전에 삽입
    if grep -qiE "^[[:space:]]*service[[:space:]]+finger([[:space:]]|\{)" /etc/xinetd.d/finger 2>/dev/null && \
       grep -qE "^[[:space:]]*\}[[:space:]]*$" /etc/xinetd.d/finger 2>/dev/null; then
      sed -i -E '0,/^[[:space:]]*\}[[:space:]]*$/ { s/^[[:space:]]*\}[[:space:]]*$/\tdisable = yes\n}/ }' /etc/xinetd.d/finger 2>/dev/null \
        || append_err "xinetd finger disable=yes 블록 삽입 실패"
      MODIFIED=1
      restart_xinetd_if_exists
    else
      # 2) 구조 파악이 어려우면 파일 끝에 추가
      echo -e "\n\tdisable = yes" >> /etc/xinetd.d/finger 2>/dev/null \
        || append_err "xinetd finger disable=yes 파일 끝 추가 실패"
      MODIFIED=1
      restart_xinetd_if_exists
    fi
  fi
fi

############################
# 4) 조치 후 검증
############################
FINGER_ACTIVE=0

# inetd 활성 finger 존재하면 취약
if [ -f "/etc/inetd.conf" ]; then
  if grep -Ev "^[[:space:]]*#" /etc/inetd.conf 2>/dev/null | grep -qE "^[[:space:]]*finger([[:space:]]|$)"; then
    FINGER_ACTIVE=1
  fi
fi

# xinetd: 파일이 존재할 때 disable=yes가 확인되지 않으면 취약(보수적 판단)
if [ -f "/etc/xinetd.d/finger" ]; then
  if ! grep -Ev "^[[:space:]]*#" /etc/xinetd.d/finger 2>/dev/null | grep -qiE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*yes([[:space:]]|$)"; then
    FINGER_ACTIVE=1
  fi
fi

# systemd unit이 enabled/active면 취약
SYSTEMD_FINGER_BAD=0
if command -v systemctl >/dev/null 2>&1; then
  for u in finger.socket finger.service fingerd.service fingerd.socket; do
    if systemctl list-unit-files 2>/dev/null | grep -qiE "^${u}[[:space:]]"; then
      if systemctl is-enabled "$u" 2>/dev/null | grep -qiE "enabled"; then
        SYSTEMD_FINGER_BAD=1
      fi
      if systemctl is-active "$u" 2>/dev/null | grep -qiE "active"; then
        SYSTEMD_FINGER_BAD=1
      fi
    fi
  done
fi

# detail 근거 수집(조치 후 상태만)
append_detail "inetd_active_finger=$( [ -f /etc/inetd.conf ] && (grep -Ev '^[[:space:]]*#' /etc/inetd.conf 2>/dev/null | grep -nE '^[[:space:]]*finger([[:space:]]|$)' | head -n 3) || echo 'inetd_conf_not_found' )"
append_detail "xinetd_finger_disable=$( [ -f /etc/xinetd.d/finger ] && (grep -nEv '^[[:space:]]*#' /etc/xinetd.d/finger 2>/dev/null | grep -niE '^[[:space:]]*disable[[:space:]]*=' | head -n 3) || echo 'xinetd_finger_not_found' )"

if command -v systemctl >/dev/null 2>&1; then
  append_detail "systemd_units=$(systemctl list-unit-files 2>/dev/null | grep -Ei '^(finger|fingerd)\.(service|socket)[[:space:]]' || echo 'systemd_units_not_found')"
  for u in finger.socket finger.service fingerd.service fingerd.socket; do
    if systemctl list-unit-files 2>/dev/null | grep -qiE "^${u}[[:space:]]"; then
      append_detail "${u}_is_enabled=$(systemctl is-enabled "$u" 2>/dev/null || echo 'unknown')"
      append_detail "${u}_is_active=$(systemctl is-active "$u" 2>/dev/null || echo 'unknown')"
    fi
  done
else
  append_detail "systemctl_not_found"
fi

# 최종 판정
if [ "$FINGER_ACTIVE" -eq 0 ] && [ "$SYSTEMD_FINGER_BAD" -eq 0 ]; then
  IS_SUCCESS=1
  if [ "$MODIFIED" -eq 1 ]; then
    REASON_LINE="Finger 서비스가 비활성화되도록 설정이 변경되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
  else
    REASON_LINE="Finger 서비스가 이미 비활성화 상태로 유지되어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
  fi
else
  IS_SUCCESS=0
  REASON_LINE="조치를 수행했으나 Finger 서비스 관련 설정이 여전히 활성화 상태이거나 검증 기준을 충족하지 못해 조치가 완료되지 않았습니다."
fi

if [ -n "$ACTION_ERR_LOG" ]; then
  DETAIL_CONTENT="$DETAIL_CONTENT\n$ACTION_ERR_LOG"
fi

# raw_evidence 구성(조치 이후 상태만)
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