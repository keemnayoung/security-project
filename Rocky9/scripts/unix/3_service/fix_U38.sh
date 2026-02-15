#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-38
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : DoS 공격에 취약한 서비스 비활성화
# @Description : 사용하지 않는 DoS 공격에 취약한 서비스의 실행 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-38 DoS 공격에 취약한 서비스 비활성화

# 기본 변수
ID="U-38"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

DOS_SERVICES=("echo" "discard" "daytime" "chargen")

CHECK_COMMAND='
( [ -f /etc/inetd.conf ] && grep -nEv "^[[:space:]]*#" /etc/inetd.conf 2>/dev/null | grep -nE "^[[:space:]]*(echo|discard|daytime|chargen)([[:space:]]|$)" ) || echo "inetd_no_active_dos_services";
for s in echo discard daytime chargen; do
  [ -f "/etc/xinetd.d/$s" ] && echo "xinetd_file:$s" && grep -nEv "^[[:space:]]*#" "/etc/xinetd.d/$s" 2>/dev/null | grep -niE "^[[:space:]]*disable[[:space:]]*=" | head -n 1 || true;
done;
(command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -Eqi "^(echo|discard|daytime|chargen)(-dgram|-stream)?\.(service|socket)[[:space:]]") || echo "systemd_units_not_found"
'

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE="/etc/inetd.conf
/etc/xinetd.d/(echo,discard,daytime,chargen)
systemd(echo/discard/daytime/chargen 및 -dgram/-stream 변형)"

ACTION_ERR_LOG=""

# (필수) root 권한 권장 안내(실패 원인 명확화용)
if [ "$(id -u)" -ne 0 ]; then
  ACTION_ERR_LOG="(주의) root 권한이 아니면 sed/systemctl 조치가 실패할 수 있습니다."
fi

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
MODIFIED=0

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

# inetd restart(있을 때만)
restart_inetd_if_exists() {
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl list-unit-files 2>/dev/null | grep -qE "^inetd\.service" || return 0
  systemctl restart inetd 2>/dev/null || append_err "systemctl restart inetd 실패"
}

# xinetd restart(있을 때만)
restart_xinetd_if_exists() {
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl list-unit-files 2>/dev/null | grep -qE "^xinetd\.service" || return 0
  systemctl restart xinetd 2>/dev/null || append_err "systemctl restart xinetd 실패"
}

# systemd 조치(있을 때만): stop/disable/mask
disable_systemd_unit_if_exists() {
  local unit="$1"
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl list-unit-files 2>/dev/null | grep -qiE "^${unit}[[:space:]]" || return 0

  systemctl stop "$unit" 2>/dev/null || append_err "systemctl stop ${unit} 실패"
  systemctl disable "$unit" 2>/dev/null || append_err "systemctl disable ${unit} 실패"
  systemctl mask "$unit" 2>/dev/null || append_err "systemctl mask ${unit} 실패"
  MODIFIED=1
}

########################################
# 1) inetd: /etc/inetd.conf DoS 서비스 활성 라인 주석 처리
########################################
if [ -f "/etc/inetd.conf" ]; then
  INETD_ACTIVE=0
  if grep -nEv "^[[:space:]]*#" /etc/inetd.conf 2>/dev/null | grep -qE "^[[:space:]]*(echo|discard|daytime|chargen)([[:space:]]|$)"; then
    INETD_ACTIVE=1
  fi

  if [ "$INETD_ACTIVE" -eq 1 ]; then
    cp -a /etc/inetd.conf "/etc/inetd.conf.bak_${TIMESTAMP}" 2>/dev/null || append_err "inetd.conf 백업 실패"
    for s in "${DOS_SERVICES[@]}"; do
      sed -i "s/^\([[:space:]]*${s}\([[:space:]]\|$\)\)/#\1/g" /etc/inetd.conf 2>/dev/null || true
    done
    MODIFIED=1
    restart_inetd_if_exists
  fi
fi

########################################
# 2) xinetd: disable=no -> disable=yes
########################################
XINETD_CHANGED=0
for s in "${DOS_SERVICES[@]}"; do
  if [ -f "/etc/xinetd.d/$s" ]; then
    if grep -Ev "^[[:space:]]*#" "/etc/xinetd.d/$s" 2>/dev/null | grep -qiE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no([[:space:]]|$)"; then
      cp -a "/etc/xinetd.d/$s" "/etc/xinetd.d/${s}.bak_${TIMESTAMP}" 2>/dev/null || append_err "/etc/xinetd.d/$s 백업 실패"
      sed -Ei 's/^([[:space:]]*disable[[:space:]]*=[[:space:]]*)[Nn][Oo]([[:space:]]*(#.*)?)?$/\1yes\2/' "/etc/xinetd.d/$s" 2>/dev/null \
        || append_err "/etc/xinetd.d/$s disable=yes 변경 실패"
      XINETD_CHANGED=1
      MODIFIED=1
    fi
  fi
done

if [ "$XINETD_CHANGED" -eq 1 ]; then
  restart_xinetd_if_exists
fi

########################################
# 3) systemd: DoS 서비스 유닛 비활성화(있을 때만)
#    (필수 보완) -dgram/-stream 변형 유닛 포함
########################################
for base in echo discard daytime chargen; do
  for suf in "" "-dgram" "-stream"; do
    disable_systemd_unit_if_exists "${base}${suf}.service"
    disable_systemd_unit_if_exists "${base}${suf}.socket"
  done
done

########################################
# 4) 조치 후 검증 + detail(현재/조치 후 상태만)
########################################
FAIL_FLAG=0

# inetd 활성 라인 남아있으면 실패
INETD_POST="inetd_conf_not_found"
if [ -f "/etc/inetd.conf" ]; then
  INETD_POST="$(grep -nEv '^[[:space:]]*#' /etc/inetd.conf 2>/dev/null | grep -nE '^[[:space:]]*(echo|discard|daytime|chargen)([[:space:]]|$)' | head -n 5)"
  [ -z "$INETD_POST" ] && INETD_POST="no_active_dos_services"
fi
[ "$INETD_POST" != "no_active_dos_services" ] && FAIL_FLAG=1

# xinetd disable=no 남아있으면 실패(파일 존재하는 것만 체크)
XINETD_BAD=0
for s in "${DOS_SERVICES[@]}"; do
  if [ -f "/etc/xinetd.d/$s" ]; then
    if grep -Ev "^[[:space:]]*#" "/etc/xinetd.d/$s" 2>/dev/null | grep -qiE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no([[:space:]]|$)"; then
      XINETD_BAD=1
    fi
  fi
done
[ "$XINETD_BAD" -eq 1 ] && FAIL_FLAG=1

# systemd enabled/active면 실패(필수 보완: -dgram/-stream 포함)
SYSTEMD_BAD=0
if command -v systemctl >/dev/null 2>&1; then
  for base in echo discard daytime chargen; do
    for suf in "" "-dgram" "-stream"; do
      for typ in service socket; do
        u="${base}${suf}.${typ}"
        if systemctl list-unit-files 2>/dev/null | grep -qiE "^${u}[[:space:]]"; then
          if systemctl is-enabled "$u" 2>/dev/null | grep -qiE "enabled"; then
            SYSTEMD_BAD=1
          fi
          if systemctl is-active "$u" 2>/dev/null | grep -qiE "active"; then
            SYSTEMD_BAD=1
          fi
        fi
      done
    done
  done
fi
[ "$SYSTEMD_BAD" -eq 1 ] && FAIL_FLAG=1

# detail(현재/조치 후 상태만)
append_detail "inetd_active_dos_services(after)=$INETD_POST"

XINETD_POST_SUMMARY=""
for s in "${DOS_SERVICES[@]}"; do
  if [ -f "/etc/xinetd.d/$s" ]; then
    line="$(grep -nEv '^[[:space:]]*#' "/etc/xinetd.d/$s" 2>/dev/null | grep -niE '^[[:space:]]*disable[[:space:]]*=' | head -n 1)"
    [ -z "$line" ] && line="disable_setting_not_found"
    XINETD_POST_SUMMARY="${XINETD_POST_SUMMARY}${s}:${line}; "
  fi
done
[ -z "$XINETD_POST_SUMMARY" ] && XINETD_POST_SUMMARY="no_xinetd_dos_service_files"
append_detail "xinetd_disable_settings(after)=$XINETD_POST_SUMMARY"

if command -v systemctl >/dev/null 2>&1; then
  units="$(systemctl list-unit-files 2>/dev/null | grep -Ei '^(echo|discard|daytime|chargen)(-dgram|-stream)?\.(service|socket)[[:space:]]' || echo 'systemd_units_not_found')"
  append_detail "systemd_units(after)=$units"

  for base in echo discard daytime chargen; do
    for suf in "" "-dgram" "-stream"; do
      for typ in service socket; do
        u="${base}${suf}.${typ}"
        if systemctl list-unit-files 2>/dev/null | grep -qiE "^${u}[[:space:]]"; then
          append_detail "${u}_is_enabled(after)=$(systemctl is-enabled "$u" 2>/dev/null || echo 'unknown')"
          append_detail "${u}_is_active(after)=$(systemctl is-active "$u" 2>/dev/null || echo 'unknown')"
        fi
      done
    done
  done
else
  append_detail "systemctl_not_found"
fi

# 최종 판정
if [ "$FAIL_FLAG" -eq 0 ]; then
  IS_SUCCESS=1
  if [ "$MODIFIED" -eq 1 ]; then
    REASON_LINE="DoS 공격에 취약한 서비스(echo, discard, daytime, chargen)가 비활성화되도록 설정이 변경되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
  else
    REASON_LINE="DoS 공격에 취약한 서비스(echo, discard, daytime, chargen)가 이미 비활성화 상태로 유지되어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
  fi
else
  IS_SUCCESS=0
  REASON_LINE="조치를 수행했으나 DoS 공격에 취약한 서비스 관련 설정이 여전히 활성화 상태이거나 검증 기준을 충족하지 못해 조치가 완료되지 않았습니다."
fi

if [ -n "$ACTION_ERR_LOG" ]; then
  DETAIL_CONTENT="$DETAIL_CONTENT\n$ACTION_ERR_LOG"
fi

# raw_evidence 구성 (after/current만 포함)
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