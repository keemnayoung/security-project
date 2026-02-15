#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-36
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : r 계열 서비스 비활성화
# @Description : r-command 서비스 비활성화 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-36 r 계열 서비스 비활성화

# 기본 변수
ID="U-36"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

R_SERVICES=("rsh" "rlogin" "rexec" "shell" "login" "exec")

CHECK_COMMAND='
( [ -f /etc/inetd.conf ] && grep -nEv "^[[:space:]]*#" /etc/inetd.conf 2>/dev/null | grep -nE "^[[:space:]]*(rsh|rlogin|rexec|shell|login|exec)([[:space:]]|$)" ) || echo "inetd_no_active_r_services";
for s in rsh rlogin rexec shell login exec; do
  [ -f "/etc/xinetd.d/$s" ] && echo "xinetd_file:$s" && grep -nEv "^[[:space:]]*#" "/etc/xinetd.d/$s" 2>/dev/null | grep -niE "^[[:space:]]*disable[[:space:]]*=" | head -n 1 || true;
done;
(command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -Ei "^(rsh|rlogin|rexec|shell|login|exec)\.(service|socket)[[:space:]]") || echo "systemd_units_not_found";
( [ -f /etc/hosts.equiv ] && grep -nEv "^[[:space:]]*#|^[[:space:]]*$" /etc/hosts.equiv ) || echo "hosts_equiv_not_found_or_empty";
( find /home -maxdepth 3 -type f -name .rhosts 2>/dev/null -print ) || echo "no_rhosts_found"
'

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE="/etc/inetd.conf
/etc/xinetd.d/(rsh,rlogin,rexec,shell,login,exec)
systemd(rsh/rlogin/rexec/shell/login/exec)
 /etc/hosts.equiv
/home/*/.rhosts"

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

# 신뢰 기반 파일 조치: /etc/hosts.equiv, /home/*/.rhosts (내용 무력화)
neutralize_trust_file() {
  local f="$1"
  [ -f "$f" ] || return 0

  # 유효 라인이 없으면 건드리지 않음
  if ! grep -nEv "^[[:space:]]*#|^[[:space:]]*$" "$f" >/dev/null 2>&1; then
    return 0
  fi

  cp -a "$f" "${f}.bak_${TIMESTAMP}" 2>/dev/null || append_err "$f 백업 실패"
  # 주석/공백 제외 라인을 주석 처리하여 신뢰 기반 설정 무력화
  # (이미 주석인 라인은 유지)
  sed -i -e '/^[[:space:]]*#/b' -e '/^[[:space:]]*$/b' -e 's/^[[:space:]]*/# /' "$f" 2>/dev/null \
    || append_err "$f 설정 주석 처리 실패"
  MODIFIED=1
}

########################################
# 1) inetd: /etc/inetd.conf r계열 활성 라인 주석 처리
########################################
if [ -f "/etc/inetd.conf" ]; then
  INETD_ACTIVE=0
  if grep -nEv "^[[:space:]]*#" /etc/inetd.conf 2>/dev/null | grep -qE "^[[:space:]]*(rsh|rlogin|rexec|shell|login|exec)([[:space:]]|$)"; then
    INETD_ACTIVE=1
  fi

  if [ "$INETD_ACTIVE" -eq 1 ]; then
    cp -a /etc/inetd.conf "/etc/inetd.conf.bak_${TIMESTAMP}" 2>/dev/null || append_err "inetd.conf 백업 실패"
    # 라인 시작의 공백 + 서비스명만 주석 처리
    for s in "${R_SERVICES[@]}"; do
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
for s in "${R_SERVICES[@]}"; do
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
# 3) systemd: r 계열 유닛 비활성화(있을 때만)
#    (필수 추가) shell/login/exec 유닛도 포함
########################################
for base in rsh rlogin rexec shell login exec; do
  disable_systemd_unit_if_exists "${base}.service"
  disable_systemd_unit_if_exists "${base}.socket"
done

########################################
# 4) (필수 추가) 신뢰 기반 접속 설정 무력화
########################################
neutralize_trust_file "/etc/hosts.equiv"

RHOSTS_FILES=$(find /home -maxdepth 3 -type f -name .rhosts 2>/dev/null | head -n 200)
if [ -n "$RHOSTS_FILES" ]; then
  while IFS= read -r rf; do
    [ -n "$rf" ] && neutralize_trust_file "$rf"
  done <<< "$RHOSTS_FILES"
fi

########################################
# 5) 조치 후 검증 + detail(현재/조치 후 상태만)
########################################
FAIL_FLAG=0

# inetd 활성 라인 남아있으면 실패
INETD_POST="inetd_conf_not_found"
if [ -f "/etc/inetd.conf" ]; then
  INETD_POST="$(grep -nEv '^[[:space:]]*#' /etc/inetd.conf 2>/dev/null | grep -nE '^[[:space:]]*(rsh|rlogin|rexec|shell|login|exec)([[:space:]]|$)' | head -n 5)"
  [ -z "$INETD_POST" ] && INETD_POST="no_active_r_services"
fi
[ "$INETD_POST" != "no_active_r_services" ] && FAIL_FLAG=1

# xinetd disable=no 남아있으면 실패(파일 존재하는 것만 체크)
XINETD_BAD=0
for s in "${R_SERVICES[@]}"; do
  if [ -f "/etc/xinetd.d/$s" ]; then
    if grep -Ev "^[[:space:]]*#" "/etc/xinetd.d/$s" 2>/dev/null | grep -qiE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no([[:space:]]|$)"; then
      XINETD_BAD=1
    fi
  fi
done
[ "$XINETD_BAD" -eq 1 ] && FAIL_FLAG=1

# systemd enabled/active면 실패 (shell/login/exec 포함)
SYSTEMD_BAD=0
if command -v systemctl >/dev/null 2>&1; then
  for base in rsh rlogin rexec shell login exec; do
    for u in "${base}.service" "${base}.socket"; do
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
fi
[ "$SYSTEMD_BAD" -eq 1 ] && FAIL_FLAG=1

# (필수 추가) hosts.equiv / .rhosts 유효 설정 남아있으면 실패
TRUST_BAD=0

HOSTS_EQ_AFTER="hosts_equiv_not_found"
if [ -f "/etc/hosts.equiv" ]; then
  HOSTS_EQ_AFTER="$(grep -nEv "^[[:space:]]*#|^[[:space:]]*$" /etc/hosts.equiv 2>/dev/null | head -n 5)"
  [ -z "$HOSTS_EQ_AFTER" ] && HOSTS_EQ_AFTER="no_effective_entries"
fi
[ "$HOSTS_EQ_AFTER" != "no_effective_entries" ] && [ "$HOSTS_EQ_AFTER" != "hosts_equiv_not_found" ] && TRUST_BAD=1

RHOSTS_AFTER_SUMMARY=""
RHOSTS_FILES2=$(find /home -maxdepth 3 -type f -name .rhosts 2>/dev/null | head -n 50)
if [ -n "$RHOSTS_FILES2" ]; then
  while IFS= read -r rf; do
    eff="$(grep -nEv "^[[:space:]]*#|^[[:space:]]*$" "$rf" 2>/dev/null | head -n 1)"
    if [ -n "$eff" ]; then
      TRUST_BAD=1
      RHOSTS_AFTER_SUMMARY="${RHOSTS_AFTER_SUMMARY}${rf}:effective_entry_present; "
    else
      RHOSTS_AFTER_SUMMARY="${RHOSTS_AFTER_SUMMARY}${rf}:no_effective_entries; "
    fi
  done <<< "$RHOSTS_FILES2"
else
  RHOSTS_AFTER_SUMMARY="no_rhosts_files"
fi

[ "$TRUST_BAD" -eq 1 ] && FAIL_FLAG=1

# detail(현재/조치 후 상태만)
append_detail "inetd_active_r_services(after)=$INETD_POST"

XINETD_POST_SUMMARY=""
for s in "${R_SERVICES[@]}"; do
  if [ -f "/etc/xinetd.d/$s" ]; then
    line="$(grep -nEv '^[[:space:]]*#' "/etc/xinetd.d/$s" 2>/dev/null | grep -niE '^[[:space:]]*disable[[:space:]]*=' | head -n 1)"
    [ -z "$line" ] && line="disable_setting_not_found"
    XINETD_POST_SUMMARY="${XINETD_POST_SUMMARY}${s}:${line}; "
  fi
done
[ -z "$XINETD_POST_SUMMARY" ] && XINETD_POST_SUMMARY="no_xinetd_r_service_files"
append_detail "xinetd_disable_settings(after)=$XINETD_POST_SUMMARY"

if command -v systemctl >/dev/null 2>&1; then
  units="$(systemctl list-unit-files 2>/dev/null | grep -Ei '^(rsh|rlogin|rexec|shell|login|exec)\.(service|socket)[[:space:]]' || echo 'systemd_units_not_found')"
  append_detail "systemd_units(after)=$units"
  for base in rsh rlogin rexec shell login exec; do
    for u in "${base}.service" "${base}.socket"; do
      if systemctl list-unit-files 2>/dev/null | grep -qiE "^${u}[[:space:]]"; then
        append_detail "${u}_is_enabled(after)=$(systemctl is-enabled "$u" 2>/dev/null || echo 'unknown')"
        append_detail "${u}_is_active(after)=$(systemctl is-active "$u" 2>/dev/null || echo 'unknown')"
      fi
    done
  done
else
  append_detail "systemctl_not_found"
fi

append_detail "hosts_equiv_effective_entries(after)=$HOSTS_EQ_AFTER"
append_detail "rhosts_effective_entries(after)=$RHOSTS_AFTER_SUMMARY"

# 최종 판정
if [ "$FAIL_FLAG" -eq 0 ]; then
  IS_SUCCESS=1
  if [ "$MODIFIED" -eq 1 ]; then
    REASON_LINE="r 계열 서비스(rsh, rlogin, rexec, shell, login, exec)가 비활성화되도록 설정이 변경되고 신뢰 기반 설정이 무력화되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
  else
    REASON_LINE="r 계열 서비스(rsh, rlogin, rexec, shell, login, exec)가 이미 비활성화 상태로 유지되고 신뢰 기반 설정이 없어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
  fi
else
  IS_SUCCESS=0
  REASON_LINE="조치를 수행했으나 r 계열 서비스 관련 설정이 여전히 활성화 상태이거나(또는 신뢰 기반 설정이 남아있어) 검증 기준을 충족하지 못해 조치가 완료되지 않았습니다."
fi

if [ -n "$ACTION_ERR_LOG" ]; then
  DETAIL_CONTENT="$DETAIL_CONTENT\n$ACTION_ERR_LOG"
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