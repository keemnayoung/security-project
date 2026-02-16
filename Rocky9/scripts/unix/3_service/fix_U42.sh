#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-42
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 불필요한 RPC 서비스 비활성화
# @Description : 불필요한 RPC 서비스의 실행 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-42 불필요한 RPC 서비스 비활성화

# 기본 변수
ID="U-42"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

TARGET_FILE="/etc/inetd.conf
/etc/xinetd.d/*
systemd(rpc related services)"

# 가이드 기반 불필요 RPC 서비스(핵심 목록)
UNNEEDED_RPC_SERVICES=(
  "rpc.cmsd" "rpc.ttdbserverd" "sadmind" "rusersd" "walld" "sprayd" "rstatd"
  "rpc.nisd" "rexd" "rpc.pcnfsd" "rpc.statd" "rpc.ypupdated" "rpc.rquotad"
  "kcms_server" "cachefsd"
)

# systemd 후보(환경 의존)
RPC_UNITS_CANDIDATES=(
  "rpcbind.service"
  "rpcbind.socket"
  "rpc-statd.service"
  "rpc-statd-notify.service"
  "rpc-gssd.service"
  "rpc-svcgssd.service"
  "rpc-idmapd.service"
)

BACKUP_DIR="/var/backups/${ID}_backup"
TS="$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR" 2>/dev/null || true

CHECK_COMMAND='
( [ -f /etc/inetd.conf ] && grep -nEv "^[[:space:]]*#" /etc/inetd.conf 2>/dev/null | egrep -n "^[[:space:]]*(rpc\.cmsd|rpc\.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc\.nisd|rexd|rpc\.pcnfsd|rpc\.statd|rpc\.ypupdated|rpc\.rquotad|kcms_server|cachefsd)([[:space:]]|$)" | head -n 50 ) || echo "inetd_no_active_unneeded_rpc_lines_or_not_found";
if [ -d /etc/xinetd.d ]; then
  for f in /etc/xinetd.d/*; do
    [ -f "$f" ] || continue
    echo "$f" | grep -qE "\.bak_|\.orig$|~$" && continue
    egrep -qi "^[[:space:]]*service[[:space:]]+(rpc\.cmsd|rpc\.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc\.nisd|rexd|rpc\.pcnfsd|rpc\.statd|rpc\.ypupdated|rpc\.rquotad|kcms_server|cachefsd)([[:space:]]|$)" "$f" 2>/dev/null || continue
    echo "xinetd_file:$f"
    grep -nEi "^[[:space:]]*service[[:space:]]+|^[[:space:]]*disable[[:space:]]*=" "$f" 2>/dev/null | head -n 30
  done
else
  echo "xinetd_dir_not_found"
fi;
(command -v systemctl >/dev/null 2>&1 && (
  for u in rpcbind.service rpcbind.socket rpc-statd.service rpc-statd-notify.service rpc-gssd.service rpc-svcgssd.service rpc-idmapd.service; do
    systemctl list-unit-files 2>/dev/null | awk "{print \$1}" | grep -qx "$u" || continue
    echo "unit:$u enabled=$(systemctl is-enabled "$u" 2>/dev/null || echo unknown) active=$(systemctl is-active "$u" 2>/dev/null || echo unknown)"
  done
)) || echo "systemctl_not_found"
'

REASON_LINE=""
DETAIL_CONTENT=""
ACTION_ERR_LOG=""
MODIFIED=0
FAIL_FLAG=0

append_err() {
  [ -n "$ACTION_ERR_LOG" ] && ACTION_ERR_LOG="${ACTION_ERR_LOG}\n$1" || ACTION_ERR_LOG="$1"
}

append_detail() {
  [ -n "$DETAIL_CONTENT" ] && DETAIL_CONTENT="${DETAIL_CONTENT}\n$1" || DETAIL_CONTENT="$1"
}

restart_inetd_if_exists() {
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "inetd.service" || return 0
  systemctl restart inetd 2>/dev/null || append_err "systemctl restart inetd 실패"
}

restart_xinetd_if_exists() {
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "xinetd.service" || return 0
  systemctl restart xinetd 2>/dev/null || append_err "systemctl restart xinetd 실패"
}

disable_systemd_unit_if_exists() {
  local unit="$1"
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$unit" || return 0

  systemctl stop "$unit" 2>/dev/null || append_err "systemctl stop ${unit} 실패"
  systemctl disable "$unit" 2>/dev/null || append_err "systemctl disable ${unit} 실패"
  systemctl mask "$unit" 2>/dev/null || append_err "systemctl mask ${unit} 실패"
  MODIFIED=1
}

########################################
# 0) (필수) 기존에 남아있는 /etc/xinetd.d 백업파일을 점검에 걸리지 않게 이동
########################################
if [ "$(id -u)" -eq 0 ] && [ -d /etc/xinetd.d ]; then
  # 이전 실행에서 생성된 백업 파일들이 남아있으면 check에서 FAIL 유발 가능
  mv -f /etc/xinetd.d/*.bak_* "$BACKUP_DIR"/ 2>/dev/null || true
fi

# root 권한 체크
if [ "$(id -u)" -ne 0 ]; then
  FAIL_FLAG=1
  REASON_LINE="root 권한이 아니어서 서비스 설정 변경(sed/systemctl 등)을 수행할 수 없어 조치가 완료되지 않았습니다."
  append_detail "현재 실행 UID=$(id -u) (root 권한으로 재실행이 필요합니다.)"
else

  ########################################
  # 1) inetd: 불필요 서비스 라인만 주석 처리
  ########################################
  if [ -f "/etc/inetd.conf" ]; then
    INETD_NEED_RESTART=0
    for svc in "${UNNEEDED_RPC_SERVICES[@]}"; do
      if grep -nEv "^[[:space:]]*#" /etc/inetd.conf 2>/dev/null | grep -qE "^[[:space:]]*${svc}([[:space:]]|$)"; then
        cp -a /etc/inetd.conf "$BACKUP_DIR/inetd.conf.bak_${TS}" 2>/dev/null || append_err "inetd.conf 백업 실패"
        sed -i -E "s/^([[:space:]]*)(${svc})([[:space:]]|$)/\1#\2\3/" /etc/inetd.conf 2>/dev/null || append_err "inetd.conf ${svc} 주석 처리 실패"
        MODIFIED=1
        INETD_NEED_RESTART=1
      fi
    done
    [ "$INETD_NEED_RESTART" -eq 1 ] && restart_inetd_if_exists
  fi

  ########################################
  # 2) xinetd: 불필요 서비스는 disable=yes 강제(없으면 삽입)
  ########################################
  XINETD_CHANGED=0
  if [ -d "/etc/xinetd.d" ]; then
    for conf in /etc/xinetd.d/*; do
      [ -f "$conf" ] || continue
      # 백업/임시 파일은 조치 대상에서 제외
      echo "$conf" | grep -qE "\.bak_|\.orig$|~$" && continue

      MATCHED_SVC=""
      for svc in "${UNNEEDED_RPC_SERVICES[@]}"; do
        if grep -Ev "^[[:space:]]*#" "$conf" 2>/dev/null | grep -qiE "^[[:space:]]*service[[:space:]]+${svc}([[:space:]]|$)"; then
          MATCHED_SVC="$svc"
          break
        fi
      done
      [ -z "$MATCHED_SVC" ] && continue

      cp -a "$conf" "$BACKUP_DIR/$(basename "$conf").bak_${TS}" 2>/dev/null || append_err "$(basename "$conf") 백업 실패"

      if grep -Ev "^[[:space:]]*#" "$conf" 2>/dev/null | grep -qiE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no([[:space:]]|$)"; then
        sed -Ei 's/^([[:space:]]*disable[[:space:]]*=[[:space:]]*)[Nn][Oo]([[:space:]]*(#.*)?)?$/\1yes\2/' "$conf" 2>/dev/null \
          || append_err "$(basename "$conf") disable=yes 변경 실패"
        XINETD_CHANGED=1
        MODIFIED=1
      else
        if ! grep -Ev "^[[:space:]]*#" "$conf" 2>/dev/null | grep -qiE "^[[:space:]]*disable[[:space:]]*="; then
          awk -v SVC="$MATCHED_SVC" '
            BEGIN{inblk=0; has_disable=0}
            {
              line=$0
              if (line ~ /^[[:space:]]*service[[:space:]]+/) {
                inblk = (tolower(line) ~ ("^[[:space:]]*service[[:space:]]+" tolower(SVC) "([[:space:]]|$)")) ? 1 : 0
                has_disable=0
              }
              if (inblk==1 && tolower(line) ~ /^[[:space:]]*disable[[:space:]]*=/) { has_disable=1 }
              if (inblk==1 && line ~ /^[[:space:]]*}[[:space:]]*$/) {
                if (has_disable==0) { print "    disable = yes" }
                inblk=0
              }
              print line
            }
          ' "$conf" > "${conf}.tmp_${ID}" 2>/dev/null && mv -f "${conf}.tmp_${ID}" "$conf" 2>/dev/null \
            || append_err "$(basename "$conf") disable=yes 삽입 실패"
          XINETD_CHANGED=1
          MODIFIED=1
        fi
      fi
    done
  fi
  [ "$XINETD_CHANGED" -eq 1 ] && restart_xinetd_if_exists

  ########################################
  # 3) systemd: 존재할 때만 stop/disable/mask
  ########################################
  for u in "${RPC_UNITS_CANDIDATES[@]}"; do
    disable_systemd_unit_if_exists "$u"
  done
fi

########################################
# 4) 조치 후 검증(조치 후/현재 설정만)
########################################
INETD_POST="inetd_conf_not_found"
if [ -f "/etc/inetd.conf" ]; then
  INETD_POST="$(grep -nEv '^[[:space:]]*#' /etc/inetd.conf 2>/dev/null | egrep -n "^[[:space:]]*(rpc\.cmsd|rpc\.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc\.nisd|rexd|rpc\.pcnfsd|rpc\.statd|rpc\.ypupdated|rpc\.rquotad|kcms_server|cachefsd)([[:space:]]|$)" | head -n 10)"
  [ -z "$INETD_POST" ] && INETD_POST="no_active_unneeded_rpc_lines"
fi
[ "$INETD_POST" != "no_active_unneeded_rpc_lines" ] && [ "$INETD_POST" != "inetd_conf_not_found" ] && FAIL_FLAG=1
append_detail "inetd_unneeded_rpc_lines(after)=$INETD_POST"

XINETD_BAD=0
XINETD_POST_SUMMARY=""
if [ -d "/etc/xinetd.d" ]; then
  for conf in /etc/xinetd.d/*; do
    [ -f "$conf" ] || continue
    # 백업파일은 검증에서도 제외(점검과 동일한 기준으로 맞춤)
    echo "$conf" | grep -qE "\.bak_|\.orig$|~$" && continue

    egrep -qi "^[[:space:]]*service[[:space:]]+(rpc\.cmsd|rpc\.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc\.nisd|rexd|rpc\.pcnfsd|rpc\.statd|rpc\.ypupdated|rpc\.rquotad|kcms_server|cachefsd)([[:space:]]|$)" "$conf" 2>/dev/null || continue

    dis_line="$(grep -nEv '^[[:space:]]*#' "$conf" 2>/dev/null | grep -niE '^[[:space:]]*disable[[:space:]]*=' | head -n 1)"
    [ -z "$dis_line" ] && dis_line="disable_setting_not_found"
    XINETD_POST_SUMMARY="${XINETD_POST_SUMMARY}$(basename "$conf"):${dis_line}; "

    grep -Ev "^[[:space:]]*#" "$conf" 2>/dev/null | grep -qiE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no([[:space:]]|$)" && XINETD_BAD=1
    echo "$dis_line" | grep -qi "disable_setting_not_found" && XINETD_BAD=1
  done
else
  XINETD_POST_SUMMARY="xinetd_dir_not_found"
fi
[ -z "$XINETD_POST_SUMMARY" ] && XINETD_POST_SUMMARY="no_unneeded_rpc_xinetd_files"
append_detail "xinetd_unneeded_rpc_disable_settings(after)=$XINETD_POST_SUMMARY"
[ "$XINETD_BAD" -eq 1 ] && FAIL_FLAG=1

if command -v systemctl >/dev/null 2>&1; then
  for u in "${RPC_UNITS_CANDIDATES[@]}"; do
    systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$u" || continue
    en="$(systemctl is-enabled "$u" 2>/dev/null || echo unknown)"
    ac="$(systemctl is-active "$u" 2>/dev/null || echo unknown)"
    append_detail "${u}(after) enabled=$en active=$ac"
    [ "$en" = "enabled" ] && FAIL_FLAG=1
    [ "$ac" = "active" ] && FAIL_FLAG=1
  done
else
  append_detail "systemctl_not_found (systemd 기반 조치/검증은 수행하지 않았습니다.)"
fi

if [ "$FAIL_FLAG" -eq 0 ]; then
  IS_SUCCESS=1
  if [ "$MODIFIED" -eq 1 ]; then
    REASON_LINE="불필요한 RPC 서비스가 비활성화되도록 설정이 변경되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
  else
    REASON_LINE="불필요한 RPC 서비스가 이미 비활성화 상태로 유지되어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
  fi
else
  IS_SUCCESS=0
  [ -z "$REASON_LINE" ] && REASON_LINE="조치를 수행했으나 불필요한 RPC 서비스 관련 설정이 여전히 활성화 상태이거나 검증 기준을 충족하지 못해 조치가 완료되지 않았습니다."
fi

[ -n "$ACTION_ERR_LOG" ] && DETAIL_CONTENT="$DETAIL_CONTENT\n$ACTION_ERR_LOG"

RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/"/\\"/g' \
  | sed ':a;N;$!ba;s/\n/\\n/g')

echo ""
cat << EOF
{
    "item_code": "$ID",
    "action_date": "$ACTION_DATE",
    "is_success": $IS_SUCCESS,
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
}
EOF