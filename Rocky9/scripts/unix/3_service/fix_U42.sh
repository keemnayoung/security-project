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

# NOTE: rpc 관련 서비스는 환경에 따라 필수(NFS 등)일 수 있으므로,
# 무분별한 전체 중지는 위험. 대표적으로 불필요로 분류되는 항목 위주로 존재할 때만 조치.
RPC_UNITS_CANDIDATES=(
  "rpcbind.service"
  "rpcbind.socket"
  "rpc-statd.service"
  "rpc-statd-notify.service"
  "rpc-gssd.service"
  "rpc-svcgssd.service"
  "rpc-idmapd.service"
)

CHECK_COMMAND='
( [ -f /etc/inetd.conf ] && grep -nEv "^[[:space:]]*#" /etc/inetd.conf 2>/dev/null | grep -nE "^[[:space:]]*rpc([[:space:]]|$)" ) || echo "inetd_no_active_rpc_lines";
if [ -d /etc/xinetd.d ]; then
  for f in /etc/xinetd.d/*; do
    [ -f "$f" ] || continue
    ( echo "$f" | grep -qi "rpc" || grep -qiE "^[[:space:]]*service[[:space:]]+.*rpc" "$f" 2>/dev/null ) || continue
    echo "xinetd_rpc_file:$f"
    grep -nEv "^[[:space:]]*#" "$f" 2>/dev/null | grep -niE "^[[:space:]]*disable[[:space:]]*=" | head -n 1
  done
else
  echo "xinetd_dir_not_found"
fi;
(command -v systemctl >/dev/null 2>&1 && (
  systemctl list-unit-files 2>/dev/null | grep -Ei "^rpc.*\.(service|socket)[[:space:]]" | head -n 50 || echo "no_rpc_unit_files";
  for u in rpcbind.service rpcbind.socket rpc-statd.service rpc-statd-notify.service rpc-gssd.service rpc-svcgssd.service rpc-idmapd.service; do
    systemctl list-unit-files 2>/dev/null | grep -qiE "^${u}[[:space:]]" && echo "unit:$u enabled=$(systemctl is-enabled "$u" 2>/dev/null || echo unknown) active=$(systemctl is-active "$u" 2>/dev/null || echo unknown)";
  done
)) || echo "systemctl_not_found"
'

REASON_LINE=""
DETAIL_CONTENT=""
ACTION_ERR_LOG=""
MODIFIED=0
FAIL_FLAG=0

# (필수) root 권한 권장 안내(실패 원인 명확화용)
if [ "$(id -u)" -ne 0 ]; then
  ACTION_ERR_LOG="(주의) root 권한이 아니면 sed/systemctl 조치가 실패할 수 있습니다."
fi

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

restart_inetd_if_exists() {
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl list-unit-files 2>/dev/null | grep -qE "^inetd\.service" || return 0
  systemctl restart inetd 2>/dev/null || append_err "systemctl restart inetd 실패"
}

restart_xinetd_if_exists() {
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl list-unit-files 2>/dev/null | grep -qE "^xinetd\.service" || return 0
  systemctl restart xinetd 2>/dev/null || append_err "systemctl restart xinetd 실패"
}

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
# 1) inetd: /etc/inetd.conf 내 rpc 시작 라인 주석 처리(활성 라인만)
########################################
if [ -f "/etc/inetd.conf" ]; then
  if grep -nEv "^[[:space:]]*#" /etc/inetd.conf 2>/dev/null | grep -qE "^[[:space:]]*rpc([[:space:]]|$)"; then
    cp -a /etc/inetd.conf "/etc/inetd.conf.bak_$(date +%Y%m%d_%H%M%S)" 2>/dev/null || append_err "inetd.conf 백업 실패"
    sed -i 's/^\([[:space:]]*rpc\)/#\1/g' /etc/inetd.conf 2>/dev/null || append_err "inetd.conf rpc 라인 주석 처리 실패"
    MODIFIED=1
    restart_inetd_if_exists
  fi
fi

########################################
# 2) xinetd: /etc/xinetd.d 내 rpc 관련 파일 disable=no -> disable=yes
########################################
XINETD_CHANGED=0
if [ -d "/etc/xinetd.d" ]; then
  for conf in /etc/xinetd.d/*; do
    [ -f "$conf" ] || continue
    # 파일명에 rpc 포함 또는 service 라인에 rpc 포함(보수적)
    if echo "$conf" | grep -qi "rpc" || grep -qiE "^[[:space:]]*service[[:space:]]+.*rpc" "$conf" 2>/dev/null; then
      if grep -Ev "^[[:space:]]*#" "$conf" 2>/dev/null | grep -qiE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no([[:space:]]|$)"; then
        cp -a "$conf" "${conf}.bak_$(date +%Y%m%d_%H%M%S)" 2>/dev/null || append_err "$(basename "$conf") 백업 실패"
        sed -Ei 's/^([[:space:]]*disable[[:space:]]*=[[:space:]]*)[Nn][Oo]([[:space:]]*(#.*)?)?$/\1yes\2/' "$conf" 2>/dev/null \
          || append_err "$(basename "$conf") disable=yes 변경 실패"
        XINETD_CHANGED=1
        MODIFIED=1
      fi
    fi
  done
fi

if [ "$XINETD_CHANGED" -eq 1 ]; then
  restart_xinetd_if_exists
fi

########################################
# 3) systemd: 대표 RPC 유닛 stop/disable/mask(존재할 때만)
#    ※ rpcbind는 NFS 등에 필요할 수 있어, 불필요한 경우에만 적용 권고.
########################################
for u in "${RPC_UNITS_CANDIDATES[@]}"; do
  disable_systemd_unit_if_exists "$u"
done

########################################
# 4) 조치 후 검증 + detail(현재/조치 후 상태만)
########################################
# inetd 활성 rpc 라인 남아있으면 실패
INETD_POST="inetd_conf_not_found"
if [ -f "/etc/inetd.conf" ]; then
  INETD_POST="$(grep -nEv '^[[:space:]]*#' /etc/inetd.conf 2>/dev/null | grep -nE '^[[:space:]]*rpc([[:space:]]|$)' | head -n 5)"
  [ -z "$INETD_POST" ] && INETD_POST="no_active_rpc_lines"
fi
[ "$INETD_POST" != "no_active_rpc_lines" ] && FAIL_FLAG=1
append_detail "inetd_active_rpc_lines(after)=$INETD_POST"

# xinetd rpc 파일 중 disable=no 남아있으면 실패(존재하는 것만)
XINETD_BAD=0
XINETD_POST_SUMMARY=""
if [ -d "/etc/xinetd.d" ]; then
  for conf in /etc/xinetd.d/*; do
    [ -f "$conf" ] || continue
    if echo "$conf" | grep -qi "rpc" || grep -qiE "^[[:space:]]*service[[:space:]]+.*rpc" "$conf" 2>/dev/null; then
      line="$(grep -nEv '^[[:space:]]*#' "$conf" 2>/dev/null | grep -niE '^[[:space:]]*disable[[:space:]]*=' | head -n 1)"
      [ -z "$line" ] && line="disable_setting_not_found"
      XINETD_POST_SUMMARY="${XINETD_POST_SUMMARY}$(basename "$conf"):${line}; "
      if grep -Ev "^[[:space:]]*#" "$conf" 2>/dev/null | grep -qiE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no([[:space:]]|$)"; then
        XINETD_BAD=1
      fi
    fi
  done
else
  XINETD_POST_SUMMARY="xinetd_dir_not_found"
fi
[ -z "$XINETD_POST_SUMMARY" ] && XINETD_POST_SUMMARY="no_rpc_related_xinetd_files"
append_detail "xinetd_rpc_disable_settings(after)=$XINETD_POST_SUMMARY"
[ "$XINETD_BAD" -eq 1 ] && FAIL_FLAG=1

# systemd enabled/active면 실패
if command -v systemctl >/dev/null 2>&1; then
  for u in "${RPC_UNITS_CANDIDATES[@]}"; do
    if systemctl list-unit-files 2>/dev/null | grep -qiE "^${u}[[:space:]]"; then
      en="$(systemctl is-enabled "$u" 2>/dev/null || echo unknown)"
      ac="$(systemctl is-active "$u" 2>/dev/null || echo unknown)"
      append_detail "${u}(after) enabled=$en active=$ac"
      echo "$en" | grep -qiE "enabled" && FAIL_FLAG=1
      echo "$ac" | grep -qiE "active" && FAIL_FLAG=1
    fi
  done
else
  append_detail "systemctl_not_found"
  FAIL_FLAG=1
fi

# 최종 판정
if [ "$FAIL_FLAG" -eq 0 ]; then
  IS_SUCCESS=1
  if [ "$MODIFIED" -eq 1 ]; then
    REASON_LINE="불필요한 RPC 서비스가 비활성화되도록 설정이 변경되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
  else
    REASON_LINE="RPC 서비스가 이미 비활성화 상태로 유지되어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
  fi
else
  IS_SUCCESS=0
  REASON_LINE="조치를 수행했으나 RPC 서비스 관련 설정이 여전히 활성화 상태이거나 검증 기준을 충족하지 못해 조치가 완료되지 않았습니다."
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