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
# ※ 환경에 따라 존재하지 않을 수 있음(존재할 때만 조치/검증)
UNNEEDED_RPC_SERVICES=(
  "rpc.cmsd" "rpc.ttdbserverd" "sadmind" "rusersd" "walld" "sprayd" "rstatd"
  "rpc.nisd" "rexd" "rpc.pcnfsd" "rpc.statd" "rpc.ypupdated" "rpc.rquotad"
  "kcms_server" "cachefsd"
)

# systemd에서 현실적으로 자주 매칭되는 RPC 유닛 후보(환경 의존/NFS 등 필요할 수 있음)
# NOTE: 무분별한 전체 중지는 위험. "불필요로 분류되는 것 + 존재할 때만" 조치.
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
# inetd(after)
( [ -f /etc/inetd.conf ] && echo "## inetd(after)" && grep -nEv "^[[:space:]]*#" /etc/inetd.conf 2>/dev/null | egrep -n "^[[:space:]]*(rpc\.cmsd|rpc\.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc\.nisd|rexd|rpc\.pcnfsd|rpc\.statd|rpc\.ypupdated|rpc\.rquotad|kcms_server|cachefsd)([[:space:]]|$)" | head -n 50 ) || echo "inetd_no_active_unneeded_rpc_lines_or_not_found";
# xinetd(after)
if [ -d /etc/xinetd.d ]; then
  echo "## xinetd(after)"
  for f in /etc/xinetd.d/*; do
    [ -f "$f" ] || continue
    egrep -qi "^[[:space:]]*service[[:space:]]+(rpc\.cmsd|rpc\.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc\.nisd|rexd|rpc\.pcnfsd|rpc\.statd|rpc\.ypupdated|rpc\.rquotad|kcms_server|cachefsd)([[:space:]]|$)" "$f" 2>/dev/null || continue
    echo "xinetd_file:$f"
    grep -nEi "^[[:space:]]*service[[:space:]]+|^[[:space:]]*disable[[:space:]]*=" "$f" 2>/dev/null | head -n 30
  done
else
  echo "xinetd_dir_not_found"
fi;
# systemd(after)
(command -v systemctl >/dev/null 2>&1 && (
  echo "## systemd(after)"
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

# (필수) root 권한 체크: 조치 실패 원인 명확화
if [ "$(id -u)" -ne 0 ]; then
  FAIL_FLAG=1
  REASON_LINE="root 권한이 아니어서 서비스 설정 변경(sed/systemctl 등)을 수행할 수 없어 조치가 완료되지 않았습니다."
  append_detail "현재 실행 UID=$(id -u) (root 권한으로 재실행이 필요합니다.)"
else

########################################
# 1) inetd: /etc/inetd.conf 내 '가이드 불필요 서비스' 활성 라인만 주석 처리
########################################
if [ -f "/etc/inetd.conf" ]; then
  INETD_NEED_RESTART=0
  for svc in "${UNNEEDED_RPC_SERVICES[@]}"; do
    if grep -nEv "^[[:space:]]*#" /etc/inetd.conf 2>/dev/null | grep -qE "^[[:space:]]*${svc}([[:space:]]|$)"; then
      cp -a /etc/inetd.conf "/etc/inetd.conf.bak_$(date +%Y%m%d_%H%M%S)" 2>/dev/null || append_err "inetd.conf 백업 실패"
      # 해당 서비스 시작 라인만 주석 처리
      sed -i -E "s/^([[:space:]]*)(${svc})([[:space:]]|$)/\1#\2\3/" /etc/inetd.conf 2>/dev/null || append_err "inetd.conf ${svc} 라인 주석 처리 실패"
      MODIFIED=1
      INETD_NEED_RESTART=1
    fi
  done
  [ "$INETD_NEED_RESTART" -eq 1 ] && restart_inetd_if_exists
fi

########################################
# 2) xinetd: /etc/xinetd.d 내 '가이드 불필요 서비스' 블록을 disable=yes로 고정
#    - disable=no면 yes로 변경
#    - disable 항목이 없으면 해당 서비스 블록에 disable=yes 삽입(필수 보강)
########################################
XINETD_CHANGED=0
if [ -d "/etc/xinetd.d" ]; then
  for conf in /etc/xinetd.d/*; do
    [ -f "$conf" ] || continue

    # 해당 파일이 가이드 불필요 서비스 중 하나를 정의하는지 확인
    MATCHED_SVC=""
    for svc in "${UNNEEDED_RPC_SERVICES[@]}"; do
      if grep -Ev "^[[:space:]]*#" "$conf" 2>/dev/null | grep -qiE "^[[:space:]]*service[[:space:]]+${svc}([[:space:]]|$)"; then
        MATCHED_SVC="$svc"
        break
      fi
    done
    [ -z "$MATCHED_SVC" ] && continue

    cp -a "$conf" "${conf}.bak_$(date +%Y%m%d_%H%M%S)" 2>/dev/null || append_err "$(basename "$conf") 백업 실패"

    # 2-1) disable=no -> yes
    if grep -Ev "^[[:space:]]*#" "$conf" 2>/dev/null | grep -qiE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no([[:space:]]|$)"; then
      sed -Ei 's/^([[:space:]]*disable[[:space:]]*=[[:space:]]*)[Nn][Oo]([[:space:]]*(#.*)?)?$/\1yes\2/' "$conf" 2>/dev/null \
        || append_err "$(basename "$conf") disable=yes 변경 실패"
      XINETD_CHANGED=1
      MODIFIED=1
    else
      # 2-2) disable 항목이 아예 없으면 해당 service 블록 안에 disable=yes 삽입
      #      (블록 단위 최소 삽입: service <svc> ... { ... } 내 '}' 직전에 추가)
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
        ' "$conf" > "${conf}.tmp_u42" 2>/dev/null && mv -f "${conf}.tmp_u42" "$conf" 2>/dev/null \
          || append_err "$(basename "$conf") disable=yes 삽입 실패"
        XINETD_CHANGED=1
        MODIFIED=1
      fi
    fi
  done
fi

[ "$XINETD_CHANGED" -eq 1 ] && restart_xinetd_if_exists

########################################
# 3) systemd: 대표 RPC 유닛 stop/disable/mask(존재할 때만)
#    ※ rpcbind 등은 NFS 등에 필요할 수 있으므로, 운영 환경에서는 의존성 확인 필요.
########################################
for u in "${RPC_UNITS_CANDIDATES[@]}"; do
  disable_systemd_unit_if_exists "$u"
done

fi # root check else

########################################
# 4) 조치 후 검증 + detail(조치 후/현재 상태만)
########################################
# 4-1) inetd: 불필요 서비스 라인 남아있으면 실패
INETD_POST="inetd_conf_not_found"
if [ -f "/etc/inetd.conf" ]; then
  INETD_POST="$(grep -nEv '^[[:space:]]*#' /etc/inetd.conf 2>/dev/null | egrep -n "^[[:space:]]*(rpc\.cmsd|rpc\.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc\.nisd|rexd|rpc\.pcnfsd|rpc\.statd|rpc\.ypupdated|rpc\.rquotad|kcms_server|cachefsd)([[:space:]]|$)" | head -n 10)"
  [ -z "$INETD_POST" ] && INETD_POST="no_active_unneeded_rpc_lines"
fi
[ "$INETD_POST" != "no_active_unneeded_rpc_lines" ] && [ "$INETD_POST" != "inetd_conf_not_found" ] && FAIL_FLAG=1
append_detail "inetd_unneeded_rpc_lines(after)=$INETD_POST"

# 4-2) xinetd: 불필요 서비스 블록에서 disable=no 남아있으면 실패 / disable 미설정이면 실패로 간주(명시 권장)
XINETD_BAD=0
XINETD_POST_SUMMARY=""
if [ -d "/etc/xinetd.d" ]; then
  for conf in /etc/xinetd.d/*; do
    [ -f "$conf" ] || continue
    # 대상 서비스인지 확인
    egrep -qi "^[[:space:]]*service[[:space:]]+(rpc\.cmsd|rpc\.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc\.nisd|rexd|rpc\.pcnfsd|rpc\.statd|rpc\.ypupdated|rpc\.rquotad|kcms_server|cachefsd)([[:space:]]|$)" "$conf" 2>/dev/null || continue

    dis_line="$(grep -nEv '^[[:space:]]*#' "$conf" 2>/dev/null | grep -niE '^[[:space:]]*disable[[:space:]]*=' | head -n 1)"
    [ -z "$dis_line" ] && dis_line="disable_setting_not_found"
    XINETD_POST_SUMMARY="${XINETD_POST_SUMMARY}$(basename "$conf"):${dis_line}; "

    if grep -Ev "^[[:space:]]*#" "$conf" 2>/dev/null | grep -qiE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no([[:space:]]|$)"; then
      XINETD_BAD=1
    fi
    # disable 항목이 없으면(명시 미흡)도 위험으로 보고 실패 처리(가이드의 disable=yes 권고 반영)
    if echo "$dis_line" | grep -qi "disable_setting_not_found"; then
      XINETD_BAD=1
    fi
  done
else
  XINETD_POST_SUMMARY="xinetd_dir_not_found"
fi
[ -z "$XINETD_POST_SUMMARY" ] && XINETD_POST_SUMMARY="no_unneeded_rpc_xinetd_files"
append_detail "xinetd_unneeded_rpc_disable_settings(after)=$XINETD_POST_SUMMARY"
[ "$XINETD_BAD" -eq 1 ] && FAIL_FLAG=1

# 4-3) systemd: 존재하는 후보 유닛만 enabled/active면 실패(조건부 검증)
if command -v systemctl >/dev/null 2>&1; then
  for u in "${RPC_UNITS_CANDIDATES[@]}"; do
    systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$u" || continue
    en="$(systemctl is-enabled "$u" 2>/dev/null || echo unknown)"
    ac="$(systemctl is-active "$u" 2>/dev/null || echo unknown)"
    append_detail "${u}(after) enabled=$en active=$ac"
    echo "$en" | grep -qiE "^enabled$" && FAIL_FLAG=1
    echo "$ac" | grep -qiE "^active$" && FAIL_FLAG=1
  done
else
  append_detail "systemctl_not_found (systemd 기반 조치/검증은 수행하지 않았습니다.)"
fi

# 최종 판정
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

# 에러 로그는 detail에만 추가(이전 설정은 포함하지 않음)
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