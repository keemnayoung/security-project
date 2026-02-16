#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-39
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 불필요한 NFS 서비스 비활성화
# @Description : 불필요한 NFS 서비스 사용 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-39 불필요한 NFS 서비스 비활성화


# 기본 변수
ID="U-39"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND='
(command -v systemctl >/dev/null 2>&1 && (
  systemctl list-unit-files 2>/dev/null | grep -Ei "^(nfs-server|nfs|rpcbind|rpc-statd|rpc-idmapd|nfs-mountd|nfs-idmapd|rpcbind)\.(service|socket)[[:space:]]" || echo "nfs_related_unit_files_not_found";
  for u in nfs-server.service nfs.service rpcbind.service rpcbind.socket rpc-statd.service rpc-idmapd.service nfs-mountd.service nfs-idmapd.service; do
    systemctl list-unit-files 2>/dev/null | grep -qiE "^${u}[[:space:]]" && echo "unit:$u enabled=$(systemctl is-enabled "$u" 2>/dev/null | head -n 1) active=$(systemctl is-active "$u" 2>/dev/null | head -n 1)";
  done
)) || echo "systemctl_not_found";
[ -f /etc/exports ] && (grep -nEv "^[[:space:]]*#|^[[:space:]]*$" /etc/exports || echo "exports_empty") || echo "exports_not_found"
'

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE="systemd(NFS related services), /etc/exports"

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

# (필수) root 권한 권장 안내(실패 원인 명확화용)
if [ "$(id -u)" -ne 0 ]; then
  append_err "(주의) root 권한이 아니면 systemctl stop/disable/mask 조치가 실패할 수 있습니다."
fi

# systemctl 출력값에서 unknown 덧붙는 버그 방지용 함수
get_is_enabled() {
  local unit="$1"
  local out
  out="$(systemctl is-enabled "$unit" 2>/dev/null | head -n 1)"
  [ -z "$out" ] && out="unknown"
  echo "$out"
}

get_is_active() {
  local unit="$1"
  local out
  out="$(systemctl is-active "$unit" 2>/dev/null | head -n 1)"
  [ -z "$out" ] && out="unknown"
  echo "$out"
}

unit_exists() {
  local unit="$1"
  systemctl list-unit-files 2>/dev/null | grep -qiE "^${unit}[[:space:]]"
}

# systemd 조치(있을 때만): stop/disable/mask
disable_systemd_unit_if_exists() {
  local unit="$1"

  command -v systemctl >/dev/null 2>&1 || return 0
  unit_exists "$unit" || return 0

  # stop
  systemctl stop "$unit" 2>/dev/null || append_err "systemctl stop ${unit} 실패"

  # disable
  systemctl disable "$unit" 2>/dev/null || append_err "systemctl disable ${unit} 실패"

  # mask
  systemctl mask "$unit" 2>/dev/null || append_err "systemctl mask ${unit} 실패"

  MODIFIED=1
}

# ---------------------------
# 조치 수행
# ---------------------------
if ! command -v systemctl >/dev/null 2>&1; then
  IS_SUCCESS=0
  REASON_LINE="systemctl 명령을 사용할 수 없어 NFS 서비스 비활성화 조치를 수행할 수 없습니다."
  DETAIL_CONTENT="systemctl_not_found"
else
  # 대표 유닛 목록(환경별 차이를 고려해 존재하는 것만 처리)
  UNITS=(
    "nfs-server.service"
    "nfs.service"
    "rpcbind.service"
    "rpcbind.socket"
    "rpc-statd.service"
    "rpc-idmapd.service"
    "nfs-mountd.service"
    "nfs-idmapd.service"
    "nfsdcld.service"
  )

  for u in "${UNITS[@]}"; do
    disable_systemd_unit_if_exists "$u"
  done

  # (필수 보완) /etc/exports 유효 설정이 있으면 주석 처리하여 공유 구성 제거
  EXPORTS_FILE="/etc/exports"
  if [ -f "$EXPORTS_FILE" ]; then
    EXPORTS_ACTIVE="$(grep -nEv "^[[:space:]]*#|^[[:space:]]*$" "$EXPORTS_FILE" 2>/dev/null || true)"
    if [ -n "$EXPORTS_ACTIVE" ]; then
      # 비주석 라인을 주석 처리 (after만 남기기 위함)
      sed -i -E 's/^([[:space:]]*[^#[:space:]].*)/# \1/' "$EXPORTS_FILE" 2>/dev/null \
        || append_err "/etc/exports 주석 처리(sed) 실패"
      MODIFIED=1
    fi
  fi

  # ---------------------------
  # 조치 후 검증(현재/조치 후 상태만)
  # ---------------------------
  for u in "${UNITS[@]}"; do
    if unit_exists "$u"; then
      en="$(get_is_enabled "$u")"
      ac="$(get_is_active "$u")"
      append_detail "${u}(after) enabled=$en active=$ac"

      # enabled면 실패
      echo "$en" | grep -qiE "^(enabled|enabled-runtime)$" && FAIL_FLAG=1
      # active/running/listening이면 실패(소켓 포함)
      echo "$ac" | grep -qiE "^(active|running|listening)$" && FAIL_FLAG=1
    fi
  done

  # exports after 검증(점검 스크립트가 exports로 FAIL을 판단할 수 있으므로 조치에 포함)
  if [ -f "$EXPORTS_FILE" ]; then
    EXPORTS_AFTER="$(grep -nEv "^[[:space:]]*#|^[[:space:]]*$" "$EXPORTS_FILE" 2>/dev/null || true)"
    if [ -n "$EXPORTS_AFTER" ]; then
      append_detail "/etc/exports(after) 유효 설정이 남아있습니다: $(echo "$EXPORTS_AFTER" | head -n 5 | tr '\n' '; ' | sed 's/; $//')"
      FAIL_FLAG=1
    else
      append_detail "/etc/exports(after) 유효 설정(주석/공백 제외) 없음"
    fi
  else
    append_detail "/etc/exports(after) 파일 없음"
  fi

  if [ "$FAIL_FLAG" -eq 0 ]; then
    IS_SUCCESS=1
    if [ "$MODIFIED" -eq 1 ]; then
      REASON_LINE="불필요한 NFS 관련 서비스/공유 설정이 비활성화되도록 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
    else
      REASON_LINE="NFS 관련 서비스/공유 설정이 이미 비활성화 상태로 유지되어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
    fi
  else
    IS_SUCCESS=0
    REASON_LINE="조치를 수행했으나 NFS 관련 서비스가 여전히 활성화 상태이거나 /etc/exports 설정이 남아 있어 조치가 완료되지 않았습니다."
  fi
fi

# detail 비어있으면 none
if [ -z "$DETAIL_CONTENT" ]; then
  DETAIL_CONTENT="none"
fi

# 에러 로그는 after 상태 뒤에 첨부(이전 설정은 포함하지 않음)
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