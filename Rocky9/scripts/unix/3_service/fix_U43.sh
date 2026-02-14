#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-43
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : NIS, NIS+ 점검
# @Description : 안전하지 않은 NIS 서비스의 비활성화, 안전한 NIS+ 서비스의 활성화 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-43 NIS, NIS+ 점검

# 기본 변수
ID="U-43"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

TARGET_FILE="systemd(NIS/NIS+ related services)"

# 대표 NIS/NIS+ 유닛 후보(환경별로 이름이 다를 수 있어 후보를 넓게)
NIS_UNITS_CANDIDATES=(
  "ypserv.service"
  "ypbind.service"
  "ypxfrd.service"
  "yppasswdd.service"
  "rpc-yppasswdd.service"
  "ypupdated.service"
  "rpc-ypupdated.service"
)

CHECK_COMMAND='
(command -v systemctl >/dev/null 2>&1 && (
  systemctl list-unit-files 2>/dev/null | grep -Ei "^(ypserv|ypbind|ypxfrd|yppasswdd|rpc-yppasswdd|ypupdated|rpc-ypupdated)\.service[[:space:]]" || echo "nis_unit_files_not_found";
  for u in ypserv.service ypbind.service ypxfrd.service yppasswdd.service rpc-yppasswdd.service ypupdated.service rpc-ypupdated.service; do
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
  ACTION_ERR_LOG="(주의) root 권한이 아니면 systemctl stop/disable/mask 조치가 실패할 수 있습니다."
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

disable_systemd_unit_if_exists() {
  local unit="$1"
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl list-unit-files 2>/dev/null | grep -qiE "^${unit}[[:space:]]" || return 0

  systemctl stop "$unit" 2>/dev/null || append_err "systemctl stop ${unit} 실패"
  systemctl disable "$unit" 2>/dev/null || append_err "systemctl disable ${unit} 실패"
  systemctl mask "$unit" 2>/dev/null || append_err "systemctl mask ${unit} 실패"
  MODIFIED=1
}

# ---------------------------
# 조치 수행
# ---------------------------
if ! command -v systemctl >/dev/null 2>&1; then
  IS_SUCCESS=0
  REASON_LINE="systemctl 명령을 사용할 수 없어 NIS/NIS+ 서비스 비활성화 조치를 수행할 수 없습니다."
  DETAIL_CONTENT="systemctl_not_found"
else
  for u in "${NIS_UNITS_CANDIDATES[@]}"; do
    disable_systemd_unit_if_exists "$u"
  done

  # ---------------------------
  # 조치 후 검증(현재/조치 후 상태만)
  # ---------------------------
  for u in "${NIS_UNITS_CANDIDATES[@]}"; do
    if systemctl list-unit-files 2>/dev/null | grep -qiE "^${u}[[:space:]]"; then
      en="$(systemctl is-enabled "$u" 2>/dev/null || echo unknown)"
      ac="$(systemctl is-active "$u" 2>/dev/null || echo unknown)"
      append_detail "${u}(after) enabled=$en active=$ac"

      echo "$en" | grep -qiE "enabled" && FAIL_FLAG=1
      echo "$ac" | grep -qiE "active" && FAIL_FLAG=1
    fi
  done

  if [ "$FAIL_FLAG" -eq 0 ]; then
    IS_SUCCESS=1
    if [ "$MODIFIED" -eq 1 ]; then
      REASON_LINE="안전하지 않은 NIS/NIS+ 서비스가 비활성화되도록 설정이 변경되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
    else
      REASON_LINE="NIS/NIS+ 서비스가 이미 비활성화 상태로 유지되어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
    fi
  else
    IS_SUCCESS=0
    REASON_LINE="조치를 수행했으나 NIS/NIS+ 서비스가 여전히 활성화 상태이거나 검증 기준을 충족하지 못해 조치가 완료되지 않았습니다."
  fi
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
