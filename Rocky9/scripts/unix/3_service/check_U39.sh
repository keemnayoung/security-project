#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-39
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 불필요한 NFS 서비스 비활성화
# @Description : 불필요한 NFS 서비스 사용 여부 점검
# @Criteria_Good : 불필요한 NFS 서비스 관련 데몬이 비활성화된 경우
# @Criteria_Bad : 불필요한 NFS 서비스 관련 데몬이 활성화된 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================


# 기본 변수
ID="U-39"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="systemd(nfs-server, rpcbind 등), /etc/exports"

# 가이드(예시) + 실제 판정에 필요한 핵심 커맨드 포함
CHECK_COMMAND='
systemctl list-units --type=service 2>/dev/null | egrep -i "(nfs|rpcbind)" || echo "no_nfs_related_services";
for u in nfs-server.service rpcbind.service rpcbind.socket nfs-mountd.service nfs-idmapd.service rpc-statd.service nfsdcld.service; do
  systemctl is-enabled "$u" 2>/dev/null || true;
  systemctl is-active "$u" 2>/dev/null || true;
done;
[ -f /etc/exports ] && (grep -nEv "^[[:space:]]*#|^[[:space:]]*$" /etc/exports || echo "exports_empty") || echo "exports_not_found"
'

DETAIL_CONTENT=""
REASON_LINE=""

FOUND=0
FOUND_LINES=()

add_found() {
  local msg="$1"
  [ -n "$msg" ] && FOUND_LINES+=("$msg")
}

# 1) NFS 관련 unit 상태 점검 (서비스/소켓 포함)
# - 불필요 NFS 서비스 비활성화(가이드 취지) 관점에서 active 또는 enabled이면 "취약" 신호로 판단
UNITS=(
  "nfs-server.service"
  "rpcbind.service"
  "rpcbind.socket"
  "nfs-mountd.service"
  "nfs-idmapd.service"
  "rpc-statd.service"
  "nfsdcld.service"
)

for u in "${UNITS[@]}"; do
  ACTIVE_STATE="$(systemctl is-active "$u" 2>/dev/null || echo "unknown")"
  ENABLED_STATE="$(systemctl is-enabled "$u" 2>/dev/null || echo "unknown")"

  # active이면 즉시 취약 신호
  if [ "$ACTIVE_STATE" = "active" ] || [ "$ACTIVE_STATE" = "running" ] || [ "$ACTIVE_STATE" = "listening" ]; then
    FOUND=1
    add_found "systemd: $u 가 활성(active) 상태입니다. (is-active=$ACTIVE_STATE, is-enabled=$ENABLED_STATE)"
    continue
  fi

  # enabled이면 취약 신호 (masked/disabled는 양호로 간주, static은 enable 개념이 아니므로 단독으로는 취약 처리하지 않음)
  if [ "$ENABLED_STATE" = "enabled" ] || [ "$ENABLED_STATE" = "enabled-runtime" ]; then
    FOUND=1
    add_found "systemd: $u 가 부팅 시 자동 시작(enabled) 상태입니다. (is-enabled=$ENABLED_STATE, is-active=$ACTIVE_STATE)"
  else
    add_found "systemd: $u 상태(참고) (is-enabled=$ENABLED_STATE, is-active=$ACTIVE_STATE)"
  fi
done

# 2) /etc/exports 설정 존재 여부(참고/보조 신호)
# - 데몬이 꺼져 있어도 exports가 구성되어 있으면 NFS 사용 흔적이므로 FAIL 판단에 참고로 포함
if [ -f /etc/exports ]; then
  EXPORTS_ACTIVE="$(grep -nEv "^[[:space:]]*#|^[[:space:]]*$" /etc/exports 2>/dev/null || true)"
  if [ -n "$EXPORTS_ACTIVE" ]; then
    add_found "/etc/exports에 export 설정이 존재합니다(주석 제외). 예: $(echo "$EXPORTS_ACTIVE" | head -n 5 | tr '\n' '; ' | sed 's/; $//')"
  else
    add_found "/etc/exports는 존재하나 유효 export 설정(주석/공백 제외)은 없습니다."
  fi
else
  add_found "/etc/exports 파일이 존재하지 않습니다."
fi

# 결과 유무에 따른 PASS/FAIL 결정 + raw_evidence 문장 요구사항 반영
if [ "$FOUND" -eq 1 ]; then
  STATUS="FAIL"
  REASON_LINE="systemd에서 NFS 관련 서비스/소켓이 활성(active) 또는 자동 시작(enabled) 상태로 확인되어 취약합니다. (불필요한 NFS 사용 시 비인가 파일 공유·접근 경로가 될 수 있습니다.) 조치: NFS를 사용하지 않으면 'systemctl stop <서비스명>' 후 'systemctl disable <서비스명>'을 적용하고, 필요 시 /etc/exports의 공유 설정을 제거한 뒤 재확인하세요."
  DETAIL_CONTENT="$(printf "%s\n" "${FOUND_LINES[@]}")"
else
  STATUS="PASS"
  REASON_LINE="systemd에서 NFS 관련 서비스/소켓이 활성화되어 있지 않고(disabled/masked 등), 불필요한 NFS 공유가 동작할 수 있는 상태가 아니므로 이 항목에 대한 보안 위협이 없습니다."
  DETAIL_CONTENT="$(printf "%s\n" "${FOUND_LINES[@]}")"
fi

# raw_evidence 구성 (첫 줄: 평가 문장 / 다음 줄부터: 현재 설정값)
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

# scan_history 저장용 JSON 출력
echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF