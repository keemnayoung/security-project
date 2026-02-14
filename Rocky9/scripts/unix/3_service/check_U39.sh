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
CHECK_COMMAND='systemctl list-units --type=service 2>/dev/null | egrep -i "(nfs|rpcbind)" || echo "no_nfs_related_services"; systemctl is-enabled nfs-server 2>/dev/null || true; systemctl is-active nfs-server 2>/dev/null || true; [ -f /etc/exports ] && (grep -nEv "^[[:space:]]*#|^[[:space:]]*$" /etc/exports || echo "exports_empty") || echo "exports_not_found"'

DETAIL_CONTENT=""
REASON_LINE=""

FOUND=0
FOUND_LINES=()

add_found() {
  local msg="$1"
  [ -n "$msg" ] && FOUND_LINES+=("$msg")
}

# 1) systemd에서 NFS 관련 서비스 활성/로딩 여부 확인
# - 단순 "list-units에서 보인다"가 아니라, loaded/active 상태 중심으로 판단(오탐 완화)
NFS_UNITS_RAW=$(systemctl list-units --type=service 2>/dev/null | egrep -i "(^| )(nfs|rpcbind)" || true)
if [ -n "$NFS_UNITS_RAW" ]; then
  # ACTIVE 상태(3열: ACTIVE) 기준으로 필터링
  NFS_ACTIVE=$(echo "$NFS_UNITS_RAW" | awk '$4=="running" || $4=="exited" || $4=="waiting" || $4=="listening" {print}')
  if [ -n "$NFS_ACTIVE" ]; then
    FOUND=1
    add_found "systemd 활성 NFS 관련 unit 감지: $(echo "$NFS_ACTIVE" | awk '{print $1"("$4")"}' | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
  else
    # 로딩은 되었지만 active가 아닌 경우는 참고 정보로만 표시
    add_found "systemd에 NFS 관련 unit이 있으나 active 상태는 아님(참고): $(echo "$NFS_UNITS_RAW" | awk '{print $1"("$4")"}' | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
  fi
fi

# 2) /etc/exports에 실제 export 설정이 존재하면(NFS 사용 가능성) 취약(불필요 서비스 관점)
# - 주석/공백 제외하고 라인이 있으면 "사용 중" 신호로 간주
if [ -f /etc/exports ]; then
  EXPORTS_ACTIVE=$(grep -nEv "^[[:space:]]*#|^[[:space:]]*$" /etc/exports 2>/dev/null || true)
  if [ -n "$EXPORTS_ACTIVE" ]; then
    FOUND=1
    add_found "/etc/exports에 export 설정 존재(주석 제외): $(echo "$EXPORTS_ACTIVE" | head -n 5 | tr '\n' '; ' | sed 's/; $//')"
  fi
fi

# 결과 유무에 따른 PASS/FAIL 결정
if [ "$FOUND" -eq 1 ]; then
  STATUS="FAIL"
  REASON_LINE="NFS 서비스(또는 export 설정)가 활성화/구성되어 있어, 불필요한 경우 비인가 파일 공유·접근 경로가 될 수 있으므로 취약합니다. 실제 사용 여부를 확인한 뒤 불필요하면 비활성화해야 합니다."
  DETAIL_CONTENT=$(printf "%s\n" "${FOUND_LINES[@]}")
else
  STATUS="PASS"
  REASON_LINE="NFS 서비스가 활성화되어 있지 않고(/etc/exports에 유효 설정도 확인되지 않아), 불필요한 파일 공유로 인한 비인가 접근 가능성이 없으므로 이 항목에 대한 보안 위협이 없습니다."
  DETAIL_CONTENT="none"
fi

# raw_evidence 구성 (첫 줄: 평가 이유 / 다음 줄부터: 현재 설정값)
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