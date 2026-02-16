#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-41
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 불필요한 automountd 제거
# @Description : automountd 서비스 데몬의 실행 여부 점검
# @Criteria_Good : automountd 서비스가 비활성화된 경우
# @Criteria_Bad :  automountd 서비스가 활성화된 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-41 불필요한 automountd 제거

# 기본 변수
ID="U-41"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="N/A"

# 핵심: 실행(active) + 부팅(enabled) 여부까지 확인
CHECK_COMMAND='
(systemctl list-units --type=service --all 2>/dev/null | grep -E "^[[:space:]]*autofs\.service" || echo "autofs_service_not_listed");
(systemctl list-units --type=socket --all 2>/dev/null | grep -E "^[[:space:]]*autofs\.socket" || echo "autofs_socket_not_listed");
(systemctl is-active autofs.service 2>/dev/null || echo "autofs.service:unknown");
(systemctl is-enabled autofs.service 2>/dev/null || echo "autofs.service:unknown");
(systemctl is-active autofs.socket 2>/dev/null || echo "autofs.socket:unknown");
(systemctl is-enabled autofs.socket 2>/dev/null || echo "autofs.socket:unknown");
'

DETAIL_CONTENT=""
REASON_LINE=""

# 실행 결과 수집(최소)
AUTOFS_SVC_ACTIVE="$(systemctl is-active autofs.service 2>/dev/null || echo unknown)"
AUTOFS_SVC_ENABLED="$(systemctl is-enabled autofs.service 2>/dev/null || echo unknown)"
AUTOFS_SOCK_ACTIVE="$(systemctl is-active autofs.socket 2>/dev/null || echo unknown)"
AUTOFS_SOCK_ENABLED="$(systemctl is-enabled autofs.socket 2>/dev/null || echo unknown)"

# 판단: active 이거나 enabled면 취약으로 처리(재부팅/재기동 시 활성화 가능)
VULN=0
if [ "$AUTOFS_SVC_ACTIVE" = "active" ] || [ "$AUTOFS_SVC_ENABLED" = "enabled" ] || \
   [ "$AUTOFS_SOCK_ACTIVE" = "active" ] || [ "$AUTOFS_SOCK_ENABLED" = "enabled" ]; then
  VULN=1
fi

if [ "$VULN" -eq 1 ]; then
  STATUS="FAIL"
  REASON_LINE="systemd에서 autofs 서비스/소켓이 실행 중이거나(enabled 포함) 자동 시작으로 설정되어 있어 자동 마운트 기능이 동작할 수 있으므로 취약합니다. 조치: 사용하지 않으면 'systemctl stop autofs.service autofs.socket' 후 'systemctl disable autofs.service autofs.socket' (필요 시 mask)로 비활성화하고, 적용 시 /etc/auto.* 또는 /etc/autofs* 설정 사용 여부를 함께 확인하세요."
  DETAIL_CONTENT="autofs.service(active=${AUTOFS_SVC_ACTIVE}, enabled=${AUTOFS_SVC_ENABLED}), autofs.socket(active=${AUTOFS_SOCK_ACTIVE}, enabled=${AUTOFS_SOCK_ENABLED})"
else
  STATUS="PASS"
  REASON_LINE="systemd에서 autofs 서비스/소켓이 실행 중이지 않고(enabled도 아님) 자동 시작으로 설정되어 있지 않아 자동 마운트 기능이 동작하지 않으므로 이 항목에 대한 보안 위협이 없습니다."
  DETAIL_CONTENT="autofs.service(active=${AUTOFS_SVC_ACTIVE}, enabled=${AUTOFS_SVC_ENABLED}), autofs.socket(active=${AUTOFS_SOCK_ACTIVE}, enabled=${AUTOFS_SOCK_ENABLED})"
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