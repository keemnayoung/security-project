#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
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
CHECK_COMMAND='systemctl list-units --type=service 2>/dev/null | grep -E "(automount|autofs)" || echo "no_autofs_related_services"'

DETAIL_CONTENT=""
REASON_LINE=""

# automount/autofs 서비스 활성화 여부 점검
AUTOFS_SERVICES=$(systemctl list-units --type=service 2>/dev/null | grep -E "automount|autofs" | awk '{print $1}' | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g' | sed 's/[[:space:]]$//')

if [ -n "$AUTOFS_SERVICES" ]; then
  STATUS="FAIL"
  REASON_LINE="automount/autofs 서비스가 활성화되어 있어 자동 마운트 기능을 통한 비인가 접근 경로가 생길 수 있으므로 취약합니다. 실제 사용 여부(NFS/Samba/이동식 매체 자동 마운트 등)를 확인한 뒤 불필요하면 비활성화해야 합니다."
  DETAIL_CONTENT="active_services=${AUTOFS_SERVICES}"
else
  STATUS="PASS"
  REASON_LINE="automount/autofs 관련 서비스가 활성화되어 있지 않아 자동 마운트 기반 접근 위험이 없으므로 이 항목에 대한 보안 위협이 없습니다."
  DETAIL_CONTENT="no_active_services"
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