#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-43
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : NIS, NIS+ 점검
# @Description : 안전하지 않은 NIS 서비스의 비활성화, 안전한 NIS+ 서비스의 활성화 여부 점검
# @Criteria_Good : NIS 서비스가 비활성화되어 있거나, 불가피하게 사용 시 NIS+ 서비스를 사용하는 경우
# @Criteria_Bad : NIS 서비스가 활성화된 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-43 NIS, NIS+ 점검

# 기본 변수
ID="U-43"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="N/A"
CHECK_COMMAND='systemctl list-units --type=service 2>/dev/null | grep -E "ypserv|ypbind|ypxfrd|rpc\.yppasswdd|rpc\.ypupdated|yppasswdd|ypupdated" || echo "no_nis_related_services"'

DETAIL_CONTENT=""
REASON_LINE=""


# NIS/NIS+ 관련 서비스 감지
# (Rocky Linux 계열에서는 보통 ypserv/ypbind 중심. 환경에 따라 rpc.yppasswdd 등 존재 가능)
NIS_SERVICES=$(systemctl list-units --type=service 2>/dev/null \
  | grep -E "ypserv|ypbind|ypxfrd|rpc\.yppasswdd|rpc\.ypupdated|yppasswdd|ypupdated" \
  | awk '{print $1}' | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g' | sed 's/[[:space:]]$//')

if [ -n "$NIS_SERVICES" ]; then
  STATUS="FAIL"
  REASON_LINE="NIS/NIS+ 관련 서비스가 활성화되어 있으면 인증/계정 정보가 네트워크로 노출될 수 있어 취약합니다. 실제 사용 여부(레거시 의존성)를 확인한 뒤 불필요하면 중지/비활성화가 필요합니다."
  DETAIL_CONTENT="active_services=${NIS_SERVICES}"
else
  STATUS="PASS"
  REASON_LINE="NIS/NIS+ 관련 서비스가 활성화된 정황이 확인되지 않아 이 항목에 대한 보안 위협이 없습니다."
  DETAIL_CONTENT="no_nis_service_active"
fi

# raw_evidence 구성 (첫 줄: 평가 이유 / 다음 줄: 현재 설정값)
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