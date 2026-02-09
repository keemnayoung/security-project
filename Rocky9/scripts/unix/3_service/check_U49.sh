#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-49
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : DNS 보안 버전 패치
# @Description : BIND 최신 버전 사용 유무 및 주기적 보안 패치 여부 점검
# @Criteria_Good : 주기적으로 패치를 관리하는 경우
# @Criteria_Bad : 주기적으로 패치를 관리하고 있지 않은 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-49 DNS 보안 버전 패치

# 1. 항목 정보 정의
ID="U-49"
CATEGORY="서비스 관리"
TITLE="DNS 보안 버전 패치"
IMPORTANCE="상"
TARGET_FILE="/usr/sbin/named"

# 2. 진단 로직 (무결성 해시 포함)
STATUS="PASS"
EVIDENCE=""
FILE_HASH="NOT_FOUND"

VULNERABLE=0
DNS_VERSION=""

# [Step 1] DNS 서비스 활성화 여부 확인
# 가이드: systemctl list-units --type=service | grep named
if systemctl list-units --type=service 2>/dev/null | grep -q "named"; then
    DNS_ACTIVE=1
else
    DNS_ACTIVE=0
fi

# [Step 3] BIND 버전 확인
# 가이드: named -v
if command -v named &>/dev/null; then
    DNS_VERSION=$(named -v 2>/dev/null)
    TARGET_FILE=$(command -v named)
    FILE_HASH=$(sha256sum "$TARGET_FILE" 2>/dev/null | awk '{print $1}')
fi

if [ $DNS_ACTIVE -eq 1 ]; then
    # DNS 서비스가 활성화된 경우 취약으로 판단 (최신 패치 확인 필요)
    STATUS="FAIL"
    if [ -n "$DNS_VERSION" ]; then
        EVIDENCE="DNS 서비스 실행 중 ($DNS_VERSION) - 최신 보안 패치 적용 여부 확인 필요"
    else
        EVIDENCE="DNS 서비스 실행 중이나 버전을 확인할 수 없음 - 수동 점검 필요"
    fi
else
    STATUS="PASS"
    EVIDENCE="DNS 서비스가 비활성화되어 있음"
fi


IMPACT_LEVEL="HIGH"
ACTION_IMPACT="DNS 서비스 보안 패치 적용 시 시스템 및 서비스에 영향을 줄 수 있습니다. 특히 DNS 서비스는 패치 적용에 따른 서비스 영향 정도를 정확히 파악한 뒤 주기적인 패치 적용 정책을 수립하여 운영에 미칠 수 있는 영향을 충분히 고려하고 단계적으로 적용해야 합니다."

# 3. 마스터 템플릿 표준 출력
echo ""
cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "BIND 최신 보안 버전으로 업데이트: dnf update bind 실행 후 named 서비스 재시작하세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
