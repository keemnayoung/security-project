#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
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

# 1. 항목 정보 정의
ID="U-43"
CATEGORY="서비스 관리"
TITLE="NIS, NIS+ 점검"
IMPORTANCE="상"
TARGET_FILE="N/A"

# 2. 진단 로직 (KISA 가이드 기준)
STATUS="PASS"
EVIDENCE=""
FILE_HASH="NOT_FOUND"

VULNERABLE=0

# [Step 1] NIS 관련 서비스 데몬 활성화 여부 확인
# 가이드: systemctl list-units --type=service | grep -E "ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated"
NIS_SERVICES=$(systemctl list-units --type=service 2>/dev/null | grep -E "ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated" | awk '{print $1}' | tr '\n' ' ')

if [ -n "$NIS_SERVICES" ]; then
    VULNERABLE=1
    EVIDENCE="NIS 관련 서비스 활성화: $NIS_SERVICES"
fi

# 결과 판단
if [ $VULNERABLE -eq 1 ]; then
    STATUS="FAIL"
    EVIDENCE="NIS 서비스 활성화:$EVIDENCE"
else
    STATUS="PASS"
    EVIDENCE="NIS 관련 서비스가 비활성화되어 있음"
fi

# JSON 출력 전 특수문자 제거
EVIDENCE=$(echo "$EVIDENCE" | tr '\n\r\t' '   ' | sed 's/"/\\"/g')


IMPACT_LEVEL="LOW"
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없으나, NIS를 불가피하게 사용 중인 환경에서는 운영 정책(사용 여부/대체 서비스 적용 여부)에 따라 영향이 달라질 수 있으므로 적용 범위를 사전에 점검한 뒤 설정을 반영해야 합니다."

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
    "guide": "NIS 서비스가 불필요한 경우 systemctl stop ypserv ypbind && systemctl disable ypserv ypbind로 비활성화하세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
