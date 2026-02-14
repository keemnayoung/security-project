#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
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

# [진단] U-39 불필요한 NFS 서비스 비활성화

# 1. 항목 정보 정의
ID="U-39"
CATEGORY="서비스 관리"
TITLE="불필요한 NFS 서비스 비활성화"
IMPORTANCE="상"
TARGET_FILE="N/A"

# 2. 진단 로직 (KISA 가이드 기준)
STATUS="PASS"
EVIDENCE=""
FILE_HASH="NOT_FOUND"

VULNERABLE=0

# [Step 1] NFS 서비스 활성화 여부 확인
# 가이드: systemctl list-units --type=service | grep nfs
NFS_SERVICES=$(systemctl list-units --type=service 2>/dev/null | grep nfs | awk '{print $1}' | tr '\n' ' ')
if [ -n "$NFS_SERVICES" ]; then
    VULNERABLE=1
    EVIDENCE="NFS 서비스 활성화: $NFS_SERVICES"
fi

# 결과 판단
if [ $VULNERABLE -eq 1 ]; then
    STATUS="FAIL"
    EVIDENCE="불필요한 NFS 서비스가 활성화되어 있어, 비인가 파일 접근이 발생할 수 있는 위험이 있습니다. $EVIDENCE"
else
    STATUS="PASS"
    EVIDENCE="NFS 서비스가 비활성화되어 있습니다."
fi

# JSON 출력 전 특수문자 제거
EVIDENCE=$(echo "$EVIDENCE" | tr '\n\r\t' '   ' | sed 's/"/\\"/g')

IMPACT_LEVEL="LOW"
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없으나, 기존에 NFS로 디렉터리를 공유/마운트하여 사용 중인 환경이라면 해당 공유 경로 접근이 중단될 수 있으므로, 적용 전 마운트/공유 디렉터리 정리 및 서비스 의존도 확인이 필요합니다."

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
    "guide": "NFS 서비스가 불필요한 경우 systemctl stop nfs-server && systemctl disable nfs-server로 비활성화해야 합니다.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
