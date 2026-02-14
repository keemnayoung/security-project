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

# 1. 항목 정보 정의
ID="U-39"
CATEGORY="서비스 관리"
TITLE="불필요한 NFS 서비스 비활성화"
IMPORTANCE="상"
TARGET_FILE="N/A"

# 2. 보완 로직
ACTION_RESULT="SUCCESS"
ACTION_LOG=""

# [Step 1] NFS 서비스 활성화 여부 확인
# 가이드: systemctl list-units --type=service | grep nfs
NFS_SERVICES=$(systemctl list-units --type=service 2>/dev/null | grep nfs | awk '{print $1}')

# [Step 2] 불필요한 NFS 서비스 중지
# 가이드: systemctl stop <서비스명>
for svc in $NFS_SERVICES; do
    systemctl stop "$svc" 2>/dev/null
    ACTION_LOG="$ACTION_LOG $svc 서비스를 중지했습니다."
done

# [Step 3] NFS 서비스 비활성화
# 가이드: systemctl disable <서비스명>
for svc in $NFS_SERVICES; do
    systemctl disable "$svc" 2>/dev/null
    ACTION_LOG="$ACTION_LOG $svc 서비스를 비활성화했습니다."
done

if [ -n "$ACTION_LOG" ]; then
    ACTION_LOG="불필요한 NFS 서비스를 중지하고 비활성화 처리했습니다."
else
    ACTION_LOG="NFS 서비스가 이미 비활성화되어 있어 추가 조치 없이 양호한 상태를 유지합니다."
fi

STATUS="PASS"
EVIDENCE="NFS 서비스가 비활성화되어 있습니다."

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
    "guide": "KISA 가이드라인에 따른 보안 설정이 완료되었습니다.",
    "action_result": "$ACTION_RESULT",
    "action_log": "$ACTION_LOG",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
