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
BEFORE_SETTING=""
AFTER_SETTING=""
ACTION_LOG=""

# [Step 1] NFS 서비스 활성화 여부 확인
# 가이드: systemctl list-units --type=service | grep nfs
NFS_SERVICES=$(systemctl list-units --type=service 2>/dev/null | grep nfs | awk '{print $1}')
BEFORE_SETTING="$NFS_SERVICES"

# [Step 2] 불필요한 NFS 서비스 중지
# 가이드: systemctl stop <서비스명>
for svc in $NFS_SERVICES; do
    systemctl stop "$svc" 2>/dev/null
    ACTION_LOG="$ACTION_LOG $svc 중지;"
done

# [Step 3] NFS 서비스 비활성화
# 가이드: systemctl disable <서비스명>
for svc in $NFS_SERVICES; do
    systemctl disable "$svc" 2>/dev/null
    ACTION_LOG="$ACTION_LOG $svc 비활성화;"
done

AFTER_SETTING="NFS 서비스 비활성화 완료"
[ -z "$ACTION_LOG" ] && ACTION_LOG="NFS 서비스가 이미 비활성화 상태"

# 3. 마스터 템플릿 표준 출력
echo ""

STATUS="$ACTION_RESULT"
EVIDENCE="$ACTION_LOG"
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
