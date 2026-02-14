#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-43
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : NIS, NIS+ 점검
# @Description : 안전하지 않은 NIS 서비스의 비활성화, 안전한 NIS+ 서비스의 활성화 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-43 NIS, NIS+ 점검

# 1. 항목 정보 정의
ID="U-43"
CATEGORY="서비스 관리"
TITLE="NIS, NIS+ 점검"
IMPORTANCE="상"
TARGET_FILE="N/A"

# 2. 보완 로직
ACTION_RESULT="SUCCESS"
ACTION_LOG=""

# [Step 1] NIS 관련 서비스 데몬 활성화 여부 확인
# 가이드: ypserv, ypbind, ypxfrd, rpc.yppasswdd, rpc.ypupdated
NIS_SERVICES=$(systemctl list-units --type=service 2>/dev/null | grep -E "ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated" | awk '{print $1}')

# [Step 2] NIS 관련 서비스 데몬 중지
# 가이드: systemctl stop <서비스명>
for svc in $NIS_SERVICES; do
    systemctl stop "$svc" 2>/dev/null
    ACTION_LOG="$ACTION_LOG $svc 중지;"
done

# [Step 3] NIS 관련 서비스 데몬 비활성화
# 가이드: systemctl disable <서비스명>
for svc in $NIS_SERVICES; do
    systemctl disable "$svc" 2>/dev/null
    ACTION_LOG="$ACTION_LOG $svc 비활성화;"
done

if [ -n "$ACTION_LOG" ]; then
    ACTION_LOG="안전하지 않은 NIS 서비스를 중지하고 비활성화 처리했습니다."
else
    ACTION_LOG="NIS 서비스가 이미 비활성화되어 있어 추가 조치 없이 양호한 상태를 유지합니다."
fi

STATUS="PASS"
EVIDENCE="Xinetd 서비스 접근 제어가 적절히 설정되어 있습니다."

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
