#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 김나영
# @Last Updated: 2026-02-09
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-06
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : su 명령 사용 제한
# @Description : 특정 그룹(wheel)만 su 명령을 사용할 수 있도록 제한 설정 여부 점검
# @Criteria_Good : su 명령 사용 권한이 특정 그룹에만 부여되어 있는 경우
# @Criteria_Bad : su 명령 사용 권한이 모든 사용자에게 개방되어 있는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-06"
CATEGORY="계정관리"
TITLE="su 명령 사용 제한"
IMPORTANCE="상"
TARGET_FILE="/etc/pam.d/su"
IMPACT_LEVEL="MEDIUM"
ACTION_IMPACT="su 명령 사용이 제한된 wheel 그룹에 추가된 계정들은 현재 연결된 모든 세션(Session)을 종료하고 재로그인해야만 su 명령어를 정상적으로 사용할 수 있습니다. 기존에 접속 중인 세션에는 설정이 즉시 반영되지 않음을 유의해야 합니다."

STATUS="FAIL"
EVIDENCE="N/A"

if [ -f "$TARGET_FILE" ]; then
    # 1. pam_wheel.so 설정이 주석 해제되어 활성화된 라인 확인
    # 현업 기준: auth required pam_wheel.so use_uid 형태가 표준
    CHECK_WHEEL=$(grep -v '^#' "$TARGET_FILE" | grep "pam_wheel.so" | grep "auth" | grep "required")
    
    if [ -n "$CHECK_WHEEL" ]; then
        STATUS="PASS"
        # 실제 설정된 라인을 근거로 제시
        EVIDENCE="su 사용 제한 설정이 활성화 되어있습니다. ($(echo $CHECK_WHEEL | xargs))"
    else
        STATUS="FAIL"
        EVIDENCE="pam_wheel.so 설정이 비활성화되어 모든 사용자가 su 명령을 시도할 수 있습니다."
    fi
else
    STATUS="FAIL"
    EVIDENCE="설정 파일($TARGET_FILE)을 찾을 수 없습니다."
fi

echo ""
cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "guide": "/etc/pam.d/su 파일에서 pam_wheel.so 설정의 주석을 제거하여 wheel 그룹으로 제한하세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF