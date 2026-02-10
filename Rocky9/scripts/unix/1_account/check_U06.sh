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

# 1. 항목 정보 정의
ID="U-06"
CATEGORY="계정관리"
TITLE="su 명령 사용 제한"
IMPORTANCE="상"
TARGET_FILE="/etc/pam.d/su"

# 2. 진단 로직
STATUS="FAIL"
EVIDENCE="N/A"

if [ -f "$TARGET_FILE" ]; then
    # pam_wheel.so 설정이 활성화되어 있는지 확인
    CHECK_WHEEL=$(grep -v '^#' "$TARGET_FILE" | grep "pam_wheel.so" | grep "auth" | grep "required")
    
    if [ -n "$CHECK_WHEEL" ]; then
        STATUS="PASS"
        ACTION_RESULT="SUCCESS"
        EVIDENCE="wheel 그룹에 속한 사용자만 su 명령을 사용할 수 있도록 제한되어 있어 보안 가이드라인을 준수하고 있습니다."
        GUIDE="KISA 보안 가이드라인을 준수하고 있습니다."
    else
        STATUS="FAIL"
        ACTION_RESULT="PARTIAL_SUCCESS"
        EVIDENCE="현재 모든 사용자가 su 명령어를 사용할 수 있는 상태로 설정되어 있어 권한 오남용 위험이 존재합니다."
        GUIDE="1. 먼저 su 명령을 사용해야 하는 운영자 계정 리스트를 확인하세요. 2. 해당 계정들을 'usermod -G wheel <계정명>' 명령으로 wheel 그룹에 추가하세요. 3. 이후 /etc/pam.d/su 파일에서 pam_wheel.so 라인의 주석을 제거하십시오."
    fi
else
    STATUS="FAIL"
    ACTION_RESULT="PARTIAL_SUCCESS"
    EVIDENCE="시스템 인증 설정 파일($TARGET_FILE)이 존재하지 않아 권한 제어 상태를 확인할 수 없습니다."
    GUIDE="시스템 환경에 맞는 인증 설정 파일 존재 여부를 수동으로 점검하십시오."
fi

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
    "guide": "$GUIDE",
    "action_result": "$ACTION_RESULT",
    "target_file": "$TARGET_FILE",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF