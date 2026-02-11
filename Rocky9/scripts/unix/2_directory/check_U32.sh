#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-32
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 중
# @Title       : 홈 디렉토리로 지정한 디렉토리의 존재 관리
# @Description : 사용자 계정과 홈 디렉토리의 일치 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 1. 항목 정보 정의
ID="U-32"
CATEGORY="파일 및 디렉토리 관리"
TITLE="홈 디렉토리로 지정한 디렉토리의 존재 관리"
IMPORTANCE="중"
STATUS="PASS"
EVIDENCE="홈 디렉토리가 존재하지 않는 계정이 발견되지 않음"
GUIDE="해당 항목은 자동 조치 시 시스템 장애 위험이 커서 자동 조치 기능을 제공하지 않습니다. 관리자가 직접 홈 디렉토리가 존재하지 않는 계정에 홈 디렉토리를 설정하거나 계정을 제거해주세요."
ACTION_RESULT="N/A"
IMPACT_LEVEL="LOW" 
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없으나, 잘못된 계정에 조치할 경우 기존 서비스나 배치 작업의 실행 경로에 영향을 줄 수 있습니다."
TARGET_FILE="/etc/passwd"
FILE_HASH="$(sha256sum /etc/passwd 2>/dev/null | awk '{print $1}')"
CHECK_DATE=$(date +"%Y-%m-%d %H:%M:%S")


# 2. 진단 로직
MISSING_HOME_USERS=()

while IFS=: read -r username _ uid _ _ homedir; do
    # 시스템 계정 제외 (UID 1000 미만)
    if [ "$uid" -ge 1000 ]; then
        if [ ! -d "$homedir" ]; then
            MISSING_HOME_USERS+=("$username:$homedir")
        fi
    fi
done < "$TARGET_FILE"

if [ "${#MISSING_HOME_USERS[@]}" -ne 0 ]; then
    STATUS="FAIL"
    ACTION_RESULT="PARTIAL_SUCCESS"

    IFS=", "
    JOINED_USERS="${MISSING_HOME_USERS[*]}"
    unset IFS

    EVIDENCE="다음과 같은 홈 디렉토리가 존재하지 않는 계정이 발견되었습니다. ($JOINED_USERS)"
fi

if [ "$STATUS" == "PASS" ]; then
    ACTION_RESULT="SUCCESS"
    EVIDENCE="사용자 계정들이 모두 홈 디렉토리를 소유하고 있어 이 항목에 대한 보안 위협이 없습니다."
    GUIDE="KISA 보안 가이드라인을 준수하고 있습니다."
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
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "guide": "$GUIDE",
    "action_result": "$ACTION_RESULT",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$CHECK_DATE"
}
EOF