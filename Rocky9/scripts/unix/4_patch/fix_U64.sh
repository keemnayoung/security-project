#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-64
# @Category    : 패치 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : 주기적 보안 패치 및 벤더 권고사항 적용
# @Description : 시스템에서 최신 패치가 적용 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#################
# 수동 조치 필요
#################

ID="U-64"
CATEGORY="패치 관리"
TITLE="주기적 보안 패치 및 벤더 권고사항 적용"
IMPORTANCE="상"
TARGET_FILE="/etc/os-release"

STATUS="PASS"
ACTION_RESULT="NO_ACTION"
ACTION_LOG="N/A"
EVIDENCE=""
GUIDE="OS 관리자 및 서비스 담당자는 패치 적용에 따른 영향도를 검토한 후, EOL 적용 전 최신 지원 버전 기준으로 OS 업그레이드 및 최신 보안 패치를 적용해야 합니다."

ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
CHECK_DATE="$(date '+%Y-%m-%d %H:%M:%S')"


# 1. OS 정보 수집
OS_NAME="UNKNOWN"
OS_VERSION="UNKNOWN"
OS_ID="UNKNOWN"
KERNEL_VERSION="$(uname -r)"

if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_NAME="$NAME"
    OS_VERSION="$VERSION_ID"
    OS_ID="$ID"
fi


# 2. EOL 적용 전 기준 판단
NEED_ACTION="NO"
RECOMMENDED_VERSION="현재 버전 유지"

case "$OS_ID" in
    ubuntu)
        case "$OS_VERSION" in
            18.04)
                NEED_ACTION="YES"
                RECOMMENDED_VERSION="Ubuntu 20.04 LTS 이상"
                ;;
            20.04)
                NEED_ACTION="YES"
                RECOMMENDED_VERSION="Ubuntu 22.04 LTS 이상"
                ;;
        esac
        ;;
    rocky)
        case "$OS_VERSION" in
            8)
                NEED_ACTION="YES"
                RECOMMENDED_VERSION="Rocky Linux 9 이상"
                ;;
        esac
        ;;
    centos)
        NEED_ACTION="YES"
        RECOMMENDED_VERSION="Rocky Linux 9 / AlmaLinux 9 / RHEL 9"
        ;;
    *)
        NEED_ACTION="YES"
        RECOMMENDED_VERSION="OS 식별 불가 – 관리자 수동 판단 필요"
        ;;
esac


# 3. 조치 결과 판단
if [ "$NEED_ACTION" = "YES" ]; then
    STATUS="FAIL"
    ACTION_RESULT="MANUAL_REQUIRED"
    ACTION_LOG="EOL 또는 지원 종료 예정 OS 사용 확인. EOL 적용 전 최신 지원 버전 기준으로 업그레이드 및 패치 정책 수립 필요."
    EVIDENCE="OS=${OS_NAME}, VERSION=${OS_VERSION}, KERNEL=${KERNEL_VERSION}"
else
    STATUS="PASS"
    ACTION_RESULT="NO_ACTION"
    ACTION_LOG="지원 중인 OS 사용 중이며 최신 패치 유지 정책에 따라 운영 중."
    EVIDENCE="OS=${OS_NAME}, VERSION=${OS_VERSION}, KERNEL=${KERNEL_VERSION}"
fi


# 4. JSON 표준 출력 (U-01과 동일 구조)
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
    "action_log": "$ACTION_LOG",
    "action_date": "$ACTION_DATE",
    "check_date": "$CHECK_DATE"
}
EOF