#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 권순형
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-64
# @Category    : 패치 관리
# @Platform    : Debian
# @Importance  : 상
# @Title       : 주기적 보안 패치 및 벤더 권고사항 적용
# @Description : 시스템에서 최신 패치가 적용 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#################
# 수동 조치 필요
#################

# 1. 필수 변수 정의
ID="U-64"
TARGET_FILE="/etc/os-release"
ACTION_RESULT="NONE"
ACTION_LOG=""
BEFORE_SETTING=""
AFTER_SETTING=""
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"


# 2. OS 정보 수집
OS_NAME=""
OS_VERSION=""
OS_ID=""

if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_NAME="$NAME"
    OS_VERSION="$VERSION_ID"
    OS_ID="$ID"
fi

KERNEL_VERSION=$(uname -r)

BEFORE_SETTING="OS=${OS_NAME}, VERSION=${OS_VERSION}, KERNEL=${KERNEL_VERSION}"


# 3. EOL 적용 전 기준 버전 산정
RECOMMENDED_ACTION="유지"
NEED_ACTION="NO"

case "$OS_ID" in
    ubuntu)
        case "$OS_VERSION" in
            18.04)
                RECOMMENDED_ACTION="Ubuntu 20.04 LTS 이상으로 업그레이드"
                NEED_ACTION="YES"
                ;;
            20.04)
                RECOMMENDED_ACTION="Ubuntu 22.04 LTS 이상으로 업그레이드"
                NEED_ACTION="YES"
                ;;
            *)
                RECOMMENDED_ACTION="현재 지원 버전 유지 및 최신 패치 적용"
                ;;
        esac
        ;;
    rocky)
        case "$OS_VERSION" in
            8)
                RECOMMENDED_ACTION="Rocky Linux 9 이상으로 업그레이드"
                NEED_ACTION="YES"
                ;;
            *)
                RECOMMENDED_ACTION="현재 지원 버전 유지 및 최신 패치 적용"
                ;;
        esac
        ;;
    centos)
        RECOMMENDED_ACTION="Rocky Linux 9 / AlmaLinux 9 / RHEL 9 전환"
        NEED_ACTION="YES"
        ;;
    *)
        RECOMMENDED_ACTION="OS 식별 불가 – 관리자 수동 판단 필요"
        NEED_ACTION="YES"
        ;;
esac


# 4. 패치 적용 조치 판단
if [ "$NEED_ACTION" = "YES" ]; then
    ACTION_RESULT="MANUAL_REQUIRED"
    ACTION_LOG="EOL 또는 지원 종료 예정 OS 확인. EOL 적용 전 최신 지원 버전 기준으로 OS 업그레이드 및 최신 패치 적용 필요."
else
    ACTION_RESULT="NO_ACTION"
    ACTION_LOG="지원 중인 OS 사용 중. 정기적인 패치 정책에 따라 최신 패치 유지 필요."
fi

AFTER_SETTING="${RECOMMENDED_ACTION}"


# 5. JSON 출력
echo ""
cat <<EOF
{
  "check_id": "${ID}",
  "action_result": "${ACTION_RESULT}",
  "before_setting": "${BEFORE_SETTING}",
  "after_setting": "${AFTER_SETTING}",
  "action_log": "${ACTION_LOG}",
  "action_date": "${ACTION_DATE}"
}
EOF