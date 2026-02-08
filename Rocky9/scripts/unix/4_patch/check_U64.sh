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

# 1. 항목 정보 정의
CHECK_ID="U-64"
CATEGORY="패치 관리"
TITLE="주기적 보안 패치 및 벤더 권고사항 적용"
IMPORTANCE="상"
STATUS="PASS"
EVIDENCE=""
TARGET_FILE="/etc/os-release"
CHECK_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

# 2. OS 정보 수집
OS_NAME=""
OS_VERSION=""
OS_ID=""
EOL_STATUS="UNKNOWN"

if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_NAME="$NAME"
    OS_VERSION="$VERSION_ID"
    OS_ID="$ID"
fi

KERNEL_VERSION=$(uname -r)


# 3. EOL OS 판별 로직 (기준일: 2026년)
case "$OS_ID" in
    ubuntu)
        case "$OS_VERSION" in
            14.04|16.04|18.04|20.04)
                EOL_STATUS="EOL"
                ;;
            *)
                EOL_STATUS="SUPPORTED"
                ;;
        esac
        ;;
    rocky)
        case "$OS_VERSION" in
            8)
                EOL_STATUS="SUPPORTED"
                ;;
            9|10)
                EOL_STATUS="SUPPORTED"
                ;;
            *)
                EOL_STATUS="UNKNOWN"
                ;;
        esac
        ;;
    centos)
        EOL_STATUS="EOL"
        ;;
    rhel)
        case "$OS_VERSION" in
            6|7)
                EOL_STATUS="EOL"
                ;;
            *)
                EOL_STATUS="SUPPORTED"
                ;;
        esac
        ;;
    *)
        EOL_STATUS="UNKNOWN"
        ;;
esac


# 4. 패치 미적용 여부 점검
UPDATE_COUNT=0
UPDATE_INFO=""

if command -v apt >/dev/null 2>&1; then
    UPDATE_COUNT=$(apt list --upgradable 2>/dev/null | grep -vc "Listing")
    UPDATE_INFO="APT 기반 시스템, 미적용 업데이트 수: ${UPDATE_COUNT}"
elif command -v dnf >/dev/null 2>&1; then
    UPDATE_COUNT=$(dnf check-update --quiet 2>/dev/null | wc -l)
    UPDATE_INFO="DNF 기반 시스템, 미적용 업데이트 수: ${UPDATE_COUNT}"
elif command -v yum >/dev/null 2>&1; then
    UPDATE_COUNT=$(yum check-update -q 2>/dev/null | wc -l)
    UPDATE_INFO="YUM 기반 시스템, 미적용 업데이트 수: ${UPDATE_COUNT}"
else
    UPDATE_COUNT=-1
    UPDATE_INFO="패키지 관리자 확인 불가"
fi


# 5. 종합 판단
if [ "$EOL_STATUS" = "EOL" ]; then
    STATUS="FAIL"
elif [ "$UPDATE_COUNT" -gt 0 ]; then
    STATUS="FAIL"
fi


# 6. 증적 구성
EVIDENCE=$(cat <<EOF
[OS Information]
Name: ${OS_NAME}
Version: ${OS_VERSION}
Kernel: ${KERNEL_VERSION}

[EOL Status]
${EOL_STATUS}

[Patch Status]
${UPDATE_INFO}

※ EOL OS 사용 시 최신 보안 패치 적용이 불가능하므로 즉시 상위 버전 OS로 업그레이드 필요
※ 패치 적용 정책 수립 여부 및 주기적 관리 여부는 운영 정책 문서 확인 필요
EOF
)

# 6. JSON 출력
echo ""
cat <<EOF
{
  "check_id": "${CHECK_ID}",
  "category": "${CATEGORY}",
  "title": "${TITLE}",
  "importance": "${IMPORTANCE}",
  "status": "${STATUS}",
  "evidence": "$(echo "${EVIDENCE}" | sed ':a;N;$!ba;s/\n/\\n/g')",
  "target_file": "${TARGET_FILE}",
  "check_date": "${CHECK_DATE}"
}
EOF