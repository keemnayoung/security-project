#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-64
# @Category    : 패치 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : 주기적 보안 패치 및 벤더 권고사항 적용
# @Description : 시스템에서 최신 패치가 적용 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-64"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/os-release"
CHECK_COMMAND='cat /etc/os-release 2>/dev/null; uname -r; (command -v apt >/dev/null && apt list --upgradable 2>/dev/null) || (command -v dnf >/dev/null && dnf check-update --quiet 2>/dev/null) || (command -v yum >/dev/null && yum check-update -q 2>/dev/null)'

OS_NAME=""
OS_VERSION=""
OS_ID=""
EOL_STATUS="UNKNOWN"

# OS 정보 수집
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_NAME="$NAME"
    OS_VERSION="$VERSION_ID"
    OS_ID="$ID"
fi

KERNEL_VERSION=$(uname -r 2>/dev/null)

# EOL 판단(기준 로직은 기존 코드 유지)
case "$OS_ID" in
    ubuntu)
        case "$OS_VERSION" in
            14.04|16.04|18.04|20.04) EOL_STATUS="EOL" ;;
            *) EOL_STATUS="SUPPORTED" ;;
        esac
        ;;
    rocky)
        case "$OS_VERSION" in
            8|9|10) EOL_STATUS="SUPPORTED" ;;
            *) EOL_STATUS="UNKNOWN" ;;
        esac
        ;;
    centos)
        EOL_STATUS="EOL"
        ;;
    rhel)
        case "$OS_VERSION" in
            6|7) EOL_STATUS="EOL" ;;
            *) EOL_STATUS="SUPPORTED" ;;
        esac
        ;;
    *)
        EOL_STATUS="UNKNOWN"
        ;;
esac

# 패치 미적용 여부 점검
UPDATE_COUNT=0
UPDATE_INFO=""
PKG_MGR="UNKNOWN"

if command -v apt >/dev/null 2>&1; then
    PKG_MGR="APT"
    UPDATE_COUNT=$(apt list --upgradable 2>/dev/null | grep -vc "Listing")
    UPDATE_INFO="pkg_mgr=APT upgradable_count=${UPDATE_COUNT}"
elif command -v dnf >/dev/null 2>&1; then
    PKG_MGR="DNF"
    UPDATE_COUNT=$(dnf check-update --quiet 2>/dev/null | wc -l | tr -d ' ')
    UPDATE_INFO="pkg_mgr=DNF check_update_lines=${UPDATE_COUNT}"
elif command -v yum >/dev/null 2>&1; then
    PKG_MGR="YUM"
    UPDATE_COUNT=$(yum check-update -q 2>/dev/null | wc -l | tr -d ' ')
    UPDATE_INFO="pkg_mgr=YUM check_update_lines=${UPDATE_COUNT}"
else
    UPDATE_COUNT=-1
    UPDATE_INFO="pkg_mgr=UNKNOWN"
fi

# 종합 판단
if [ "$EOL_STATUS" = "EOL" ]; then
    STATUS="FAIL"
elif [ "$UPDATE_COUNT" -gt 0 ]; then
    STATUS="FAIL"
else
    STATUS="PASS"
fi

# 평가 이유 및 detail 구성
DETAIL_CONTENT="os_name=${OS_NAME:-unknown} os_id=${OS_ID:-unknown} os_version=${OS_VERSION:-unknown}"$'\n'
DETAIL_CONTENT+="kernel=${KERNEL_VERSION:-unknown}"$'\n'
DETAIL_CONTENT+="eol_status=${EOL_STATUS}"$'\n'
DETAIL_CONTENT+="${UPDATE_INFO}"

if [ "$STATUS" = "PASS" ]; then
    REASON_LINE="운영 중인 OS가 지원 상태로 판단되고 미적용 업데이트가 확인되지 않아 보안 패치가 최신 수준으로 유지되고 있으므로 이 항목에 대한 보안 위협이 없습니다."
else
    if [ "$EOL_STATUS" = "EOL" ]; then
        REASON_LINE="운영 중인 OS가 EOL(지원 종료) 상태로 판단되어 최신 보안 패치를 정상적으로 제공받기 어려우므로 취약합니다. 상위 버전 OS로 업그레이드하고 보안 패치 정책을 수립하여 주기적으로 적용해야 합니다."
    elif [ "$UPDATE_COUNT" -gt 0 ]; then
        REASON_LINE="미적용 보안 업데이트가 존재하여 알려진 취약점이 패치되지 않은 상태로 남을 수 있으므로 취약합니다. 서비스 영향도를 검토한 뒤 패치를 적용하고 주기적 업데이트 정책을 수립해야 합니다."
    else
        REASON_LINE="패치 상태를 정확히 판단하기 어려운 상태이므로 취약할 수 있습니다. 패키지 관리자/업데이트 정책을 확인하고 최신 보안 패치를 적용해야 합니다."
    fi
fi

# raw_evidence 구성 (첫 줄: 평가 이유 / 다음 줄부터: 현재 설정값)
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

# JSON escape 처리 (따옴표, 줄바꿈)
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/"/\\"/g' \
  | sed ':a;N;$!ba;s/\n/\\n/g')

# scan_history 저장용 JSON 출력
echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF

