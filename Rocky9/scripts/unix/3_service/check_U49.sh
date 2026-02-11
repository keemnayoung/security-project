#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.1.0
# @Author: 이가영
# @Last Updated: 2026-02-11
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-49
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : DNS 보안 버전 패치
# @Description : BIND(named) 서비스가 기준 버전 이상인지 점검
# ============================================================================

ID="U-49"
CATEGORY="서비스 관리"
TITLE="DNS 보안 버전 패치"
IMPORTANCE="상"
TARGET_FILE="/usr/sbin/named"

# 운영 기준 버전(사용자가 수정)
REQUIRED_BIND_VERSION="${REQUIRED_BIND_VERSION:-}"

STATUS="PASS"
ACTION_RESULT="SUCCESS"
EVIDENCE=""
GUIDE=""
FILE_HASH="NOT_FOUND"
IMPACT_LEVEL="HIGH"
ACTION_IMPACT="DNS 패치는 서비스 재시작이 필요할 수 있으므로 운영 영향도를 검토한 뒤 적용해야 합니다."

normalize_version() {
    echo "$1" | grep -Eo '[0-9]+(\.[0-9]+)+' | head -n1
}

ver_ge() {
    [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]
}

DNS_ACTIVE=0
if systemctl is-active --quiet named || pgrep -x named >/dev/null 2>&1; then
    DNS_ACTIVE=1
fi

if [ "$DNS_ACTIVE" -eq 0 ]; then
    STATUS="PASS"
    ACTION_RESULT="SUCCESS"
    EVIDENCE="DNS(named) 서비스가 비활성화되어 있습니다."
    GUIDE="KISA 보안 가이드라인을 준수하고 있습니다."
else
    if command -v named >/dev/null 2>&1; then
        TARGET_FILE="$(command -v named)"
        FILE_HASH=$(sha256sum "$TARGET_FILE" 2>/dev/null | awk '{print $1}')
        INSTALLED_BIND_VERSION=$(normalize_version "$(named -v 2>/dev/null)")
    else
        INSTALLED_BIND_VERSION=""
    fi

    if [ -z "$REQUIRED_BIND_VERSION" ]; then
        STATUS="MANUAL"
        ACTION_RESULT="MANUAL_REQUIRED"
        EVIDENCE="기준 버전(REQUIRED_BIND_VERSION)이 설정되지 않았습니다."
        GUIDE="check_U49.sh와 fix_U49.sh의 REQUIRED_BIND_VERSION에 최신 기준 버전을 설정하십시오."
    elif [ -z "$INSTALLED_BIND_VERSION" ]; then
        STATUS="FAIL"
        ACTION_RESULT="MANUAL_REQUIRED"
        EVIDENCE="named 버전을 확인할 수 없습니다."
        GUIDE="named 패키지 상태를 확인하고 fix_U49.sh로 자동 업데이트 후 재점검하십시오."
    elif ver_ge "$INSTALLED_BIND_VERSION" "$REQUIRED_BIND_VERSION"; then
        STATUS="PASS"
        ACTION_RESULT="SUCCESS"
        EVIDENCE="BIND 버전 $INSTALLED_BIND_VERSION (기준 $REQUIRED_BIND_VERSION 이상)"
        GUIDE="기준 버전을 충족합니다."
    else
        STATUS="FAIL"
        ACTION_RESULT="MANUAL_REQUIRED"
        EVIDENCE="BIND 버전 $INSTALLED_BIND_VERSION (기준 $REQUIRED_BIND_VERSION 미만)"
        GUIDE="fix_U49.sh 조치를 실행해 패키지 자동 업데이트 후 재점검하십시오."
    fi
fi

echo ""
cat << EOF_JSON
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
    "file_hash": "$FILE_HASH",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF_JSON
