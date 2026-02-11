#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.1.0
# @Author: 이가영
# @Last Updated: 2026-02-11
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-49
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : DNS 보안 버전 패치
# @Description : BIND(named) 자동 업데이트 및 기준 버전 재검증
# ============================================================================

ID="U-49"
CATEGORY="서비스 관리"
TITLE="DNS 보안 버전 패치"
IMPORTANCE="상"

# 운영 기준 버전(사용자가 수정)
REQUIRED_BIND_VERSION="${REQUIRED_BIND_VERSION:-}"

STATUS="PASS"
ACTION_RESULT="SUCCESS"
EVIDENCE="취약점 조치가 완료되었습니다."
ACTION_LOG=""

normalize_version() {
    echo "$1" | grep -Eo '[0-9]+(\.[0-9]+)+' | head -n1
}

ver_ge() {
    [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]
}

update_pkg() {
    if command -v dnf >/dev/null 2>&1; then
        dnf -y update bind bind-utils >/dev/null 2>&1
        return $?
    elif command -v yum >/dev/null 2>&1; then
        yum -y update bind bind-utils >/dev/null 2>&1
        return $?
    elif command -v apt-get >/dev/null 2>&1; then
        apt-get update -y >/dev/null 2>&1
        apt-get install --only-upgrade -y bind9 >/dev/null 2>&1
        return $?
    fi
    return 1
}

DNS_ACTIVE=0
if systemctl is-active --quiet named || pgrep -x named >/dev/null 2>&1; then
    DNS_ACTIVE=1
fi

if [ "$DNS_ACTIVE" -eq 0 ]; then
    ACTION_LOG="DNS(named) 서비스가 비활성화되어 조치 대상이 없습니다."
else
    if [ -z "$REQUIRED_BIND_VERSION" ]; then
        STATUS="MANUAL"
        ACTION_RESULT="MANUAL"
        EVIDENCE="기준 버전(REQUIRED_BIND_VERSION)이 설정되지 않았습니다."
        ACTION_LOG="check_U49.sh와 fix_U49.sh의 REQUIRED_BIND_VERSION 값을 먼저 설정하세요."
    elif ! command -v named >/dev/null 2>&1; then
        STATUS="FAIL"
        ACTION_RESULT="FAIL"
        EVIDENCE="named 명령어를 찾을 수 없습니다."
        ACTION_LOG="BIND 패키지 상태를 점검한 뒤 수동 조치가 필요합니다."
    else
        current_ver=$(normalize_version "$(named -v 2>/dev/null)")

        if [ -n "$current_ver" ] && ver_ge "$current_ver" "$REQUIRED_BIND_VERSION"; then
            ACTION_LOG="이미 기준 버전 충족($current_ver >= $REQUIRED_BIND_VERSION)"
        else
            if update_pkg; then
                systemctl restart named >/dev/null 2>&1
                new_ver=$(normalize_version "$(named -v 2>/dev/null)")

                if [ -n "$new_ver" ] && ver_ge "$new_ver" "$REQUIRED_BIND_VERSION"; then
                    ACTION_LOG="BIND 업데이트 완료($new_ver >= $REQUIRED_BIND_VERSION)"
                else
                    STATUS="FAIL"
                    ACTION_RESULT="FAIL"
                    EVIDENCE="자동 업데이트 후에도 기준 버전 미충족"
                    ACTION_LOG="현재 버전:$new_ver / 기준:$REQUIRED_BIND_VERSION"
                fi
            else
                STATUS="FAIL"
                ACTION_RESULT="FAIL"
                EVIDENCE="BIND 자동 업데이트 실패"
                ACTION_LOG="패키지 매니저(dnf/yum/apt) 실행 또는 저장소 상태를 확인하세요."
            fi
        fi
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
    "guide": "KISA 가이드라인에 따른 보안 설정이 완료되었습니다.",
    "action_result": "$ACTION_RESULT",
    "action_log": "$ACTION_LOG",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF_JSON
