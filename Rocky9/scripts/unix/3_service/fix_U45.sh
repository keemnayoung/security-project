#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.1.0
# @Author: 이가영
# @Last Updated: 2026-02-11
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-45
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 메일 서비스 버전 점검
# @Description : 메일 서비스 패키지 자동 업데이트 및 기준 버전 재검증
# ============================================================================

ID="U-45"
CATEGORY="서비스 관리"
TITLE="메일 서비스 버전 점검"
IMPORTANCE="상"

# 운영 기준 버전(사용자가 수정)
REQUIRED_SENDMAIL_VERSION="${REQUIRED_SENDMAIL_VERSION:-}"
REQUIRED_POSTFIX_VERSION="${REQUIRED_POSTFIX_VERSION:-}"
REQUIRED_EXIM_VERSION="${REQUIRED_EXIM_VERSION:-}"

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
    local pkg="$1"
    if command -v dnf >/dev/null 2>&1; then
        dnf -y update "$pkg" >/dev/null 2>&1
        return $?
    elif command -v yum >/dev/null 2>&1; then
        yum -y update "$pkg" >/dev/null 2>&1
        return $?
    elif command -v apt-get >/dev/null 2>&1; then
        apt-get update -y >/dev/null 2>&1
        apt-get install --only-upgrade -y "$pkg" >/dev/null 2>&1
        return $?
    fi
    return 1
}

failed=0
manual_needed=0
active_count=0

fix_service() {
    local name="$1"
    local service_name="$2"
    local package_name="$3"
    local required="$4"
    local version_cmd="$5"

    if ! systemctl is-active --quiet "$service_name"; then
        return
    fi

    active_count=$((active_count + 1))

    if [ -z "$required" ]; then
        ACTION_LOG+="$name: 기준 버전 미설정; "
        manual_needed=1
        return
    fi

    local installed
    installed=$(normalize_version "$(eval "$version_cmd" 2>/dev/null)")

    if [ -z "$installed" ]; then
        ACTION_LOG+="$name: 현재 버전 확인 실패; "
        failed=1
        return
    fi

    if ver_ge "$installed" "$required"; then
        ACTION_LOG+="$name: 이미 기준 충족($installed >= $required); "
        return
    fi

    if update_pkg "$package_name"; then
        systemctl restart "$service_name" >/dev/null 2>&1
        installed=$(normalize_version "$(eval "$version_cmd" 2>/dev/null)")
        if [ -n "$installed" ] && ver_ge "$installed" "$required"; then
            ACTION_LOG+="$name: 업데이트 후 기준 충족($installed >= $required); "
        else
            ACTION_LOG+="$name: 업데이트 후에도 기준 미충족(현재:$installed 기준:$required); "
            failed=1
        fi
    else
        ACTION_LOG+="$name: 패키지 업데이트 실패; "
        failed=1
    fi
}

fix_service "Postfix" "postfix" "postfix" "$REQUIRED_POSTFIX_VERSION" "postconf -d mail_version"
fix_service "Sendmail" "sendmail" "sendmail" "$REQUIRED_SENDMAIL_VERSION" "sendmail -d0 < /dev/null | grep -i Version"

if systemctl is-active --quiet exim; then
    fix_service "Exim" "exim" "exim" "$REQUIRED_EXIM_VERSION" "exim -bV | head -n1"
elif systemctl is-active --quiet exim4; then
    fix_service "Exim" "exim4" "exim" "$REQUIRED_EXIM_VERSION" "exim -bV | head -n1"
fi

if [ "$active_count" -eq 0 ]; then
    ACTION_LOG="실행 중인 메일 서비스가 없어 조치 대상이 없습니다."
elif [ "$failed" -eq 1 ]; then
    STATUS="FAIL"
    ACTION_RESULT="FAIL"
    EVIDENCE="일부 메일 서비스가 기준 버전을 충족하지 못했습니다."
elif [ "$manual_needed" -eq 1 ]; then
    STATUS="MANUAL"
    ACTION_RESULT="MANUAL"
    EVIDENCE="기준 버전 미설정으로 자동 조치가 제한됩니다. 운영 기준값 설정 후 재실행이 필요합니다."
else
    STATUS="PASS"
    ACTION_RESULT="SUCCESS"
    EVIDENCE="활성 메일 서비스의 버전 조치를 완료했습니다."
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
