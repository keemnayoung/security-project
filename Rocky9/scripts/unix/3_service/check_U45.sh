#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.1.0
# @Author: 이가영
# @Last Updated: 2026-02-11
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-45
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 메일 서비스 버전 점검
# @Description : 메일 서비스가 기준 버전 이상인지 점검
# ============================================================================

ID="U-45"
CATEGORY="서비스 관리"
TITLE="메일 서비스 버전 점검"
IMPORTANCE="상"
TARGET_FILE="/etc/postfix/main.cf"

# 운영 기준 버전(사용자가 수정)
REQUIRED_SENDMAIL_VERSION="${REQUIRED_SENDMAIL_VERSION:-}"
REQUIRED_POSTFIX_VERSION="${REQUIRED_POSTFIX_VERSION:-}"
REQUIRED_EXIM_VERSION="${REQUIRED_EXIM_VERSION:-}"

STATUS="PASS"
ACTION_RESULT="SUCCESS"
EVIDENCE=""
GUIDE=""
FILE_HASH="NOT_FOUND"
IMPACT_LEVEL="HIGH"
ACTION_IMPACT="메일 서비스 버전 업데이트는 서비스 재시작이 필요할 수 있으므로, 운영 영향도를 검토 후 적용해야 합니다."

normalize_version() {
    echo "$1" | grep -Eo '[0-9]+(\.[0-9]+)+' | head -n1
}

ver_ge() {
    # $1: installed, $2: required
    [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]
}

fail_count=0
manual_count=0
active_count=0
evidence_lines=()

check_service() {
    local svc="$1"
    local required="$2"
    local version_raw="$3"
    local conf_file="$4"

    local installed
    installed=$(normalize_version "$version_raw")

    if [ -n "$conf_file" ] && [ -f "$conf_file" ]; then
        TARGET_FILE="$conf_file"
        FILE_HASH=$(sha256sum "$conf_file" 2>/dev/null | awk '{print $1}')
    fi

    active_count=$((active_count + 1))

    if [ -z "$required" ]; then
        manual_count=$((manual_count + 1))
        evidence_lines+=("$svc: 기준 버전이 미설정되어 수동 확인이 필요합니다.")
        return
    fi

    if [ -z "$installed" ]; then
        fail_count=$((fail_count + 1))
        evidence_lines+=("$svc: 설치 버전을 파악하지 못했습니다.")
        return
    fi

    if ver_ge "$installed" "$required"; then
        evidence_lines+=("$svc: 설치 버전 $installed (기준 $required 이상)")
    else
        fail_count=$((fail_count + 1))
        evidence_lines+=("$svc: 설치 버전 $installed (기준 $required 미만)")
    fi
}

if command -v postfix >/dev/null 2>&1 && systemctl is-active --quiet postfix; then
    check_service "Postfix" "$REQUIRED_POSTFIX_VERSION" "$(postconf -d mail_version 2>/dev/null)" "/etc/postfix/main.cf"
fi

if command -v sendmail >/dev/null 2>&1 && systemctl is-active --quiet sendmail; then
    check_service "Sendmail" "$REQUIRED_SENDMAIL_VERSION" "$(sendmail -d0 < /dev/null 2>/dev/null | grep -i 'Version')" "/etc/mail/sendmail.cf"
fi

if command -v exim >/dev/null 2>&1 && (systemctl is-active --quiet exim || systemctl is-active --quiet exim4); then
    check_service "Exim" "$REQUIRED_EXIM_VERSION" "$(exim -bV 2>/dev/null | head -n1)" "/etc/exim4/exim4.conf"
fi

if [ "$active_count" -eq 0 ]; then
    STATUS="PASS"
    ACTION_RESULT="SUCCESS"
    EVIDENCE="실행 중인 메일 서비스가 없습니다."
    GUIDE="KISA 보안 가이드라인을 준수하고 있습니다."
elif [ "$fail_count" -gt 0 ]; then
    STATUS="FAIL"
    ACTION_RESULT="MANUAL_REQUIRED"
    EVIDENCE="$(IFS='; '; echo "${evidence_lines[*]}")"
    GUIDE="REQUIRED_*_VERSION 값을 최신 버전으로 설정하고, fix_U45.sh 조치를 실행해 자동 업데이트 후 재점검하십시오."
elif [ "$manual_count" -gt 0 ]; then
    STATUS="MANUAL"
    ACTION_RESULT="MANUAL_REQUIRED"
    EVIDENCE="$(IFS='; '; echo "${evidence_lines[*]}")"
    GUIDE="운영 기준 버전(REQUIRED_*_VERSION)을 설정한 뒤 재점검하거나 수동 패치 관리 정책으로 점검하십시오."
else
    STATUS="PASS"
    ACTION_RESULT="SUCCESS"
    EVIDENCE="$(IFS='; '; echo "${evidence_lines[*]}")"
    GUIDE="모든 활성 메일 서비스가 기준 버전 이상입니다."
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
