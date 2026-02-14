#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.1.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-55
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : FTP 계정 shell 제한
# @Description : FTP 전용 계정(ftp)의 로그인 쉘을 제한(/sbin/nologin 또는 /bin/false)
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

set -u

ID="U-55"
CATEGORY="서비스 관리"
TITLE="FTP 계정 shell 제한"
IMPORTANCE="중"
TARGET_FILE="/etc/passwd"

ACTION_RESULT="SUCCESS"
ACTION_LOG=""
STATUS="PASS"
EVIDENCE="취약점 조치가 완료되었습니다."
GUIDE="FTP 전용 계정의 쉘을 /sbin/nologin 또는 /bin/false로 설정해야 합니다. 예: usermod -s /sbin/nologin ftp"

append_log() {
    local msg="$1"
    [ -z "$msg" ] && return 0
    if [ -n "$ACTION_LOG" ]; then
        ACTION_LOG="$ACTION_LOG; $msg"
    else
        ACTION_LOG="$msg"
    fi
}

json_escape() {
    echo "$1" | tr '\n\r\t' '   ' | sed 's/\\/\\\\/g; s/"/\\"/g'
}

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    ACTION_RESULT="FAIL"
    STATUS="FAIL"
    EVIDENCE="root 권한으로 실행해야 조치가 가능합니다."
    ACTION_LOG="권한 부족으로 조치를 수행하지 못했습니다."
else
    if getent passwd ftp >/dev/null 2>&1; then
        CURRENT_SHELL="$(getent passwd ftp | awk -F: '{print $7}')"
        if [[ "$CURRENT_SHELL" == "/bin/false" || "$CURRENT_SHELL" == "/sbin/nologin" || "$CURRENT_SHELL" == "/usr/sbin/nologin" ]]; then
            ACTION_RESULT="SUCCESS"
            STATUS="PASS"
            EVIDENCE="ftp 계정의 로그인 쉘이 이미 제한되어 있습니다."
            ACTION_LOG="ftp 계정의 로그인 쉘이 이미 제한되어 있습니다(현재: ${CURRENT_SHELL})."
        else
            if command -v usermod >/dev/null 2>&1; then
                if [ -x /sbin/nologin ]; then
                    usermod -s /sbin/nologin ftp 2>/dev/null || true
                else
                    usermod -s /bin/false ftp 2>/dev/null || true
                fi

                AFTER_SHELL="$(getent passwd ftp | awk -F: '{print $7}')"
                if [[ "$AFTER_SHELL" == "/bin/false" || "$AFTER_SHELL" == "/sbin/nologin" || "$AFTER_SHELL" == "/usr/sbin/nologin" ]]; then
                    ACTION_RESULT="SUCCESS"
                    STATUS="PASS"
                    EVIDENCE="취약점 조치가 완료되었습니다."
                    ACTION_LOG="ftp 계정의 로그인 쉘을 ${AFTER_SHELL}로 설정하여 로그인을 제한했습니다."
                else
                    ACTION_RESULT="FAIL"
                    STATUS="FAIL"
                    EVIDENCE="ftp 계정 쉘 제한 조치가 적용되지 않았습니다."
                    ACTION_LOG="ftp 계정의 쉘이 변경되지 않았습니다(현재: ${AFTER_SHELL})."
                fi
            else
                ACTION_RESULT="FAIL"
                STATUS="FAIL"
                EVIDENCE="usermod 명령이 없어 자동 조치를 수행하지 못했습니다."
                ACTION_LOG="usermod가 없어 수동 조치가 필요합니다."
            fi
        fi
    else
        ACTION_RESULT="SUCCESS"
        STATUS="PASS"
        EVIDENCE="ftp 계정이 존재하지 않습니다."
        ACTION_LOG="ftp 계정이 존재하지 않습니다."
    fi
fi

EVIDENCE="$(json_escape "$EVIDENCE")"
GUIDE="$(json_escape "$GUIDE")"
ACTION_LOG="$(json_escape "$ACTION_LOG")"

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
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF

