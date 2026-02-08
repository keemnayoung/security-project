#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-53
# @Category : 서비스 관리
# @Platform : LINUX
# @Importance : 하
# @Title : FTP 서비스 접속 배너 설정
# @Description : FTP 서비스 접속 시 정보를 숨기기 위해 배너 설정
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-53 FTP 서비스 배너 설정

# 1. 항목 정보 정의
ID="U-53"
CATEGORY="서비스관리"
TITLE="FTP 서비스 접속 배너 설정"
IMPORTANCE="하"
TARGET_FILE="/etc/vsftpd.conf"

# 2. 보완 로직
ACTION_RESULT="SUCCESS"
BEFORE_SETTING=""
AFTER_SETTING=""
ACTION_LOG=""

# [vsFTP]
if command -v vsftpd &>/dev/null; then
    CONF_FILES=("/etc/vsftpd.conf" "/etc/vsftpd/vsftpd.conf")
    for conf in "${CONF_FILES[@]}"; do
        if [ -f "$conf" ]; then
            if ! grep -v "^#" "$conf" | grep -q "ftpd_banner"; then
                BEFORE_SETTING="$BEFORE_SETTING vsftpd($conf) 배너 없음;"
                echo "ftpd_banner=Welcome to FTP Service" >> "$conf"
                ACTION_LOG="$ACTION_LOG $conf ftpd_banner 추가;"
                systemctl restart vsftpd 2>/dev/null
            fi
        fi
    done
fi

# [ProFTP]
if command -v proftpd &>/dev/null; then
    CONF_FILES=("/etc/proftpd/proftpd.conf" "/etc/proftpd.conf")
    for conf in "${CONF_FILES[@]}"; do
        if [ -f "$conf" ]; then
            if ! grep -v "^#" "$conf" | grep -q "ServerIdent"; then
                BEFORE_SETTING="$BEFORE_SETTING proftpd($conf) ServerIdent 없음;"
                echo "ServerIdent off" >> "$conf"
                ACTION_LOG="$ACTION_LOG $conf ServerIdent off 추가;"
                systemctl restart proftpd 2>/dev/null
            fi
        fi
    done
fi

AFTER_SETTING="FTP 배너 설정 조치 완료"
[ -z "$ACTION_LOG" ] && ACTION_LOG="이미 설정되어 있거나 FTP 서비스 없음"

# 3. 마스터 템플릿 표준 출력
echo ""
cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "action_result": "$ACTION_RESULT",
    "before_setting": "$BEFORE_SETTING",
    "after_setting": "$AFTER_SETTING",
    "action_log": "$ACTION_LOG",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
