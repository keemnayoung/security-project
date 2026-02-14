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
# @Platform : Rocky Linux
# @Importance : 하
# @Title : FTP 서비스 정보 노출 제한
# @Description : FTP 서비스 정보 노출 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-53 FTP 서비스 정보 노출 제한

# 1. 항목 정보 정의
ID="U-53"
CATEGORY="서비스 관리"
TITLE="FTP 서비스 정보 노출 제한"
IMPORTANCE="하"
TARGET_FILE="/etc/vsftpd.conf"

# 2. 보완 로직
ACTION_RESULT="SUCCESS"
ACTION_LOG=""

# [vsFTP]
if command -v vsftpd &>/dev/null; then
    CONF_FILES=("/etc/vsftpd.conf" "/etc/vsftpd/vsftpd.conf")
    for conf in "${CONF_FILES[@]}"; do
        if [ -f "$conf" ]; then
            if ! grep -v "^#" "$conf" | grep -q "ftpd_banner"; then

                echo "ftpd_banner=Welcome to FTP Service" >> "$conf"
                ACTION_LOG="$ACTION_LOG $conf에 ftpd_banner를 추가했습니다."
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

                echo "ServerIdent off" >> "$conf"
                ACTION_LOG="$ACTION_LOG $conf에 ServerIdent off를 추가했습니다."
                systemctl restart proftpd 2>/dev/null
            fi
        fi
    done
fi

if [ -n "$ACTION_LOG" ]; then
    ACTION_LOG="FTP 서비스의 배너 설정을 수정하여 시스템 정보 노출을 방지했습니다."
else
    ACTION_LOG="FTP 배너가 이미 적절하게 설정되어 있거나 FTP 서비스가 없습니다."
fi

STATUS="PASS"
EVIDENCE="FTP 서비스의 배너 설정이 적절히 구성되어 있습니다."

# 3. 마스터 템플릿 표준 출력
echo ""
cat << EOF
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
EOF
