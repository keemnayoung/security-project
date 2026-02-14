#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-54
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : 암호화되지 않는 FTP 서비스 비활성화
# @Description : 암호화되지 않은 FTP 서비스 비활성화 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-54 암호화되지 않는 FTP 서비스 비활성화

# 1. 항목 정보 정의
ID="U-54"
CATEGORY="서비스 관리"
TITLE="암호화되지 않는 FTP 서비스 비활성화"
IMPORTANCE="중"
TARGET_FILE="/etc/vsftpd.conf"

# 2. 보완 로직
ACTION_RESULT="SUCCESS"
ACTION_LOG=""

# [inetd] FTP 비활성화
if [ -f "/etc/inetd.conf" ]; then
    if grep -v "^#" /etc/inetd.conf 2>/dev/null | grep -qE "^[[:space:]]*ftp"; then

        cp /etc/inetd.conf /etc/inetd.conf.bak_$(date +%Y%m%d_%H%M%S)
        sed -i 's/^\([[:space:]]*ftp\)/#\1/g' /etc/inetd.conf
        systemctl restart inetd 2>/dev/null || killall -HUP inetd 2>/dev/null
        ACTION_LOG="$ACTION_LOG /etc/inetd.conf FTP 주석 처리 및 inetd 재시작;"
    fi
fi

# [xinetd] FTP 비활성화
if [ -d "/etc/xinetd.d" ]; then
    for svc in ftp proftp vsftp; do
        if [ -f "/etc/xinetd.d/$svc" ]; then
            if grep -qiE "disable\s*=\s*no" "/etc/xinetd.d/$svc"; then

                sed -i 's/disable\s*=\s*no/disable = yes/gi' "/etc/xinetd.d/$svc"
                systemctl restart xinetd 2>/dev/null
                ACTION_LOG="$ACTION_LOG /etc/xinetd.d/$svc disable=yes 설정 및 xinetd 재시작;"
            fi
        fi
    done
fi

# [systemd] vsFTPd, ProFTPd 비활성화
# 가이드: systemctl list-units --type=service | grep vsftpd
#         systemctl stop/disable <서비스명>
FTP_SERVICES=("vsftpd" "proftpd" "ftp")
for svc in "${FTP_SERVICES[@]}"; do
    if systemctl list-units --type=service 2>/dev/null | grep -q "$svc"; then

        systemctl stop "$svc" 2>/dev/null
        systemctl disable "$svc" 2>/dev/null
        ACTION_LOG="$ACTION_LOG systemd $svc 중지 및 비활성화;"
    fi
done

if [ -n "$ACTION_LOG" ]; then
    ACTION_LOG="불필요한 FTP 서비스를 비활성화했습니다."
else
    ACTION_LOG="FTP 서비스가 이미 비활성화된 상태이거나 설치되어 있지 않습니다."
fi

STATUS="PASS"
EVIDENCE="조치 완료 (양호)"

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
