#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-53
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 하
# @Title : FTP 서비스 정보 노출 제한
# @Description : FTP 서비스 정보 노출 여부 점검
# @Criteria_Good : FTP 접속 배너에 노출되는 정보가 없는 경우
# @Criteria_Bad : FTP 접속 배너에 노출되는 정보가 있는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-53 FTP 서비스 정보 노출 제한

# 1. 항목 정보 정의
ID="U-53"
CATEGORY="서비스 관리"
TITLE="FTP 서비스 정보 노출 제한"
IMPORTANCE="하"
TARGET_FILE="/etc/vsftpd.conf"

# 2. 진단 로직 (무결성 해시 포함)
STATUS="PASS"
EVIDENCE=""
FILE_HASH="NOT_FOUND"

VULNERABLE=0
FTP_SERVICE=""

# [vsFTP]
if command -v vsftpd &>/dev/null; then
    FTP_SERVICE="vsftpd"
    CONF_FILES=("/etc/vsftpd.conf" "/etc/vsftpd/vsftpd.conf")
    FOUND=0
    for conf in "${CONF_FILES[@]}"; do
        if [ -f "$conf" ]; then
            FOUND=1
            TARGET_FILE="$conf"
            FILE_HASH=$(sha256sum "$TARGET_FILE" 2>/dev/null | awk '{print $1}')
            
            # ftpd_banner 확인
            if grep -v "^#" "$conf" | grep -q "ftpd_banner"; then
                SETTING=$(grep -v "^#" "$conf" | grep "ftpd_banner")
                EVIDENCE="$EVIDENCE vsftpd 배너가 설정되어 있습니다: $SETTING."
            else
                VULNERABLE=1
                EVIDENCE="$EVIDENCE vsftpd 배너 설정(ftpd_banner)이 없습니다."
            fi
        fi
    done
    if [ $FOUND -eq 0 ]; then
        # 서비스는 있는데 설정파일 못찾음
        # 가이드: systemctl list-units --type=service | grep vsftpd
        if systemctl list-units --type=service 2>/dev/null | grep -q vsftpd; then
             VULNERABLE=1
             EVIDENCE="$EVIDENCE vsftpd가 실행 중이나 설정 파일을 확인할 수 없습니다."
        fi
    fi
fi

# [ProFTP]
if command -v proftpd &>/dev/null; then
    FTP_SERVICE="proftpd"
    CONF_FILES=("/etc/proftpd/proftpd.conf" "/etc/proftpd.conf")
    for conf in "${CONF_FILES[@]}"; do
        if [ -f "$conf" ]; then
            TARGET_FILE="$conf"
            # ServerIdent 확인
            if grep -v "^#" "$conf" | grep -q "ServerIdent"; then
                SETTING=$(grep -v "^#" "$conf" | grep "ServerIdent")
                # ServerIdent off 또는 on "문자열" 확인
                if echo "$SETTING" | grep -qiE "off|on"; then
                     EVIDENCE="$EVIDENCE ProFTPd ServerIdent가 설정되어 있습니다: $SETTING."
                else
                     # 문법적으로 이상할 수 있으나 설정은 있는 것으로 간주
                     EVIDENCE="$EVIDENCE ProFTPd ServerIdent 설정이 존재합니다: $SETTING."
                fi
            else
                VULNERABLE=1
                EVIDENCE="$EVIDENCE ProFTPd ServerIdent 설정이 없어 기본 배너가 노출될 수 있습니다."
            fi
        fi
    done
fi

if [ -z "$FTP_SERVICE" ]; then
    STATUS="PASS"
    EVIDENCE="FTP 서비스가 설치되어 있지 않아 점검 대상이 없습니다."
elif [ $VULNERABLE -eq 1 ]; then
    STATUS="FAIL"
    EVIDENCE="FTP 배너 설정이 미흡하여, 서비스 버전 등 시스템 정보가 노출될 수 있는 위험이 있습니다. $EVIDENCE"
else
    STATUS="PASS"
    EVIDENCE="FTP 배너가 적절히 설정되어 있습니다."
fi


IMPACT_LEVEL="LOW"
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없으나, 접속 배너에 서비스 이름/버전 정보가 노출되던 기존 설정이 변경되므로 배너 정책을 사전에 정한 뒤 FTP 설정 파일을 통해 배너를 일관되게 적용해야 합니다."

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
    "guide": "vsftpd.conf에 ftpd_banner=Authorized users only 설정, 또는 banner_file 지정으로 정보 노출을 방지해야 합니다.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
