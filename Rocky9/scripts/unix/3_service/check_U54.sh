#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-54
# @Category : 서비스 관리
# @Platform : LINUX
# @Importance : 상
# @Title : 불필요한 FTP 서비스 비활성화
# @Description : 업무상 불필요한 FTP 서비스가 실행 중인지 점검
# @Criteria_Good : FTP 서비스가 비활성화 되어 있는 경우
# @Criteria_Bad : 업무 활용 목적 이외의 불필요한 FTP 서비스가 활성화 되어 있는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-54 불필요한 FTP 서비스 비활성화

# 1. 항목 정보 정의
ID="U-54"
CATEGORY="서비스관리"
TITLE="불필요한 FTP 서비스 비활성화"
IMPORTANCE="상"
TARGET_FILE="/etc/vsftpd.conf"

# 2. 진단 로직 (무결성 해시 포함)
STATUS="PASS"
EVIDENCE=""
FILE_HASH="NOT_FOUND"

VULNERABLE=0

# [inetd]
if [ -f "/etc/inetd.conf" ]; then
    TARGET_FILE="/etc/inetd.conf"
    FILE_HASH=$(sha256sum "$TARGET_FILE" 2>/dev/null | awk '{print $1}')
    if grep -v "^#" "$TARGET_FILE" 2>/dev/null | grep -qE "^[[:space:]]*ftp"; then
        VULNERABLE=1
        EVIDENCE="$EVIDENCE /etc/inetd.conf에 FTP 활성화;"
    fi
fi

# [xinetd]
if [ -d "/etc/xinetd.d" ]; then
    # ftp, proftp, vsftp 등 확인
    for svc in ftp proftp vsftp; do
        if [ -f "/etc/xinetd.d/$svc" ]; then
            if grep -qiE "disable\s*=\s*no" "/etc/xinetd.d/$svc" 2>/dev/null; then
                VULNERABLE=1
                EVIDENCE="$EVIDENCE /etc/xinetd.d/$svc disable=no;"
            fi
        fi
    done
fi

# [systemd] vsftpd, proftpd
SYSTEMD_FTP=$(systemctl list-units --type=service 2>/dev/null | grep -E "vsftpd|proftpd|ftp" | awk '{print $1}' | tr '\n' ' ')
if [ -n "$SYSTEMD_FTP" ]; then
    # 업무상 필요한 경우를 제외하고는 차단해야 함.
    # 하지만 자동화 점검에서는 활성화 여부를 확인하여 보고 (수동 판단 필요)
    # 가이드 기준으로는 "불필요한 FTP"이므로, 일단 활성화되어 있으면 FAIL(또는 WARN)로 잡고 관리자가 판단하도록 함
    VULNERABLE=1
    EVIDENCE="$EVIDENCE 시스템 서비스 활성화: $SYSTEMD_FTP;"
fi

# 결과 판단
if [ $VULNERABLE -eq 1 ]; then
    STATUS="FAIL"
    EVIDENCE="FTP 서비스 활성화 확인(업무 불필요 시 조치 필요): $EVIDENCE"
else
    STATUS="PASS"
    EVIDENCE="FTP 서비스가 비활성화되어 있음"
fi

# JSON 출력 전 특수문자 제거
EVIDENCE=$(echo "$EVIDENCE" | tr '\n\r\t' '   ' | sed 's/"/\\"/g')

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
    "guide": "vsftpd.conf에 ssl_enable=YES, force_local_logins_ssl=YES, force_local_data_ssl=YES 설정으로 암호화를 활성화하세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
