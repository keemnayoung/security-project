#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-35
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 공유 서비스에 대한 익명 접근 제한 설정
# @Description : 공유 서비스의 익명 접근 제한 설정 여부 점검
# @Criteria_Good : 공유 서비스에 대해 익명 접근을 제한한 경우
# @Criteria_Bad : 공유 서비스에 대해 익명 접근을 허용한 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-35 공유 서비스에 대한 익명 접근 제한 설정

# 1. 항목 정보 정의
ID="U-35"
CATEGORY="서비스 관리"
TITLE="공유 서비스에 대한 익명 접근 제한 설정"
IMPORTANCE="상"
TARGET_FILE="N/A"

# 2. 진단 로직 (KISA 가이드 기준)
STATUS="PASS"
EVIDENCE=""
FILE_HASH="NOT_FOUND"

VULNERABLE=0
SERVICE_EXISTS=0

# [기본 FTP] FTP 계정 확인
# 가이드: # cat /etc/passwd | grep ftp
#         # cat /etc/passwd | grep anonymous
if grep -q "^ftp:" /etc/passwd 2>/dev/null; then
    VULNERABLE=1
    SERVICE_EXISTS=1
    EVIDENCE="$EVIDENCE /etc/passwd에 ftp 계정이 존재합니다."
fi
if grep -q "^anonymous:" /etc/passwd 2>/dev/null; then
    VULNERABLE=1
    SERVICE_EXISTS=1
    EVIDENCE="$EVIDENCE /etc/passwd에 anonymous 계정이 존재합니다."
fi

# [vsFTP] Anonymous FTP 활성화 여부 확인
# 가이드: # cat /etc/vsftpd.conf | grep anonymous_enable
#         # cat /etc/vsftpd/vsftpd.conf | grep anonymous_enable
VSFTPD_CONF=""
if [ -f "/etc/vsftpd.conf" ]; then
    VSFTPD_CONF="/etc/vsftpd.conf"
elif [ -f "/etc/vsftpd/vsftpd.conf" ]; then
    VSFTPD_CONF="/etc/vsftpd/vsftpd.conf"
fi

if [ -n "$VSFTPD_CONF" ]; then
    SERVICE_EXISTS=1
    TARGET_FILE="$VSFTPD_CONF"
    FILE_HASH=$(sha256sum "$TARGET_FILE" 2>/dev/null | awk '{print $1}')
    # anonymous_enable=YES 인 경우 취약
    if grep -v "^#" "$VSFTPD_CONF" 2>/dev/null | grep -qiE "anonymous_enable\s*=\s*YES"; then
        VULNERABLE=1
        EVIDENCE="$EVIDENCE $VSFTPD_CONF에서 anonymous_enable=YES로 설정되어 있습니다."
    fi
fi

# [ProFTP] Anonymous FTP 활성화 여부 확인
# 가이드: # sed -n '/<Anonymous ~ftp>/,/<\/Anonymous>/p' /etc/proftpd.conf
#         # sed -n '/<Anonymous ~ftp>/,/<\/Anonymous>/p' /etc/proftpd/proftpd.conf
PROFTPD_CONF=""
if [ -f "/etc/proftpd.conf" ]; then
    PROFTPD_CONF="/etc/proftpd.conf"
elif [ -f "/etc/proftpd/proftpd.conf" ]; then
    PROFTPD_CONF="/etc/proftpd/proftpd.conf"
fi

if [ -n "$PROFTPD_CONF" ]; then
    SERVICE_EXISTS=1
    TARGET_FILE="$PROFTPD_CONF"
    # Anonymous 블록이 주석 없이 존재하면 취약 (User, UserAlias 옵션 포함)
    ANON_BLOCK=$(sed -n '/<Anonymous/,/<\/Anonymous>/p' "$PROFTPD_CONF" 2>/dev/null | grep -v "^[[:space:]]*#")
    if [ -n "$ANON_BLOCK" ]; then
        VULNERABLE=1
        EVIDENCE="$EVIDENCE $PROFTPD_CONF에 Anonymous 블록이 활성화되어 있습니다."
    fi
fi

# [NFS] 익명 접근 활성화 여부 확인
# 가이드: # cat /etc/exports | grep -E "anonuid|anongid"
# ※ anon 옵션이 설정된 경우 익명 접근이 활성화되어 있는 상태
if [ -f "/etc/exports" ]; then
    SERVICE_EXISTS=1
    if grep -v "^#" /etc/exports 2>/dev/null | grep -qE "(anonuid|anongid)"; then
        VULNERABLE=1
        EVIDENCE="$EVIDENCE /etc/exports에 anonuid/anongid가 설정되어 있습니다."
    fi
    # anon 옵션 자체가 사용된 경우도 취약으로 판단
    if grep -v "^#" /etc/exports 2>/dev/null | grep -qE '\(([^)]*,)?anon([=,)][^)]*)?\)'; then
        VULNERABLE=1
        EVIDENCE="$EVIDENCE /etc/exports에 anon 옵션이 설정되어 있습니다."
    fi
fi

# [Samba] 익명 접근 허용 여부 확인
# 가이드: # cat /etc/samba/smb.conf | grep "guest ok"
if [ -f "/etc/samba/smb.conf" ]; then
    SERVICE_EXISTS=1
    # guest ok = yes 인 경우 취약
    if grep -v "^#" /etc/samba/smb.conf 2>/dev/null | grep -qiE "guest\s*ok\s*=\s*yes"; then
        VULNERABLE=1
        EVIDENCE="$EVIDENCE /etc/samba/smb.conf에서 guest ok = yes로 설정되어 있습니다."
    fi
fi

# 결과 판단
if [ $SERVICE_EXISTS -eq 0 ]; then
    STATUS="PASS"
    EVIDENCE="공유 서비스(FTP/NFS/Samba)가 설치되어 있지 않아 점검 대상이 없습니다."
elif [ $VULNERABLE -eq 1 ]; then
    STATUS="FAIL"
    EVIDENCE="공유 서비스에서 익명 접근이 허용되어 있어, 비인가 사용자가 데이터에 접근할 수 있는 위험이 있습니다. $EVIDENCE"
else
    STATUS="PASS"
    EVIDENCE="공유 서비스에 대해 익명 접근이 제한되어 있습니다."
fi


IMPACT_LEVEL="LOW"
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없으나, 익명 FTP·NFS anon·Samba guest 등 익명 접근 방식에 의존하던 공유 방식이 있었다면 익명 접속이 차단되므로 인증된 계정 기반 접근 및 권한 정책으로 전환하여 운영해야 합니다."

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
    "guide": "vsFTPd: anonymous_enable=NO 설정, Samba: guest ok=no 설정, NFS: /etc/exports에서 anon/anonuid/anongid 옵션을 제거한 후 exportfs -ra를 실행해야 합니다.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
