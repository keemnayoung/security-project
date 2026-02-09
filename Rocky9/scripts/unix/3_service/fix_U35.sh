#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-35
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 공유 서비스에 대한 익명 접근 제한 설정
# @Description : 공유 서비스의 익명 접근 제한 설정 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-35 공유 서비스에 대한 익명 접근 제한 설정

# 1. 항목 정보 정의
ID="U-35"
CATEGORY="서비스 관리"
TITLE="공유 서비스에 대한 익명 접근 제한 설정"
IMPORTANCE="상"
TARGET_FILE="N/A"

# 2. 보완 로직
ACTION_RESULT="SUCCESS"
BEFORE_SETTING=""
AFTER_SETTING=""
ACTION_LOG=""

# [기본 FTP] FTP 계정 제거
# 가이드: # userdel ftp / # userdel anonymous
if grep -q "^ftp:" /etc/passwd 2>/dev/null; then
    BEFORE_SETTING="$BEFORE_SETTING ftp 계정 존재;"
    userdel ftp 2>/dev/null
    ACTION_LOG="$ACTION_LOG ftp 계정 삭제;"
fi
if grep -q "^anonymous:" /etc/passwd 2>/dev/null; then
    BEFORE_SETTING="$BEFORE_SETTING anonymous 계정 존재;"
    userdel anonymous 2>/dev/null
    ACTION_LOG="$ACTION_LOG anonymous 계정 삭제;"
fi

# [vsFTP] Anonymous FTP 비활성화
# 가이드: anonymous_enable 옵션을 NO로 수정 후 vsftpd 재시작
VSFTPD_CONF=""
if [ -f "/etc/vsftpd.conf" ]; then
    VSFTPD_CONF="/etc/vsftpd.conf"
elif [ -f "/etc/vsftpd/vsftpd.conf" ]; then
    VSFTPD_CONF="/etc/vsftpd/vsftpd.conf"
fi

if [ -n "$VSFTPD_CONF" ]; then
    if grep -v "^#" "$VSFTPD_CONF" 2>/dev/null | grep -qiE "anonymous_enable\s*=\s*YES"; then
        BEFORE_SETTING="$BEFORE_SETTING vsftpd anonymous_enable=YES;"
        cp "$VSFTPD_CONF" "${VSFTPD_CONF}.bak_$(date +%Y%m%d_%H%M%S)"
        sed -i 's/anonymous_enable\s*=\s*YES/anonymous_enable=NO/gi' "$VSFTPD_CONF"
        systemctl restart vsftpd 2>/dev/null
        ACTION_LOG="$ACTION_LOG vsftpd anonymous_enable=NO 설정 및 재시작;"
    fi
fi

# [ProFTP] Anonymous FTP 비활성화
# 가이드: Anonymous 필드 주석 처리 후 proftpd 재시작
PROFTPD_CONF=""
if [ -f "/etc/proftpd.conf" ]; then
    PROFTPD_CONF="/etc/proftpd.conf"
elif [ -f "/etc/proftpd/proftpd.conf" ]; then
    PROFTPD_CONF="/etc/proftpd/proftpd.conf"
fi

if [ -n "$PROFTPD_CONF" ]; then
    ANON_BLOCK=$(sed -n '/<Anonymous/,/<\/Anonymous>/p' "$PROFTPD_CONF" 2>/dev/null | grep -v "^[[:space:]]*#")
    if [ -n "$ANON_BLOCK" ]; then
        BEFORE_SETTING="$BEFORE_SETTING proftpd Anonymous 블록 존재;"
        cp "$PROFTPD_CONF" "${PROFTPD_CONF}.bak_$(date +%Y%m%d_%H%M%S)"
        # Anonymous 블록 주석 처리
        sed -i '/<Anonymous/,/<\/Anonymous>/s/^/#/' "$PROFTPD_CONF"
        systemctl restart proftpd 2>/dev/null
        ACTION_LOG="$ACTION_LOG proftpd Anonymous 블록 주석처리 및 재시작;"
    fi
fi

# [NFS] 익명 접근 비활성화
# 가이드: anon 옵션값 삭제 후 exportfs -ra
if [ -f "/etc/exports" ]; then
    if grep -v "^#" /etc/exports 2>/dev/null | grep -qE "(anonuid|anongid)"; then
        BEFORE_SETTING="$BEFORE_SETTING NFS anonuid/anongid 설정;"
        cp /etc/exports /etc/exports.bak_$(date +%Y%m%d_%H%M%S)
        # anonuid, anongid 옵션 제거
        sed -i 's/,anonuid=[0-9]*//g' /etc/exports
        sed -i 's/,anongid=[0-9]*//g' /etc/exports
        sed -i 's/anonuid=[0-9]*,//g' /etc/exports
        sed -i 's/anongid=[0-9]*,//g' /etc/exports
        exportfs -ra 2>/dev/null
        ACTION_LOG="$ACTION_LOG NFS anonuid/anongid 제거 및 exportfs -ra;"
    fi
fi

# [Samba] 익명 사용자 접근 비활성화
# 가이드: guest ok 옵션을 no로 수정 후 smbcontrol all reload-config
if [ -f "/etc/samba/smb.conf" ]; then
    if grep -v "^#" /etc/samba/smb.conf 2>/dev/null | grep -qiE "guest\s*ok\s*=\s*yes"; then
        BEFORE_SETTING="$BEFORE_SETTING Samba guest ok = yes;"
        cp /etc/samba/smb.conf /etc/samba/smb.conf.bak_$(date +%Y%m%d_%H%M%S)
        sed -i 's/guest\s*ok\s*=\s*yes/guest ok = no/gi' /etc/samba/smb.conf
        smbcontrol all reload-config 2>/dev/null || systemctl restart smbd 2>/dev/null
        ACTION_LOG="$ACTION_LOG Samba guest ok = no 설정 및 reload;"
    fi
fi

AFTER_SETTING="공유 서비스 익명 접근 제한 설정 완료"
[ -z "$ACTION_LOG" ] && ACTION_LOG="익명 접근 설정이 이미 제한된 상태"

# 3. 마스터 템플릿 표준 출력
echo ""

STATUS="$ACTION_RESULT"
EVIDENCE="$ACTION_LOG"
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
