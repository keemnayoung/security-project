#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-56
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 하
# @Title : FTP 서비스 접근 제어 설정
# @Description : FTP 서비스에 비인가자의 접근 가능 여부 점검
# @Criteria_Good : FTP 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정
# @Criteria_Bad : FTP 서비스 사용 시 접근 제어 설정
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-56 FTP 서비스 접근 제어 설정

# 1. 항목 정보 정의
ID="U-56"
CATEGORY="서비스 관리"
TITLE="FTP 서비스 접근 제어 설정"
IMPORTANCE="하"
TARGET_FILE="/etc/ftpusers"

# 2. 진단 로직 (무결성 해시 포함)
STATUS="PASS"
EVIDENCE=""
FILE_HASH="NOT_FOUND"

VULNERABLE=0
FTP_CHECKED=0

# 공통 함수: 파일 권한/소유자 및 root 포함 여부 확인
check_ftpusers_file() {
    local file=$1
    if [ -f "$file" ]; then
        TARGET_FILE="$file"
        FILE_HASH=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
        
        # 권한 확인 (640 이하)
        PERMS=$(stat -c '%a' "$file" 2>/dev/null)
        OWNER=$(stat -c '%U' "$file" 2>/dev/null)
        
        if [ "$OWNER" != "root" ]; then
            VULNERABLE=1
            EVIDENCE="$EVIDENCE $file의 소유자가 root가 아닙니다($OWNER)."
        fi
        
        if [ "$PERMS" -gt 640 ]; then
            VULNERABLE=1
            EVIDENCE="$EVIDENCE $file의 권한이 과대합니다($PERMS>640)."
        fi
        
        # root 차단 확인 (파일 내에 root가 있어야 차단됨 - vsftpd userlist_deny=YES 기준)
        # 단, userlist_deny=NO 이면 파일 내 계정만 허용하므로 root가 없어야 차단됨.
        # 일반적인 ftpusers는 차단 목록임.
        
        if grep -q "^root$" "$file"; then
             EVIDENCE="$EVIDENCE $file에 root가 포함되어 있습니다(차단 목록 가정)."
        else
             VULNERABLE=1
             EVIDENCE="$EVIDENCE $file에 root가 포함되어 있지 않아 접속이 허용될 수 있습니다."
        fi
    else
        EVIDENCE="$EVIDENCE $file 파일이 존재하지 않습니다."
    fi
}

# [vsFTP]
if command -v vsftpd &>/dev/null; then
    FTP_CHECKED=1
    CONF="/etc/vsftpd.conf"
    [ ! -f "$CONF" ] && CONF="/etc/vsftpd/vsftpd.conf"
    
    if [ -f "$CONF" ]; then
        USERLIST_ENABLE=$(grep "userlist_enable" "$CONF" | cut -d= -f2 | tr -d ' ')
        USERLIST_DENY=$(grep "userlist_deny" "$CONF" | cut -d= -f2 | tr -d ' ')
        
        if [ "$USERLIST_ENABLE" == "YES" ]; then
            TARGET="/etc/vsftpd.user_list"
            [ ! -f "$TARGET" ] && TARGET="/etc/vsftpd/user_list"
            
            check_ftpusers_file "$TARGET"
            
            # userlist_deny가 NO이면 user_list에 있는 계정만 허용 -> root가 있으면 안됨(허용되니까)
            # userlist_deny가 YES(기본)이면 user_list에 있는 계정 차단 -> root가 있어야 함
            
            if [ "$USERLIST_DENY" == "NO" ]; then
                # whitelist 모드
                if grep -q "^root$" "$TARGET"; then
                    VULNERABLE=1
                    EVIDENCE="$EVIDENCE userlist_deny=NO인데 root가 user_list에 존재하여 접속이 허용되어 있습니다."
                fi
            else
                # blacklist 모드 (기본)
                if ! grep -q "^root$" "$TARGET"; then
                    VULNERABLE=1
                    EVIDENCE="$EVIDENCE userlist_deny=YES인데 root가 user_list에 없어 접속이 차단되지 않습니다."
                fi
            fi
        else
             # userlist_enable=NO -> ftpusers 파일 사용
             TARGET="/etc/ftpusers"
             [ -f "/etc/vsftpd.ftpusers" ] && TARGET="/etc/vsftpd.ftpusers"
             check_ftpusers_file "$TARGET"
        fi
    fi
fi

# [ProFTP]
# 가이드: UseFtpUsers on/off에 따라 점검 방식 분기
if command -v proftpd &>/dev/null; then
    FTP_CHECKED=1
    CONF="/etc/proftpd/proftpd.conf"
    [ ! -f "$CONF" ] && CONF="/etc/proftpd.conf"
    
    if [ -f "$CONF" ]; then
        # UseFtpUsers 설정 확인
        USE_FTPUSERS=$(grep -i "UseFtpUsers" "$CONF" 2>/dev/null | awk '{print $2}')
        
        if echo "$USE_FTPUSERS" | grep -qi "off"; then
            # UseFtpUsers off → proftpd.conf의 <Limit LOGIN> 확인
            # 가이드: sed -n '/<Limit LOGIN>/, /<\/Limit>/p' /etc/proftpd.conf
            LIMIT_LOGIN=$(sed -n '/<Limit LOGIN>/,/<\/Limit>/p' "$CONF" 2>/dev/null)
            
            if [ -n "$LIMIT_LOGIN" ]; then
                EVIDENCE="$EVIDENCE ProFTP <Limit LOGIN> 설정이 있습니다."
                
                # DenyUser root 또는 AllowUser (root 제외) 확인
                if echo "$LIMIT_LOGIN" | grep -qi "DenyUser.*root"; then
                    EVIDENCE="$EVIDENCE DenyUser root가 설정되어 있습니다."
                elif echo "$LIMIT_LOGIN" | grep -qi "AllowUser"; then
                    if ! echo "$LIMIT_LOGIN" | grep -qi "AllowUser.*root"; then
                        EVIDENCE="$EVIDENCE AllowUser에 root가 없어 접속이 차단되어 있습니다."
                    else
                        VULNERABLE=1
                        EVIDENCE="$EVIDENCE AllowUser에 root가 포함되어 접속이 허용되어 있습니다."
                    fi
                fi
                
                # 파일 소유자/권한 확인
                PERMS=$(stat -c '%a' "$CONF" 2>/dev/null)
                OWNER=$(stat -c '%U' "$CONF" 2>/dev/null)
                if [ "$OWNER" != "root" ]; then
                    VULNERABLE=1
                    EVIDENCE="$EVIDENCE proftpd.conf의 소유자가 root가 아닙니다($OWNER)."
                fi
                if [ "$PERMS" -gt 640 ]; then
                    VULNERABLE=1
                    EVIDENCE="$EVIDENCE proftpd.conf의 권한이 과대합니다($PERMS>640)."
                fi
            else
                VULNERABLE=1
                EVIDENCE="$EVIDENCE ProFTP UseFtpUsers off이나 <Limit LOGIN> 설정이 없습니다."
            fi
        else
            # UseFtpUsers on (기본) → ftpusers 파일 사용
            check_ftpusers_file "/etc/ftpusers"
            [ ! -f "/etc/ftpusers" ] && check_ftpusers_file "/etc/ftpd/ftpusers"
        fi
    fi
fi

# [일반 FTP (inetd/xinetd 등)]
if [ $FTP_CHECKED -eq 0 ]; then
    if [ -f "/etc/ftpusers" ]; then
        check_ftpusers_file "/etc/ftpusers"
    else
        STATUS="PASS"
        EVIDENCE="FTP 서비스가 설치되어 있지 않아 점검 대상이 없습니다."
    fi
else
    if [ $VULNERABLE -eq 1 ]; then
        STATUS="FAIL"
        EVIDENCE="FTP root 접근 제한이 미흡하여, 비인가 사용자가 중요 파일에 접근할 수 있는 위험이 있습니다. $EVIDENCE"
    else
        STATUS="PASS"
        EVIDENCE="FTP root 접근이 제한되어 있습니다."
    fi
fi


IMPACT_LEVEL="HIGH"
ACTION_IMPACT="FTP 서비스 접근 제어 설정을 적용하면 특정 IP 주소 또는 호스트에서만 FTP 접속이 가능해지므로, 기존에 허용되지 않은 구간(운영자 PC, 배치 서버 등)에서 FTP를 사용하던 경우 접속 장애가 발생할 수 있습니다. 따라서 적용 전, FTP가 필요한 접속 주체(서버/클라이언트)와 허용 대상을 충분히 정리한 뒤 반영해야 합니다"

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
    "guide": "vsftpd.conf에 tcp_wrappers=YES를 설정한 후, /etc/hosts.allow 및 /etc/hosts.deny로 접근을 제어해야 합니다.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
