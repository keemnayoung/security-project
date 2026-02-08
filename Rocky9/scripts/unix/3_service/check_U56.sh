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
# @Platform : LINUX
# @Importance : 상
# @Title : root 홈, 패스 디렉터리 권한 및 패스 설정
# @Description : ftpusers 파일의 소유자 및 권한 확인, root 계정 차단 여부 점검
# @Criteria_Good : ftpusers 파일 소유자가 root이고, 권한이 640 이하이며 root 계정 접속이 차단된 경우
# @Criteria_Bad : ftpusers 파일 소유자/권한이 취약하거나 root 계정 접속이 허용된 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-56 ftpusers 파일 설정 (root 접근 제한)

# 1. 항목 정보 정의
ID="U-56"
CATEGORY="서비스관리"
TITLE="root 홈, 패스 디렉터리 권한 및 패스 설정 (FTP users 점검)"
IMPORTANCE="상"
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
            EVIDENCE="$EVIDENCE $file 소유자 root 아님($OWNER);"
        fi
        
        if [ "$PERMS" -gt 640 ]; then
            VULNERABLE=1
            EVIDENCE="$EVIDENCE $file 권한 과다($PERMS>640);"
        fi
        
        # root 차단 확인 (파일 내에 root가 있어야 차단됨 - vsftpd userlist_deny=YES 기준)
        # 단, userlist_deny=NO 이면 파일 내 계정만 허용하므로 root가 없어야 차단됨.
        # 일반적인 ftpusers는 차단 목록임.
        
        if grep -q "^root$" "$file"; then
             EVIDENCE="$EVIDENCE $file에 root 포함(차단 목록 가정);"
        else
             VULNERABLE=1
             EVIDENCE="$EVIDENCE $file에 root 미포함(접속 허용 가능성);"
        fi
    else
        EVIDENCE="$EVIDENCE $file 파일 없음;"
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
                    EVIDENCE="$EVIDENCE userlist_deny=NO인데 root가 user_list에 존재(허용);"
                fi
            else
                # blacklist 모드 (기본)
                if ! grep -q "^root$" "$TARGET"; then
                    VULNERABLE=1
                    EVIDENCE="$EVIDENCE userlist_deny=YES인데 root가 user_list에 없음(차단 안됨);"
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
                EVIDENCE="$EVIDENCE ProFTP <Limit LOGIN> 설정 있음;"
                
                # DenyUser root 또는 AllowUser (root 제외) 확인
                if echo "$LIMIT_LOGIN" | grep -qi "DenyUser.*root"; then
                    EVIDENCE="$EVIDENCE DenyUser root 설정됨;"
                elif echo "$LIMIT_LOGIN" | grep -qi "AllowUser"; then
                    if ! echo "$LIMIT_LOGIN" | grep -qi "AllowUser.*root"; then
                        EVIDENCE="$EVIDENCE AllowUser에 root 없음(차단);"
                    else
                        VULNERABLE=1
                        EVIDENCE="$EVIDENCE AllowUser에 root 포함(허용);"
                    fi
                fi
                
                # 파일 소유자/권한 확인
                PERMS=$(stat -c '%a' "$CONF" 2>/dev/null)
                OWNER=$(stat -c '%U' "$CONF" 2>/dev/null)
                if [ "$OWNER" != "root" ]; then
                    VULNERABLE=1
                    EVIDENCE="$EVIDENCE proftpd.conf 소유자 root 아님($OWNER);"
                fi
                if [ "$PERMS" -gt 640 ]; then
                    VULNERABLE=1
                    EVIDENCE="$EVIDENCE proftpd.conf 권한 과다($PERMS>640);"
                fi
            else
                VULNERABLE=1
                EVIDENCE="$EVIDENCE ProFTP UseFtpUsers off이나 <Limit LOGIN> 설정 없음;"
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
        EVIDENCE="FTP 서비스 미사용 (양호)"
    fi
else
    if [ $VULNERABLE -eq 1 ]; then
        STATUS="FAIL"
        EVIDENCE="FTP root 접근 제한 미흡: $EVIDENCE"
    else
        STATUS="PASS"
        EVIDENCE="FTP root 접근이 제한되어 있음"
    fi
fi

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
    "guide": "vsftpd.conf에 tcp_wrappers=YES 설정 후, /etc/hosts.allow 및 /etc/hosts.deny로 접근 제어하세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
