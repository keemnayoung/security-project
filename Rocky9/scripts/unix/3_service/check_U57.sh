#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-57
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중 
# @Title : Ftpusers 파일 설정
# @Description : FTP 서비스에 root 계정 접근 제한 설정 여부 점검
# @Criteria_Good : root 계정 접속을 차단한 경우
# @Criteria_Bad : root 계정 접속을 허용한 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-57 Ftpusers 파일 설정

# 1. 항목 정보 정의
ID="U-57"
CATEGORY="서비스 관리"
TITLE="Ftpusers 파일 설정"
IMPORTANCE="중"
TARGET_FILE="/etc/ftpusers"

# 2. 진단 로직 (무결성 해시 포함)
STATUS="PASS"
EVIDENCE=""
FILE_HASH="NOT_FOUND"

VULNERABLE=0
FTP_CHECKED=0

# 공통 함수: root 차단 여부 확인 (Blacklist 파일)
check_root_blocked() {
    local file=$1
    if [ -f "$file" ]; then
        TARGET_FILE="$file"
        FILE_HASH=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
        
        # 주석 제외하고 root가 있는지 확인
        if grep -v "^#" "$file" | grep -q "^root$"; then
            EVIDENCE="$EVIDENCE $file에 root 포함(차단됨);"
        else
            VULNERABLE=1
            EVIDENCE="$EVIDENCE $file에 root 미포함(차단 설정 미흡);"
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
            
            check_root_blocked "$TARGET"
            
            # userlist_deny=NO (Whitelist)인 경우 root가 있으면 허용이므로 취약
            if [ "$USERLIST_DENY" == "NO" ]; then
                if grep -v "^#" "$TARGET" | grep -q "^root$"; then
                    VULNERABLE=1
                    EVIDENCE="$EVIDENCE userlist_deny=NO(Whitelist)이나 root가 존재하여 접속 허용됨;"
                else
                    # root가 없으면 접속 불가하므로 안전 (앞선 check_root_blocked에서 root없음=취약으로 잡았을 테니 보정 필요)
                    # check_root_blocked는 무조건 root가 있어야 안전하다고 판단했으므로, 
                    # Whitelist 모드에서는 로직 반전이 필요함.
                    # 여기서는 상세 분석을 통해 VULNERABLE 값을 재조정해야 함.
                    
                    # 다시 판단:
                    # 1. check_root_blocked에서 root 없어서 VULNERABLE=1 됨.
                    # 2. 하지만 Whitelist에서 root 없으면 안전함 => VULNERABLE=0으로 정정.
                    VULNERABLE=0
                    EVIDENCE="$EVIDENCE userlist_deny=NO(Whitelist)이며 root 미포함으로 접속 차단됨;"
                fi
            fi
        else
             # userlist_enable=NO -> ftpusers 사용
             TARGET="/etc/ftpusers"
             [ -f "/etc/vsftpd.ftpusers" ] && TARGET="/etc/vsftpd.ftpusers"
             check_root_blocked "$TARGET"
        fi
    fi
fi

# [ProFTP]
if command -v proftpd &>/dev/null; then
    FTP_CHECKED=1
    CONF="/etc/proftpd/proftpd.conf"
    
    # UseFtpUsers 확인
    USE_FTPUSERS="on"
    if grep -q "UseFtpUsers" "$CONF"; then
        USE_FTPUSERS=$(grep "UseFtpUsers" "$CONF" | awk '{print $2}')
    fi
    
    if echo "$USE_FTPUSERS" | grep -qi "off"; then
        # RootLogin 확인
        ROOT_LOGIN=$(grep "RootLogin" "$CONF" | awk '{print $2}')
        if echo "$ROOT_LOGIN" | grep -qi "off"; then
            EVIDENCE="$EVIDENCE ProFTP RootLogin off 설정됨;"
        else
            VULNERABLE=1
            EVIDENCE="$EVIDENCE ProFTP UseFtpUsers off이며 RootLogin off 미설정;"
        fi
    else
        # UseFtpUsers on (기본) -> ftpusers 사용
        check_root_blocked "/etc/ftpusers"
    fi
fi

# [일반 FTP (inetd/xinetd 등)]
if [ $FTP_CHECKED -eq 0 ]; then
    if [ -f "/etc/ftpusers" ]; then
        check_root_blocked "/etc/ftpusers"
    elif [ -f "/etc/ftpd/ftpusers" ]; then
         check_root_blocked "/etc/ftpd/ftpusers"
    else
        STATUS="PASS"
        EVIDENCE="FTP 서비스 미사용 (양호)"
    fi
else
    if [ $VULNERABLE -eq 1 ]; then
        STATUS="FAIL"
        EVIDENCE="root 계정 FTP 접속 허용: $EVIDENCE"
    else
        STATUS="PASS"
        EVIDENCE="root 계정 FTP 접속 차단됨"
    fi
fi


IMPACT_LEVEL="HIGH"
ACTION_IMPACT="Ftpusers 파일 설정을 적용하면 root 계정의 FTP 사용이 제한(차단)될 수 있으므로, 애플리케이션이나 운영 절차에서 root 계정으로 직접 접속하여 FTP를 사용하고 있는 경우 계정 인증/운영 방식에 문제가 발생할 수 있습니다. 특히 자동화 스크립트나 배치 작업이 root 기반으로 구성되어 있다면 영향이 있을 수 있으므로, 사전에 사용 여부를 점검한 뒤 적용해야 합니다."

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
    "guide": "/etc/ftpusers 또는 /etc/vsftpd/ftpusers 파일에 root 계정을 추가하여 FTP 접속을 차단하세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
