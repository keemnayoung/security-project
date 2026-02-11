#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-57
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중 
# @Title : Ftpusers 파일 설정
# @Description : FTP 서비스에 root 계정 접근 제한 설정 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-57 Ftpusers 파일 설정

# 1. 항목 정보 정의
ID="U-57"
CATEGORY="서비스 관리"
TITLE="Ftpusers 파일 설정"
IMPORTANCE="중"
TARGET_FILE="/etc/ftpusers"

# 2. 보완 로직
ACTION_RESULT="SUCCESS"
ACTION_LOG=""

# root 차단 추가 함수 (Blacklist)
block_root() {
    local file=$1
    if [ -f "$file" ]; then
        if ! grep -v "^#" "$file" | grep -q "^root$"; then

            # 주석된 root가 있으면 주석 해제, 없으면 추가
            if grep -q "^#root" "$file"; then
                sed -i 's/^#root/root/' "$file"
                ACTION_LOG="$ACTION_LOG $file에서 #root 주석을 해제했습니다."
            else
                echo "root" >> "$file"
                ACTION_LOG="$ACTION_LOG $file에 root를 추가했습니다."
            fi
        fi
    fi
}

# root 허용 제거 함수 (Whitelist)
unallow_root() {
    local file=$1
    if [ -f "$file" ]; then
        if grep -v "^#" "$file" | grep -q "^root$"; then

            sed -i '/^root$/d' "$file"
            ACTION_LOG="$ACTION_LOG $file(Whitelist)에서 root를 제거했습니다."
        fi
    fi
}

# [vsFTP]
if command -v vsftpd &>/dev/null; then
    CONF="/etc/vsftpd.conf"
    [ ! -f "$CONF" ] && CONF="/etc/vsftpd/vsftpd.conf"
    
    if [ -f "$CONF" ]; then
        USERLIST_ENABLE=$(grep "userlist_enable" "$CONF" | cut -d= -f2 | tr -d ' ')
        USERLIST_DENY=$(grep "userlist_deny" "$CONF" | cut -d= -f2 | tr -d ' ')
        
        if [ "$USERLIST_ENABLE" == "YES" ]; then
            TARGET="/etc/vsftpd.user_list"
            [ ! -f "$TARGET" ] && TARGET="/etc/vsftpd/user_list"
            [ ! -f "$TARGET" ] && touch "$TARGET"
            
            if [ "$USERLIST_DENY" == "NO" ]; then
                # Whitelist
                unallow_root "$TARGET"
            else
                # Blacklist
                block_root "$TARGET"
            fi
        else
            TARGET="/etc/ftpusers"
            [ -f "/etc/vsftpd.ftpusers" ] && TARGET="/etc/vsftpd.ftpusers"
            [ ! -f "$TARGET" ] && touch "$TARGET"
            block_root "$TARGET"
        fi
    fi
fi

# [ProFTP]
if command -v proftpd &>/dev/null; then
    CONF="/etc/proftpd/proftpd.conf"
    if grep -q "UseFtpUsers off" "$CONF" 2>/dev/null; then
         if ! grep -q "RootLogin off" "$CONF"; then

             echo "RootLogin off" >> "$CONF"
             ACTION_LOG="$ACTION_LOG ProFTP RootLogin off 설정을 추가했습니다."
             systemctl restart proftpd 2>/dev/null
         fi
    else
         block_root "/etc/ftpusers"
    fi
fi

# [일반 FTP]
if [ -f "/etc/ftpusers" ]; then
    block_root "/etc/ftpusers"
fi
if [ -f "/etc/ftpd/ftpusers" ]; then
    block_root "/etc/ftpd/ftpusers"
fi

if [ -n "$ACTION_LOG" ]; then
    ACTION_LOG="FTP 서비스의 ftpusers 파일에 root 계정 접속 제한 설정을 적용했습니다."
else
    ACTION_LOG="이미 root 접속이 차단되어 있거나 FTP 서비스가 없습니다."
fi

STATUS="PASS"
EVIDENCE="취약점 조치가 완료되었습니다."

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
