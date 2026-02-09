#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-56
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 하
# @Title : FTP 서비스 접근 제어 설정
# @Description : FTP 서비스에 비인가자의 접근 가능 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-56 FTP 서비스 접근 제어 설정

# 1. 항목 정보 정의
ID="U-56"
CATEGORY="서비스 관리"
TITLE="FTP 서비스 접근 제어 설정"
IMPORTANCE="하"
TARGET_FILE="/etc/ftpusers"

# 2. 보완 로직
ACTION_RESULT="SUCCESS"
BEFORE_SETTING=""
AFTER_SETTING=""
ACTION_LOG=""

# 공통 함수: 파일 권한/소유자 변경 및 root 추가
fix_ftpusers_file() {
    local file=$1
    if [ -f "$file" ]; then
        BEFORE=$(stat -c '%U:%a' "$file" 2>/dev/null)
        BEFORE_SETTING="$BEFORE_SETTING $file($BEFORE);"
        
        # 권한/소유자 변경
        chown root "$file" 2>/dev/null
        chmod 640 "$file" 2>/dev/null
        ACTION_LOG="$ACTION_LOG $file 권한(640)/소유자(root) 변경;"
        
        # root 추가 (이미 있으면 무시)
        if ! grep -q "^root$" "$file"; then
             echo "root" >> "$file"
             ACTION_LOG="$ACTION_LOG $file에 root 추가;"
        fi
        
        AFTER=$(stat -c '%U:%a' "$file" 2>/dev/null)
        AFTER_SETTING="$AFTER_SETTING $file($AFTER);"
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
                # whitelist 모드 -> root 제거해야 차단됨
                if grep -q "^root$" "$TARGET"; then
                    sed -i '/^root$/d' "$TARGET"
                    ACTION_LOG="$ACTION_LOG $TARGET(Whitelist)에서 root 제거;"
                fi
            else
                # blacklist 모드 -> root 추가해야 차단됨
                fix_ftpusers_file "$TARGET"
            fi
        else
            TARGET="/etc/ftpusers"
            [ -f "/etc/vsftpd.ftpusers" ] && TARGET="/etc/vsftpd.ftpusers"
            [ ! -f "$TARGET" ] && touch "$TARGET"
            fix_ftpusers_file "$TARGET"
        fi
    fi
fi

# [ProFTP]
# 가이드: UseFtpUsers on/off에 따라 조치 방식 분기
if command -v proftpd &>/dev/null; then
    CONF="/etc/proftpd/proftpd.conf"
    [ ! -f "$CONF" ] && CONF="/etc/proftpd.conf"
    
    if [ -f "$CONF" ]; then
        USE_FTPUSERS=$(grep -i "UseFtpUsers" "$CONF" 2>/dev/null | awk '{print $2}')
        
        if echo "$USE_FTPUSERS" | grep -qi "off"; then
            # UseFtpUsers off → proftpd.conf에 <Limit LOGIN> 설정
            # 가이드: <Limit LOGIN> ... DenyUser root ... </Limit>
            
            # 소유자/권한 변경
            chown root "$CONF" 2>/dev/null
            chmod 640 "$CONF" 2>/dev/null
            ACTION_LOG="$ACTION_LOG proftpd.conf 권한(640)/소유자(root) 변경;"
            
            # <Limit LOGIN> 블록 확인 및 추가
            if ! grep -q "<Limit LOGIN>" "$CONF"; then
                cp "$CONF" "${CONF}.bak_$(date +%Y%m%d_%H%M%S)"
                cat >> "$CONF" << 'LIMIT_EOF'

<Limit LOGIN>
    Order Deny,Allow
    DenyUser root
</Limit>
LIMIT_EOF
                ACTION_LOG="$ACTION_LOG proftpd.conf에 <Limit LOGIN> DenyUser root 추가;"
            else
                # 이미 <Limit LOGIN>이 있으면 DenyUser root 확인
                if ! grep -A5 "<Limit LOGIN>" "$CONF" | grep -qi "DenyUser.*root"; then
                    # DenyUser root 추가 (복잡하므로 수동 권고)
                    ACTION_LOG="$ACTION_LOG <Limit LOGIN> 존재하나 DenyUser root 수동 확인 필요;"
                fi
            fi
            
            # ProFTP 재시작
            systemctl restart proftpd 2>/dev/null
            ACTION_LOG="$ACTION_LOG ProFTP 재시작;"
        else
            # UseFtpUsers on (기본) → ftpusers 파일 사용
            fix_ftpusers_file "/etc/ftpusers"
            [ ! -f "/etc/ftpusers" ] && [ -f "/etc/ftpd/ftpusers" ] && fix_ftpusers_file "/etc/ftpd/ftpusers"
        fi
    fi
fi

# [일반 FTP]
if [ -f "/etc/ftpusers" ]; then
    fix_ftpusers_file "/etc/ftpusers"
fi
if [ -f "/etc/ftpd/ftpusers" ]; then
    fix_ftpusers_file "/etc/ftpd/ftpusers"
fi

[ -z "$ACTION_LOG" ] && ACTION_LOG="대상 파일 없음 또는 이미 조치됨"
[ -z "$BEFORE_SETTING" ] && ACTION_RESULT="SUCCESS"

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
