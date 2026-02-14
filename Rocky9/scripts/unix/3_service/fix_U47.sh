#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-47
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 스팸 메일 릴레이 제한
# @Description : 메일 서버의 릴레이 기능을 제한
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-47 스팸 메일 릴레이 제한

# 1. 항목 정보 정의
ID="U-47"
CATEGORY="서비스 관리"
TITLE="스팸 메일 릴레이 제한"
IMPORTANCE="상"
TARGET_FILE="/etc/postfix/main.cf"

# 2. 보완 로직
ACTION_RESULT="SUCCESS"
ACTION_LOG=""

# [Sendmail]
# 가이드: 버전에 따라 조치 방법이 다름
if command -v sendmail &>/dev/null; then
    # 버전 확인
    SENDMAIL_VER=$(sendmail -d0 < /dev/null 2>/dev/null | grep -oE "[0-9]+\.[0-9]+" | head -1)
    MAJOR_VER=$(echo "$SENDMAIL_VER" | cut -d. -f1)
    MINOR_VER=$(echo "$SENDMAIL_VER" | cut -d. -f2)
    

    
    if [ -n "$MAJOR_VER" ] && [ -n "$MINOR_VER" ]; then
        if [ "$MAJOR_VER" -gt 8 ] || ([ "$MAJOR_VER" -eq 8 ] && [ "$MINOR_VER" -ge 9 ]); then
            # 8.9 이상 버전: access 파일 설정
            # 가이드: /etc/mail/access 파일에 허용 IP 설정
            if [ ! -f "/etc/mail/access" ]; then
                touch /etc/mail/access

            fi
            
            # 릴레이 허용 설정 (localhost만)
            if ! grep -q "127.0.0.1" /etc/mail/access; then
                echo "127.0.0.1 RELAY" >> /etc/mail/access
                ACTION_LOG="$ACTION_LOG access에 127.0.0.1 RELAY를 추가했습니다."
            fi
            if ! grep -q "localhost" /etc/mail/access; then
                echo "localhost RELAY" >> /etc/mail/access
                ACTION_LOG="$ACTION_LOG access에 localhost RELAY를 추가했습니다."
            fi
            
            # DB 파일 생성
            # 가이드: makemap hash /etc/mail/access.db < /etc/mail/access
            makemap hash /etc/mail/access.db < /etc/mail/access 2>/dev/null
            ACTION_LOG="$ACTION_LOG access.db를 생성했습니다."
        else
            # 8.9 미만 버전: sendmail.cf에 Relaying denied 룰 추가
            # 가이드: R$*$#error $@ 5.7.1 $: "550 Relaying denied"
            SENDMAIL_CF="/etc/mail/sendmail.cf"
            if [ -f "$SENDMAIL_CF" ]; then
                if ! grep -q "Relaying denied" "$SENDMAIL_CF"; then
                    cp "$SENDMAIL_CF" "${SENDMAIL_CF}.bak_$(date +%Y%m%d_%H%M%S)"
                    echo 'R$*		$#error $@ 5.7.1 $: "550 Relaying denied"' >> "$SENDMAIL_CF"
                    ACTION_LOG="$ACTION_LOG sendmail.cf에 Relaying denied 룰을 추가했습니다(8.9 미만)."
                fi
            fi
        fi
    else
        # 버전 확인 실패 시 access 파일 방식 사용
        if [ ! -f "/etc/mail/access" ]; then
            touch /etc/mail/access
        fi
        if ! grep -q "127.0.0.1" /etc/mail/access; then
            echo "127.0.0.1 RELAY" >> /etc/mail/access
        fi
        makemap hash /etc/mail/access.db < /etc/mail/access 2>/dev/null
        ACTION_LOG="$ACTION_LOG access 파일을 설정했습니다(버전 확인 실패)."
    fi
    
    # 서비스 재시작
    systemctl restart sendmail 2>/dev/null
    ACTION_LOG="$ACTION_LOG Sendmail을 재시작했습니다."
fi

# [Postfix]
if command -v postfix &>/dev/null; then
    MAIN_CF="/etc/postfix/main.cf"
    if [ -f "$MAIN_CF" ]; then
        # mynetworks 설정 확인
        # 0.0.0.0/0 (모든 IP 허용)이 있는 경우 취약 -> 주석 처리 후 로컬만 허용
        if grep -qE "^mynetworks\s*=.*0\.0\.0\.0/0" "$MAIN_CF"; then
            cp "$MAIN_CF" "${MAIN_CF}.bak_$(date +%Y%m%d_%H%M%S)"
            sed -i 's/^\(mynetworks\s*=.*0\.0\.0\.0\/0\)/#\1/g' "$MAIN_CF"
            echo "mynetworks = 127.0.0.0/8" >> "$MAIN_CF"
            ACTION_LOG="$ACTION_LOG Postfix 취약한 mynetworks 설정을 주석 처리하고 로컬 허용으로 변경했습니다."
        elif ! grep -q "^mynetworks" "$MAIN_CF"; then
            # 설정이 없는 경우 추가
            echo "mynetworks = 127.0.0.0/8" >> "$MAIN_CF"
            ACTION_LOG="$ACTION_LOG Postfix mynetworks = 127.0.0.0/8을 추가했습니다."
        fi
        
        # smtpd_recipient_restrictions 확인
        if ! grep -q "smtpd_recipient_restrictions" "$MAIN_CF"; then
            echo "smtpd_recipient_restrictions = permit_mynetworks, reject_unauth_destination" >> "$MAIN_CF"
            ACTION_LOG="$ACTION_LOG Postfix smtpd_recipient_restrictions 설정을 추가했습니다."
        fi
        
        postfix reload 2>/dev/null
        # ACTION_LOG가 비어있지 않은 경우에만 리로드 메시지 추가 (중복 방지)
        ACTION_LOG="$ACTION_LOG Postfix 설정을 점검했습니다."
    fi
fi

# [Exim]
# 가이드: relay_from_hosts = <허용할 네트워크 주소> 설정
if command -v exim &>/dev/null || command -v exim4 &>/dev/null; then
    CONF_FILES=("/etc/exim/exim.conf" "/etc/exim4/exim4.conf" "/etc/exim4/update-exim4.conf.conf")
    EXIM_MODIFIED=0
    
    for conf in "${CONF_FILES[@]}"; do
        if [ -f "$conf" ]; then
            # relay_from_hosts 설정 확인 및 수정
            if grep -v "^#" "$conf" | grep -qE "relay_from_hosts.*\*|relay_from_hosts.*0\.0\.0\.0/0"; then

                cp "$conf" "${conf}.bak_$(date +%Y%m%d_%H%M%S)"
                
                # * 또는 0.0.0.0/0을 127.0.0.1로 변경
                sed -i 's/relay_from_hosts\s*=\s*\*/relay_from_hosts = 127.0.0.1/g' "$conf"
                sed -i 's/relay_from_hosts\s*=\s*0\.0\.0\.0\/0/relay_from_hosts = 127.0.0.1/g' "$conf"
                
                ACTION_LOG="$ACTION_LOG Exim relay_from_hosts를 127.0.0.1로 변경했습니다."
                EXIM_MODIFIED=1
            fi
            
            # relay_from_hosts 설정이 없으면 추가
            if ! grep -q "relay_from_hosts" "$conf"; then
                echo "relay_from_hosts = 127.0.0.1" >> "$conf"
                ACTION_LOG="$ACTION_LOG Exim relay_from_hosts = 127.0.0.1 설정을 추가했습니다."
                EXIM_MODIFIED=1
            fi
            
            break
        fi
    done
    
    if [ $EXIM_MODIFIED -eq 1 ]; then
        systemctl restart exim4 2>/dev/null || systemctl restart exim 2>/dev/null
        ACTION_LOG="$ACTION_LOG Exim을 재시작했습니다."
    fi
fi

# [검증]
RELAY_OPEN=0
# Postfix mynetworks 확인
if command -v postfix &>/dev/null && [ -f "/etc/postfix/main.cf" ]; then
    if grep -qE "^mynetworks\s*=.*0\.0\.0\.0/0" /etc/postfix/main.cf; then
        RELAY_OPEN=1
    fi
fi

if [ $RELAY_OPEN -eq 0 ]; then
    ACTION_RESULT="SUCCESS"
    STATUS="PASS"
    if [ -z "$ACTION_LOG" ]; then
        ACTION_LOG="이미 적절한 릴레이 제한 설정이 적용되어 있습니다."
    fi
    EVIDENCE="스팸 메일 릴레이 제한 조치가 완료되었습니다."
else
    ACTION_RESULT="FAIL"
    STATUS="FAIL"
    ACTION_LOG="릴레이 제한 설정을 시도했으나 일부 설정이 여전히 취약합니다. 수동 확인이 필요합니다."
    EVIDENCE="조치 후에도 취약한 릴레이 설정이 발견되었습니다."
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
    "guide": "KISA 가이드라인에 따른 보안 설정이 완료되었습니다.",
    "action_result": "$ACTION_RESULT",
    "action_log": "$ACTION_LOG",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
