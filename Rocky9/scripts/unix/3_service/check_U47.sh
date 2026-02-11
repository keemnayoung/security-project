#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-47
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 스팸 메일 릴레이 제한
# @Description : SMTP 서버의 릴레이 기능 제한 여부 점검
# @Criteria_Good : 메일 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정
# @Criteria_Bad : 메일 서비스 사용 시 릴레이 방지 설정 또는 릴레이 대상 접근 제어 설정
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-47 스팸 메일 릴레이 제한

# 1. 항목 정보 정의
ID="U-47"
CATEGORY="서비스 관리"
TITLE="스팸 메일 릴레이 제한"
IMPORTANCE="상"
TARGET_FILE="/etc/postfix/main.cf"

# 2. 진단 로직 (무결성 해시 포함)
STATUS="PASS"
EVIDENCE=""
FILE_HASH="NOT_FOUND"

VULNERABLE=0
MAIL_SERVICE=""

# [Sendmail]
# 가이드: sendmail.cf 확인
if command -v sendmail &>/dev/null; then
    MAIL_SERVICE="sendmail"
    # sendmail.cf 확인
    if [ -f "/etc/mail/sendmail.cf" ]; then
        TARGET_FILE="/etc/mail/sendmail.cf"
        FILE_HASH=$(sha256sum "$TARGET_FILE" 2>/dev/null | awk '{print $1}')
        
        # Sendmail 버전 확인 (예: 8.15.2)
        # 가이드: sendmail -d0 < /dev/null | grep Version
        SENDMAIL_VER=$(sendmail -d0 < /dev/null 2>/dev/null | grep -oE "[0-9]+\.[0-9]+" | head -1)
        MAJOR_VER=$(echo "$SENDMAIL_VER" | cut -d. -f1)
        MINOR_VER=$(echo "$SENDMAIL_VER" | cut -d. -f2)
        
        EVIDENCE="$EVIDENCE Sendmail 버전: $SENDMAIL_VER."
        
        # 버전 비교: 8.9 이상인지 확인
        if [ -n "$MAJOR_VER" ] && [ -n "$MINOR_VER" ]; then
            if [ "$MAJOR_VER" -gt 8 ] || ([ "$MAJOR_VER" -eq 8 ] && [ "$MINOR_VER" -ge 9 ]); then
                # 8.9 이상 버전
                # 가이드: promiscuous_relay 확인, access 파일 확인
                if grep -q "promiscuous_relay" "$TARGET_FILE"; then
                     VULNERABLE=1
                     EVIDENCE="$EVIDENCE promiscuous_relay 설정(무조건 릴레이)이 발견되었습니다."
                fi
                
                if [ ! -f "/etc/mail/access" ] && [ ! -f "/etc/mail/access.db" ]; then
                     VULNERABLE=1
                     EVIDENCE="$EVIDENCE access 파일이 없어 릴레이 제어가 미흡합니다."
                fi
            else
                # 8.9 미만 버전
                # 가이드: sendmail.cf에 R$*$#error $@ 5.7.1 $: "550 Relaying denied" 확인
                if ! grep -q "Relaying denied" "$TARGET_FILE" 2>/dev/null; then
                    VULNERABLE=1
                    EVIDENCE="$EVIDENCE 8.9 미만 버전에서 Relaying denied 룰이 없습니다."
                fi
            fi
        else
            # 버전 확인 실패 시 두 가지 모두 확인
            if grep -q "promiscuous_relay" "$TARGET_FILE"; then
                 VULNERABLE=1
                 EVIDENCE="$EVIDENCE promiscuous_relay 설정이 발견되었습니다."
            fi
            if [ ! -f "/etc/mail/access" ] && [ ! -f "/etc/mail/access.db" ]; then
                if ! grep -q "Relaying denied" "$TARGET_FILE" 2>/dev/null; then
                    VULNERABLE=1
                    EVIDENCE="$EVIDENCE access 파일 및 Relaying denied 룰이 없습니다."
                fi
            fi
        fi
    fi
fi

# [Postfix]
if command -v postfix &>/dev/null; then
    MAIL_SERVICE="postfix"
    if [ -f "/etc/postfix/main.cf" ]; then
        TARGET_FILE="/etc/postfix/main.cf"
        FILE_HASH=$(sha256sum "$TARGET_FILE" 2>/dev/null | awk '{print $1}')
        
        # 1) smtpd_recipient_restrictions 설정 확인
        RESTRICTIONS=$(grep "^smtpd_recipient_restrictions" "$TARGET_FILE" 2>/dev/null)
        if [ -n "$RESTRICTIONS" ]; then
            if ! echo "$RESTRICTIONS" | grep -q "reject_unauth_destination"; then
                VULNERABLE=1
                EVIDENCE="$EVIDENCE Postfix smtpd_recipient_restrictions에 reject_unauth_destination가 없습니다."
            fi
        else
            VULNERABLE=1
            EVIDENCE="$EVIDENCE Postfix smtpd_recipient_restrictions 설정이 없습니다."
        fi
        
        # 2) mynetworks 설정 확인
        # 모든 IP 허용(0.0.0.0/0) 등이 있으면 취약
        MYNETWORKS=$(grep "^mynetworks" "$TARGET_FILE" 2>/dev/null)
        if echo "$MYNETWORKS" | grep -q "0.0.0.0/0"; then
            VULNERABLE=1
            EVIDENCE="$EVIDENCE Postfix mynetworks에 모든 IP(0.0.0.0/0)가 허용되어 있습니다."
        fi
    fi
fi

# [Exim]
# 가이드: exim.conf 파일에서 relay_from_hosts 및 ACL 설정 확인
if command -v exim &>/dev/null || command -v exim4 &>/dev/null; then
    MAIL_SERVICE="exim"
    CONF_FILES=("/etc/exim/exim.conf" "/etc/exim4/exim4.conf" "/etc/exim4/update-exim4.conf.conf")
    
    for conf in "${CONF_FILES[@]}"; do
        if [ -f "$conf" ]; then
            TARGET_FILE="$conf"
            FILE_HASH=$(sha256sum "$conf" 2>/dev/null | awk '{print $1}')
            
            # 1) relay_from_hosts 설정 확인
            # 가이드: relay_from_hosts = <허용할 네트워크 주소>
            RELAY_HOSTS=$(grep -v "^#" "$conf" | grep "relay_from_hosts")
            
            if [ -n "$RELAY_HOSTS" ]; then
                EVIDENCE="$EVIDENCE Exim relay_from_hosts: $RELAY_HOSTS."
                
                # * 또는 0.0.0.0/0 허용 시 취약
                if echo "$RELAY_HOSTS" | grep -qE "\*|0\.0\.0\.0/0"; then
                    VULNERABLE=1
                    EVIDENCE="$EVIDENCE relay_from_hosts에 모든 호스트(*)가 허용되어 취약합니다."
                fi
            else
                # relay_from_hosts 설정 없으면 기본값 확인 필요
                EVIDENCE="$EVIDENCE Exim relay_from_hosts 설정이 없습니다."
            fi
            
            # 2) ACL 설정 확인: accept hosts = +relay_from_hosts
            # 가이드: acl_check_rcpt에서 accept hosts = +relay_from_hosts 확인
            if grep -q "accept.*hosts.*=.*+relay_from_hosts" "$conf" 2>/dev/null; then
                EVIDENCE="$EVIDENCE accept hosts = +relay_from_hosts 설정이 있습니다."
            fi
            
            break
        fi
    done
fi

if [ -z "$MAIL_SERVICE" ]; then
    STATUS="PASS"
    EVIDENCE="메일 서비스가 설치되어 있지 않아 점검 대상이 없습니다."
elif [ $VULNERABLE -eq 1 ]; then
    STATUS="FAIL"
    EVIDENCE="스팸 릴레이 제한이 미흡하여, 외부에서 메일 서버를 경유한 스팸 발송이 가능한 위험이 있습니다. $EVIDENCE"
else
    STATUS="PASS"
    EVIDENCE="스팸 릴레이가 적절히 제한되어 있거나 기본 설정이 적용되어 있습니다."
fi


IMPACT_LEVEL="LOW"
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없으나, 메일 서비스 사용 시 릴레이 방지 설정 또는 릴레이 대상 접근 제어가 적용되므로 허용 범위(허용 대상/네트워크)를 운영 정책에 맞게 사전에 정의한 뒤 적용해야 합니다."

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
    "guide": "Postfix: mynetworks를 신뢰할 수 있는 IP 대역으로 제한하고, smtpd_relay_restrictions 설정을 강화해야 합니다.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
