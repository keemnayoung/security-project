#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-48
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : expn, vrfy 명령어 제한
# @Description : SMTP 서비스 사용 시 expn, vrfy 명령어 사용 금지 설정 여부 점검
# @Criteria_Good : 메일 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정
# @Criteria_Bad : 메일 서비스 사용 시 메일 서비스 설정 파일에 noexpn, novrfy 또는 goaway 옵션 추가 설정
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-48 expn, vrfy 명령어 제한

# 1. 항목 정보 정의
ID="U-48"
CATEGORY="서비스 관리"
TITLE="expn, vrfy 명령어 제한"
IMPORTANCE="중"
TARGET_FILE="/etc/postfix/main.cf"

# 2. 진단 로직 (무결성 해시 포함)
STATUS="PASS"
EVIDENCE=""
FILE_HASH="NOT_FOUND"

VULNERABLE=0
MAIL_SERVICE=""

# [Sendmail]
if command -v sendmail &>/dev/null; then
    MAIL_SERVICE="sendmail"
    CF_FILE="/etc/mail/sendmail.cf"
    if [ -f "$CF_FILE" ]; then
        TARGET_FILE="$CF_FILE"
        FILE_HASH=$(sha256sum "$TARGET_FILE" 2>/dev/null | awk '{print $1}')
        PRIVACY=$(grep -i "^O PrivacyOptions" "$TARGET_FILE")
        
        # goaway 또는 (noexpn AND novrfy) 확인
        # 순서 무관하게 확인해야 하므로 다소 복잡
        if echo "$PRIVACY" | grep -q "goaway"; then
             : # 안전
        elif echo "$PRIVACY" | grep -q "novrfy" && echo "$PRIVACY" | grep -q "noexpn"; then
             : # 안전
        else
             VULNERABLE=1
             EVIDENCE="$EVIDENCE Sendmail PrivacyOptions에 expn/vrfy 제한 미흡;"
        fi
    fi
fi

# [Postfix]
if command -v postfix &>/dev/null; then
    MAIL_SERVICE="postfix"
    MAIN_CF="/etc/postfix/main.cf"
    if [ -f "$MAIN_CF" ]; then
        TARGET_FILE="$MAIN_CF"
        FILE_HASH=$(sha256sum "$TARGET_FILE" 2>/dev/null | awk '{print $1}')
        
        # disable_vrfy_command = yes 확인
        if grep -qE "^disable_vrfy_command\s*=\s*yes" "$MAIN_CF"; then
             : # 안전
        else
             VULNERABLE=1
             EVIDENCE="$EVIDENCE Postfix disable_vrfy_command=yes 미설정;"
        fi
        
        # Postfix는 기본적으로 expn은 지원하지 않으므로 vrfy만 확인하면 됨 (가이드 기준)
    fi
fi

# [Exim]
if command -v exim &>/dev/null || command -v exim4 &>/dev/null; then
    MAIL_SERVICE="exim"
    # acl_smtp_vrfy, acl_smtp_expn 설정이 있으면 취약할 수 있음 (allow 등)
    # 가이드: 해당 옵션이 허용된 경우 취약
    # 단순히 존재 여부 보다는 설정값 확인이 필요하나, 여기서는 grep으로 accept 확인
    
    CONF_FILES=("/etc/exim/exim.conf" "/etc/exim4/exim4.conf")
    for conf in "${CONF_FILES[@]}"; do
        if [ -f "$conf" ]; then
             if grep -E "^acl_smtp_vrfy\s*=\s*accept|^acl_smtp_expn\s*=\s*accept" "$conf"; then
                 VULNERABLE=1
                 EVIDENCE="$EVIDENCE Exim expn/vrfy 허용 설정 발견;"
             fi
        fi
    done
fi

if [ -z "$MAIL_SERVICE" ]; then
    STATUS="PASS"
    EVIDENCE="메일 서비스 미사용 (양호)"
elif [ $VULNERABLE -eq 1 ]; then
    STATUS="FAIL"
    EVIDENCE="expn/vrfy 명령어 제한 미흡: $EVIDENCE"
else
    STATUS="PASS"
    EVIDENCE="expn/vrfy 명령어가 제한되어 있음"
fi


IMPACT_LEVEL="LOW"
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없으나, 메일 서비스 설정 파일에 noexpn·novrfy(또는 goaway) 옵션이 적용되므로 관련 진단·운영 방식은 변경된 정책을 반영하여 수행해야 합니다."

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
    "guide": "Postfix: main.cf에 disable_vrfy_command=yes 설정, Sendmail: PrivacyOptions에 noexpn,novrfy 추가하세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
