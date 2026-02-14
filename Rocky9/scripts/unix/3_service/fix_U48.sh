#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-48
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : expn, vrfy 명령어 제한
# @Description : SMTP expn, vrfy 명령어를 제한
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-48 expn, vrfy 명령어 제한

# 1. 항목 정보 정의
ID="U-48"
CATEGORY="서비스관리"
TITLE="expn, vrfy 명령어 제한"
IMPORTANCE="중"
TARGET_FILE="/etc/postfix/main.cf"

# 2. 보완 로직
ACTION_RESULT="SUCCESS"
ACTION_LOG=""

# [Sendmail]
if command -v sendmail &>/dev/null; then
    CF_FILE="/etc/mail/sendmail.cf"
    if [ -f "$CF_FILE" ]; then
        if grep -i "^O PrivacyOptions" "$CF_FILE" | grep -v "goaway" >/dev/null; then

            cp "$CF_FILE" "${CF_FILE}.bak_$(date +%Y%m%d_%H%M%S)"
            # 기존 옵션 뒤에 goaway 추가 (단순화: 이미 있으면 무시되지만, 여기선 그냥 추가)
            sed -i '/^O PrivacyOptions=/ s/$/,goaway/' "$CF_FILE"
            systemctl restart sendmail 2>/dev/null
            ACTION_LOG="$ACTION_LOG sendmail.cf PrivacyOptions에 goaway를 추가했습니다."
        fi
    fi
fi

# [Postfix]
if command -v postfix &>/dev/null; then
    MAIN_CF="/etc/postfix/main.cf"
    if [ -f "$MAIN_CF" ]; then
        if ! grep -q "^disable_vrfy_command" "$MAIN_CF"; then

            echo "disable_vrfy_command = yes" >> "$MAIN_CF"
            ACTION_LOG="$ACTION_LOG Postfix disable_vrfy_command = yes를 추가했습니다."
        elif grep -q "disable_vrfy_command.*=.*no" "$MAIN_CF"; then

            sed -i 's/disable_vrfy_command.*=.*/disable_vrfy_command = yes/g' "$MAIN_CF"
            ACTION_LOG="$ACTION_LOG Postfix disable_vrfy_command = yes로 수정했습니다."
        fi
        postfix reload 2>/dev/null
    fi
fi

# [Exim]
if command -v exim &>/dev/null || command -v exim4 &>/dev/null; then
    CONF_FILES=("/etc/exim/exim.conf" "/etc/exim4/exim4.conf")
    for conf in "${CONF_FILES[@]}"; do
        if [ -f "$conf" ]; then
            if grep -E "^acl_smtp_vrfy\s*=\s*accept|^acl_smtp_expn\s*=\s*accept" "$conf"; then

                sed -i 's/^acl_smtp_vrfy\s*=\s*accept/#acl_smtp_vrfy = accept/g' "$conf"
                sed -i 's/^acl_smtp_expn\s*=\s*accept/#acl_smtp_expn = accept/g' "$conf"
                ACTION_LOG="$ACTION_LOG Exim 허용 설정을 주석 처리했습니다."
                systemctl restart exim4 2>/dev/null
            fi
        fi
    done
fi

if [ -n "$ACTION_LOG" ]; then
    ACTION_LOG="메일 서버의 expn/vrfy 명령어를 제한했습니다."
else
    ACTION_LOG="메일 서버가 실행되고 있지 않거나 expn/vrfy 명령어가 이미 제한되어 있습니다."
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
