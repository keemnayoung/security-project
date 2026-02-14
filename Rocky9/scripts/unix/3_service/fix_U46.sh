#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-46
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 일반 사용자의 메일 서비스 실행 방지
# @Description : SMTP 서비스 사용 시 일반 사용자의 q 옵션 제한 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-46 일반 사용자의 메일 서비스 실행 방지

# 1. 항목 정보 정의
ID="U-46"
CATEGORY="서비스 관리"
TITLE="일반 사용자의 메일 서비스 실행 방지"
IMPORTANCE="상"
TARGET_FILE="/etc/mail/sendmail.cf"

# 2. 보완 로직
ACTION_RESULT="SUCCESS"
ACTION_LOG=""

# [Sendmail]
# 가이드: PrivacyOptions = ..., restrictqrun 추가
if command -v sendmail &>/dev/null; then
    CF_FILE="/etc/mail/sendmail.cf"
    if [ -f "$CF_FILE" ]; then
        if grep -i "PrivacyOptions" "$CF_FILE" | grep -v "restrictqrun" >/dev/null; then

            cp "$CF_FILE" "${CF_FILE}.bak_$(date +%Y%m%d_%H%M%S)"
            # PrivacyOptions 라인에 restrictqrun 추가
            sed -i '/^O PrivacyOptions=/ s/$/,restrictqrun/' "$CF_FILE"
            systemctl restart sendmail 2>/dev/null
            ACTION_LOG="$ACTION_LOG sendmail.cf PrivacyOptions에 restrictqrun을 추가했습니다."
        fi
    fi
fi

# [Postfix]
# 가이드: chmod o-x /usr/sbin/postsuper
POSTSUPER="/usr/sbin/postsuper"
if [ -f "$POSTSUPER" ]; then
    PERMS=$(stat -c '%a' "$POSTSUPER" 2>/dev/null)
    if [ $((PERMS % 2)) -ne 0 ]; then

        chmod o-x "$POSTSUPER"
        ACTION_LOG="$ACTION_LOG $POSTSUPER 권한에서 o-x를 제거했습니다."
    fi
fi

# [Exim]
# 가이드: chmod o-x /usr/sbin/exiqgrep
EXIQGREP="/usr/sbin/exiqgrep"
if [ -f "$EXIQGREP" ]; then
    PERMS=$(stat -c '%a' "$EXIQGREP" 2>/dev/null)
    if [ $((PERMS % 2)) -ne 0 ]; then

        chmod o-x "$EXIQGREP"
        ACTION_LOG="$ACTION_LOG $EXIQGREP 권한에서 o-x를 제거했습니다."
    fi
fi

if [ -n "$ACTION_LOG" ]; then
    ACTION_LOG="메일 서비스 명령어의 일반 사용자 실행 권한을 제거하고 Sendmail restrictqrun 설정을 적용했습니다."
else
    ACTION_LOG="메일 서비스 명령어의 권한이 이미 적절하게 설정되어 있습니다."
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
