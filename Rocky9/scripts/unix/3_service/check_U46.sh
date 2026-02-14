#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-46
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 일반 사용자의 메일 서비스 실행 방지
# @Description : SMTP 서비스 사용 시 일반 사용자의 q 옵션 제한 여부 점검
# @Criteria_Good : 메일 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정
# @Criteria_Bad : 메일 서비스 사용 시 메일 서비스의 q 옵션 제한 설정
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-46 일반 사용자의 메일 서비스 실행 방지

# 1. 항목 정보 정의
ID="U-46"
CATEGORY="서비스 관리"
TITLE="일반 사용자의 메일 서비스 실행 방지"
IMPORTANCE="상"
TARGET_FILE="/etc/mail/sendmail.cf"

# 2. 진단 로직 (무결성 해시 포함)
STATUS="PASS"
EVIDENCE=""
FILE_HASH="NOT_FOUND"

VULNERABLE=0
MAIL_SERVICE=""

# [Sendmail]
# 가이드: sendmail.cf PrivacyOptions에 restrictqrun 확인
if command -v sendmail &>/dev/null; then
    MAIL_SERVICE="sendmail"
    CF_FILE="/etc/mail/sendmail.cf"
    if [ -f "$CF_FILE" ]; then
        TARGET_FILE="$CF_FILE"
        FILE_HASH=$(sha256sum "$TARGET_FILE" 2>/dev/null | awk '{print $1}')
        # PrivacyOptions 행 찾기
        PRIVACY=$(grep -i "PrivacyOptions" "$CF_FILE" | grep -v "^#")
        if [ -n "$PRIVACY" ]; then
            if ! echo "$PRIVACY" | grep -q "restrictqrun"; then
               VULNERABLE=1
               EVIDENCE="$EVIDENCE Sendmail PrivacyOptions에 restrictqrun이 설정되어 있지 않습니다."
            fi
        else
            VULNERABLE=1
            EVIDENCE="$EVIDENCE Sendmail PrivacyOptions 설정이 없습니다."
        fi
    fi
fi

# [Postfix]
# 가이드: ls -l /usr/sbin/postsuper (others 실행 권한 확인)
if command -v postsuper &>/dev/null; then
    MAIL_SERVICE="postfix"
    POSTSUPER="/usr/sbin/postsuper"
    if [ -f "$POSTSUPER" ]; then
        PERMS=$(stat -c '%a' "$POSTSUPER" 2>/dev/null)
        # others 권한(마지막 자리)이 0이 아니면, 즉 1(x) 이상이면 취약
        # 8진수 모드에서 o-x가 안 되어 있으면 취약
        if [ $((PERMS % 2)) -ne 0 ]; then
            VULNERABLE=1
            EVIDENCE="$EVIDENCE $POSTSUPER에 일반 사용자 실행 권한이 있습니다. (현재: $PERMS)"
        fi
    fi
fi

# [Exim]
# 가이드: ls -l /usr/sbin/exiqgrep (others 실행 권한 확인)
# 실제로는 exim 관련 명령어
EXIQGREP="/usr/sbin/exiqgrep"
if [ -f "$EXIQGREP" ]; then
    MAIL_BINARY="exim"
    PERMS=$(stat -c '%a' "$EXIQGREP" 2>/dev/null)
    if [ $((PERMS % 2)) -ne 0 ]; then
        VULNERABLE=1
        EVIDENCE="$EVIDENCE $EXIQGREP에 일반 사용자 실행 권한이 있습니다($PERMS)."
    fi
fi

if [ -z "$MAIL_SERVICE" ] && [ -z "$MAIL_BINARY" ]; then
    STATUS="PASS"
    EVIDENCE="메일 서비스가 설치되어 있지 않아 점검 대상이 없습니다."
elif [ $VULNERABLE -eq 1 ]; then
    STATUS="FAIL"
    EVIDENCE="일반 사용자가 메일 서비스를 실행할 수 있어, 비인가 메일 발송이 발생할 수 있는 위험이 있습니다. $EVIDENCE"
else
    STATUS="PASS"
    EVIDENCE="일반 사용자의 메일 서비스 실행이 방지되어 있습니다."
fi


IMPACT_LEVEL="LOW"
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없으나, 메일 서비스 사용 시 q 옵션 제한이 적용되므로 관련 운영 작업은 관리자 권한 및 승인된 운영 절차에 따라 수행해야 합니다."

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
    "guide": "sendmail 실행파일에서 SUID 비트를 chmod u-s /usr/sbin/sendmail을 통해 제거해야 합니다: ",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
