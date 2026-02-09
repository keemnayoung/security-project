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
# @Platform : LINUX
# @Importance : 상
# @Title : 일반 사용자의 메일 서비스 실행 방지
# @Description : 일반 사용자가 메일 서비스를 실행할 수 없도록 제한되어 있는지 점검
# @Criteria_Good : 일반 사용자의 메일 서비스 실행이 제한된 경우
# @Criteria_Bad : 일반 사용자가 메일 서비스를 실행할 수 있는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-46 일반 사용자의 메일 서비스 실행 방지

# 1. 항목 정보 정의
ID="U-46"
CATEGORY="서비스관리"
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
               EVIDENCE="$EVIDENCE Sendmail PrivacyOptions에 restrictqrun 미설정;"
            fi
        else
            VULNERABLE=1
            EVIDENCE="$EVIDENCE Sendmail PrivacyOptions 설정 없음;"
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
            EVIDENCE="$EVIDENCE $POSTSUPER 일반 사용자 실행 권한 있음($PERMS);"
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
        EVIDENCE="$EVIDENCE $EXIQGREP 일반 사용자 실행 권한 있음($PERMS);"
    fi
fi

if [ -z "$MAIL_SERVICE" ] && [ -z "$MAIL_BINARY" ]; then
    STATUS="PASS"
    EVIDENCE="메일 서비스 미사용 (양호)"
elif [ $VULNERABLE -eq 1 ]; then
    STATUS="FAIL"
    EVIDENCE="일반 사용자 메일 실행 제한 미흡:$EVIDENCE"
else
    STATUS="PASS"
    EVIDENCE="일반 사용자의 메일 서비스 실행이 방지됨"
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
    "guide": "sendmail 실행파일에서 SUID 비트를 제거하세요: chmod u-s /usr/sbin/sendmail",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
