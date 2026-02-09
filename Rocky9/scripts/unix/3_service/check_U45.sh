#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-45
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 메일 서비스 버전 점검
# @Description : 취약한 버전의 메일 서비스 이용 여부 점검
# @Criteria_Good :  메일 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정
# @Criteria_Bad : 메일 서비스 사용 시 패치 관리 정책을 수립하여 주기적으로 패치 적용 설정
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-45 메일 서비스 버전 점검

# 1. 항목 정보 정의
ID="U-45"
CATEGORY="서비스 관리"
TITLE="메일 서비스 버전 점검"
IMPORTANCE="상"
TARGET_FILE="/etc/mail/sendmail.cf"

# 2. 진단 로직 (무결성 해시 포함)
STATUS="PASS"
EVIDENCE=""
FILE_HASH="NOT_FOUND"

VULNERABLE=0
MAIL_VERSION=""

# [Sendmail]
# 가이드: sendmail -d0 -bt
if command -v sendmail &>/dev/null; then
    # 버전 정보만 추출
    MAIL_VERSION=$(sendmail -d0 < /dev/null 2>/dev/null | grep -i "Version" | awk '{print $2}')
    if systemctl is-active sendmail >/dev/null 2>&1; then
       EVIDENCE="$EVIDENCE Sendmail 실행중(버전:$MAIL_VERSION) - 최신 패치 필요;"
       # 버전 확인은 수동으로 해야 하므로, 실행 여부만 체크하고 WARN 처리
       # 가이드에서는 "사용하지 않는 경우" 중지해야 한다고 명시
    fi
    TARGET_FILE="/etc/mail/sendmail.cf"
fi

# [Postfix]
# 가이드: postconf mail_version
if command -v postconf &>/dev/null; then
    MAIL_VERSION=$(postconf mail_version 2>/dev/null | cut -d= -f2 | xargs)
    if systemctl is-active postfix >/dev/null 2>&1; then
        EVIDENCE="$EVIDENCE Postfix 실행중(버전:$MAIL_VERSION) - 최신 패치 필요;"
        TARGET_FILE="/etc/postfix/main.cf"
    else
        # 사용하지 않는데 프로세스가 있으면 취약
        if ps -ef | grep -v grep | grep -q postfix; then
             VULNERABLE=1
             EVIDENCE="$EVIDENCE Postfix 서비스 중지되었으나 프로세스 잔존;"
        fi
    fi
fi

# [Exim]
# 가이드: exim --version
if command -v exim &>/dev/null || command -v exim4 &>/dev/null; then
    MAIL_VERSION=$(exim --version 2>/dev/null | head -1 | awk '{print $3}')
    if systemctl is-active exim4 >/dev/null 2>&1; then
        EVIDENCE="$EVIDENCE Exim 실행중(버전:$MAIL_VERSION) - 최신 패치 필요;"
        TARGET_FILE="/etc/exim4/exim4.conf"
    else
        if ps -ef | grep -v grep | grep -q exim; then
             VULNERABLE=1
             EVIDENCE="$EVIDENCE Exim 서비스 중지되었으나 프로세스 잔존;"
        fi
    fi
fi

# 결과 판단
# 메일 서비스가 실행 중이면 취약으로 판단 (최신 패치 확인 필요)

if [ $VULNERABLE -eq 1 ]; then
    STATUS="FAIL"
    EVIDENCE="사용하지 않는 메일 서비스 프로세스 실행 중: $EVIDENCE"
elif [ -n "$EVIDENCE" ]; then
    # 실행 중인 메일 서비스가 있음 -> 취약으로 판단 (최신 패치 확인 필요)
    STATUS="FAIL"
    EVIDENCE="메일 서비스 실행 중 - 최신 보안 패치 적용 여부 확인 필요: $EVIDENCE"
else
    STATUS="PASS"
    EVIDENCE="메일 서비스가 설치되어 있지 않음"
fi


IMPACT_LEVEL="HIGH"
ACTION_IMPACT="메일 서비스 보안 패치 적용 시 시스템 및 서비스의 구성 변경 또는 서비스 재시작이 수반될 수 있어 운영 중 서비스 영향이 발생할 수 있습니다. 특히 운영 중단 가능성과 적용 범위를 사전에 평가한 뒤 변경관리 절차에 따라 단계적으로 적용해야 합니다."

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
    "guide": "메일 서비스 최신 버전으로 업데이트하거나 불필요시 systemctl stop postfix && systemctl disable postfix로 비활성화하세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
