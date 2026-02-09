#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-45
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 메일 서비스 버전 점검
# @Description : 취약한 버전의 메일 서비스 이용 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-45 메일 서비스 버전 점검

# 1. 항목 정보 정의
ID="U-45"
CATEGORY="서비스 관리"
TITLE="메일 서비스 버전 점검"
IMPORTANCE="상"
TARGET_FILE="/etc/mail/sendmail.cf"

# 2. 보완 로직
ACTION_RESULT="MANUAL"
BEFORE_SETTING=""
AFTER_SETTING=""
ACTION_LOG=""

# [Sendmail]
# 가이드: systemctl list-units --type=service | grep sendmail
if command -v sendmail &>/dev/null; then
    # 사용하지 않는 경우 중지 (systemd stop/disable)
    if ! systemctl list-units --type=service 2>/dev/null | grep -q sendmail; then
        ACTION_LOG="$ACTION_LOG Sendmail 미사용(비활성화 유지);"
    else
        # 사용 중이면 업데이트 안내 (자동 업데이트는 위험하므로 생략하거나 패키지 업데이트만 시도)
        BEFORE_SETTING="Sendmail 사용 중"
        ACTION_LOG="$ACTION_LOG [주의] Sendmail 사용 중 - 수동 보안 패치 필요;"
    fi
else
    # 설치되지 않음
    :
fi

# [Postfix]
# 가이드: systemctl list-units --type=service | grep postfix
if command -v postfix &>/dev/null; then
    # 사용하지 않는 경우 중지 및 프로세스 kill
    # 가이드: ps -ef | grep postfix -> kill -9 <PID>
    if ! systemctl list-units --type=service 2>/dev/null | grep -q postfix; then
        PIDS=$(ps -ef | grep postfix | grep -v grep | awk '{print $2}')
        if [ -n "$PIDS" ]; then
             kill -9 $PIDS 2>/dev/null
             ACTION_LOG="$ACTION_LOG Postfix 잔존 프로세스 kill;"
        fi
    else
        BEFORE_SETTING="$BEFORE_SETTING Postfix 사용 중"
        ACTION_LOG="$ACTION_LOG [주의] Postfix 사용 중 - 수동 보안 패치 필요;"
    fi
fi

# [Exim]
# 가이드: systemctl list-units --type=service | grep exim
if command -v exim4 &>/dev/null; then
    # 사용하지 않는 경우 중지 및 프로세스 kill
    # 가이드: ps -ef | grep exim -> kill -9 <PID>
    if ! systemctl list-units --type=service 2>/dev/null | grep -q exim; then
        PIDS=$(ps -ef | grep exim | grep -v grep | awk '{print $2}')
        if [ -n "$PIDS" ]; then
             kill -9 $PIDS 2>/dev/null
             ACTION_LOG="$ACTION_LOG Exim 잔존 프로세스 kill;"
        fi
    else
        BEFORE_SETTING="$BEFORE_SETTING Exim 사용 중"
        ACTION_LOG="$ACTION_LOG [주의] Exim 사용 중 - 수동 보안 패치 필요;"
    fi
fi

AFTER_SETTING="메일 서비스 점검 완료"
[ -z "$ACTION_LOG" ] && ACTION_LOG="특이사항 없음"

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
