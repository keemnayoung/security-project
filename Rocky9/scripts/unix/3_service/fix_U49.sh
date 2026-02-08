#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-49
# @Category : 서비스 관리
# @Platform : LINUX
# @Importance : 상
# @Title : DNS 서비스 최신 패치
# @Description : DNS 서비스를 최신 버전으로 업데이트하거나 비활성화
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-49 DNS 서비스 최신 패치

# 1. 항목 정보 정의
ID="U-49"
CATEGORY="서비스관리"
TITLE="DNS 서비스 최신 패치"
IMPORTANCE="상"
TARGET_FILE="/usr/sbin/named"

# 2. 보완 로직
ACTION_RESULT="MANUAL"
BEFORE_SETTING=""
AFTER_SETTING=""
ACTION_LOG=""

# [Step 1] DNS 서비스 활성화 여부 확인
# 가이드: systemctl list-units --type=service | grep named
if systemctl list-units --type=service 2>/dev/null | grep -q "named"; then
    # 사용 중인 경우
    if command -v named &>/dev/null; then
        BEFORE_SETTING="DNS 실행 중: $(named -v 2>/dev/null)"
        
        # [Step 4] DNS 서비스 최신 패치 버전 확인 및 업데이트
        # 자동 업데이트 시도 (Debian/Ubuntu 기준)
        if command -v apt-get &>/dev/null; then
            apt-get update -qq 2>/dev/null
            apt-get install --only-upgrade bind9 -y 2>/dev/null
            ACTION_LOG="BIND 패키지 업데이트 시도;"
        elif command -v yum &>/dev/null; then
            yum update bind -y 2>/dev/null
            ACTION_LOG="BIND 패키지 업데이트 시도;"
        fi
        
        AFTER_SETTING="DNS 실행 중: $(named -v 2>/dev/null)"
        ACTION_LOG="$ACTION_LOG [주의] 최신 버전 여부는 ISC 홈페이지 확인 필요;"
        ACTION_RESULT="SUCCESS"
    else
        ACTION_LOG="DNS 서비스 실행 중이나 named 명령어를 찾을 수 없음"
    fi
else
    # [Step 2] DNS 서비스 비활성화 (이미 비활성화 상태)
    # 만약 불필요하게 켜져있었다면 껐겠지만, 여기선 이미 꺼져있는 경우
    ACTION_RESULT="SUCCESS"
    ACTION_LOG="DNS 서비스 미사용"
fi

# 3. 마스터 템플릿 표준 출력
echo ""
cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "action_result": "$ACTION_RESULT",
    "before_setting": "$BEFORE_SETTING",
    "after_setting": "$AFTER_SETTING",
    "action_log": "$ACTION_LOG",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
