#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-55
# @Category : 서비스 관리
# @Platform : LINUX
# @Importance : 상
# @Title : Anonymous FTP 비활성화
# @Description : ftp 계정의 로그인 쉘을 로그인이 불가능하도록 변경
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-55 Anonymous FTP 비활성화 (ftp 계정 쉘 제한)

# 1. 항목 정보 정의
ID="U-55"
CATEGORY="서비스관리"
TITLE="Anonymous FTP 비활성화"
IMPORTANCE="상"
TARGET_FILE="/etc/passwd"

# 2. 보완 로직
ACTION_RESULT="SUCCESS"
BEFORE_SETTING=""
AFTER_SETTING=""
ACTION_LOG=""

if grep -q "^ftp:" "/etc/passwd"; then
    CURRENT_SHELL=$(grep "^ftp:" "/etc/passwd" | awk -F: '{print $7}')
    BEFORE_SETTING="ftp shell: $CURRENT_SHELL"
    
    # 쉘 변경 필요 여부 확인
    if [[ "$CURRENT_SHELL" != "/bin/false" && "$CURRENT_SHELL" != "/sbin/nologin" && "$CURRENT_SHELL" != "/usr/sbin/nologin" ]]; then
        # usermod로 변경 시도
        if command -v usermod &>/dev/null; then
            usermod -s /bin/false ftp
            ACTION_LOG="ftp 계정 쉘을 /bin/false로 변경 (usermod)"
        else
            # usermod 없으면 sed로 직접 수정 (백업 후)
            cp /etc/passwd /etc/passwd.bak_$(date +%Y%m%d_%H%M%S)
            sed -i 's|^ftp:\(.*\):[^:]*$|ftp:\1:/bin/false|' /etc/passwd
            ACTION_LOG="ftp 계정 쉘을 /bin/false로 변경 (sed)"
        fi
        
        AFTER_SHELL=$(grep "^ftp:" "/etc/passwd" | awk -F: '{print $7}')
        AFTER_SETTING="ftp shell: $AFTER_SHELL"
    else
        ACTION_RESULT="SUCCESS"
        ACTION_LOG="ftp 계정 쉘이 이미 제한되어 있음"
        AFTER_SETTING="$BEFORE_SETTING"
    fi
else
    ACTION_RESULT="SUCCESS"
    ACTION_LOG="ftp 계정이 존재하지 않음"
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
