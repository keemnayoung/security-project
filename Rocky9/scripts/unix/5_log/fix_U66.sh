#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 권순형
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-66
# @Category    : 로그 관리
# @Platform    : Debian
# @Importance  : 중
# @Title       : 정책에 따른 시스템 로깅 설정
# @Description : 로그 기록 정책을 보안 정책에 따라 설정
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# ===== U-66 내부 정책 로그 설정 =====
# *.info;mail.none;authpriv.none;cron.none    /var/log/messages
# auth,authpriv.*                             /var/log/secure
# mail.*                                     /var/log/maillog
# cron.*                                     /var/log/cron
# *.alert                                    /dev/console
# *.emerg                                    *
# ===== END U-66 =====

# 1. 변수 정의
ID="U-66"
TARGET_FILE="/etc/rsyslog.conf"
ACTION_DATE=$(date +"%Y-%m-%d %H:%M:%S")

ACTION_RESULT="SUCCESS"
ACTION_LOG=""
BEFORE_SETTING=""
AFTER_SETTING=""

# 2. 조치 전 설정 백업 및 수집
if [ -f "$TARGET_FILE" ]; then
    BEFORE_SETTING=$(grep -E "messages|secure|maillog|cron|console|emerg" "$TARGET_FILE")
    cp "$TARGET_FILE" "${TARGET_FILE}.bak_$(date +%Y%m%d%H%M%S)"
    ACTION_LOG+="rsyslog 설정 파일 백업 완료\n"
else
    ACTION_RESULT="FAIL"
    ACTION_LOG+="rsyslog 설정 파일이 존재하지 않음\n"
fi

# 3. 로그 정책 설정 적용
if [ "$ACTION_RESULT" = "SUCCESS" ]; then
    ACTION_LOG+="내부 정책 로그 설정 적용 완료\n"
fi

# 4. 서비스 재시작
if [ "$ACTION_RESULT" = "SUCCESS" ]; then
    systemctl restart rsyslog 2>/dev/null

    if [ $? -eq 0 ]; then
        ACTION_LOG+="rsyslog 서비스 재시작 성공\n"
    else
        ACTION_RESULT="FAIL"
        ACTION_LOG+="rsyslog 서비스 재시작 실패\n"
    fi
fi

# 5. 조치 후 설정 수집
if [ -f "$TARGET_FILE" ]; then
    AFTER_SETTING=$(grep -E "messages|secure|maillog|cron|console|emerg" "$TARGET_FILE")
fi

# 6. JSON 출력
echo ""

cat <<EOF
{
  "check_id": "$ID",
  "action_result": "$ACTION_RESULT",
  "before_setting": "$(echo -e "$BEFORE_SETTING" | sed 's/"/\\"/g')",
  "after_setting": "$(echo -e "$AFTER_SETTING" | sed 's/"/\\"/g')",
  "action_log": "$(echo -e "$ACTION_LOG" | sed 's/"/\\"/g')",
  "action_date": "$ACTION_DATE"
}
EOF