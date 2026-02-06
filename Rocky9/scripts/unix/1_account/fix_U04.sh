#!/bin/bash
# [조치] U-04 비밀번호 파일 보호

ID="U-04"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
ACTION_RESULT="FAIL"
CURRENT_STATUS="FAIL"
ACTION_LOG="N/A"

# 1. 백업 (passwd와 shadow 모두 백업)
[ -f /etc/passwd ] && cp -p /etc/passwd /etc/passwd_bak_$TIMESTAMP
[ -f /etc/shadow ] && cp -p /etc/shadow /etc/shadow_bak_$TIMESTAMP

# 2. pwconv 실행 (쉐도우 패스워드 정책 적용)
if command -v pwconv >/dev/null 2>&1; then
    pwconv
    
    # 3. [검증] 조치 후 실제 /etc/passwd 파일 확인
    CHECK_COUNT=$(awk -F: '$2 != "x" {print $1}' /etc/passwd | wc -l)
    
    if [ "$CHECK_COUNT" -eq 0 ]; then
        ACTION_RESULT="SUCCESS"
        CURRENT_STATUS="PASS"
        ACTION_LOG="성공: pwconv 실행 완료 및 모든 계정 쉐도우 패스워드 적용 확인"
    else
        ACTION_RESULT="FAIL"
        ACTION_LOG="실패: pwconv 실행 후에도 ${CHECK_COUNT}개의 계정이 미적용 상태입니다."
    fi
else
    ACTION_RESULT="ERROR"
    ACTION_LOG="오류: 시스템에서 pwconv 명령어를 찾을 수 없습니다."
fi

# 4. 표준 JSON 출력
echo ""
cat << EOF
{
    "check_id": "$ID",
    "status": "$CURRENT_STATUS",
    "action_result": "$ACTION_RESULT",
    "action_log": "$ACTION_LOG",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF