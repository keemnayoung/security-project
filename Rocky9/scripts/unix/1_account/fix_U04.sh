#!/bin/bash
# [조치] U-04 비밀번호 파일 보호 (쉐도우 패스워드 적용)

ID="U-04"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"

# 1. pwconv 명령 실행 (쉐도우 패스워드 적용)
if command -v pwconv >/dev/null 2>&1; then
    pwconv
    # 조치 후 재검증
    CHECK_FAIL=$(awk -F: '$2 != "x" {print $1}' /etc/passwd | wc -l)
    if [ "$CHECK_FAIL" -eq 0 ]; then
        ACTION_RESULT="SUCCESS"
        ACTION_LOG="pwconv 실행을 통해 모든 계정에 쉐도우 패스워드 적용 완료"
    else
        ACTION_LOG="pwconv 실행 후에도 일부 계정이 암호화되지 않았습니다."
    fi
else
    ACTION_LOG="pwconv 명령어를 찾을 수 없습니다."
fi

echo ""
cat << EOF
{
    "check_id": "$ID",
    "action_type": "auto",
    "action_result": "$ACTION_RESULT",
    "action_log": "$ACTION_LOG",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF