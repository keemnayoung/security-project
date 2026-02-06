#!/bin/bash
# [조치] U-11 사용자 shell 점검

ID="U-11"
TARGET_FILE="/etc/passwd"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"

# 가이드 기준 시스템 계정 목록
SYSTEM_ACCOUNTS=("daemon" "bin" "sys" "adm" "listen" "nobody" "nobody4" "noaccess" "diag" "operator" "games" "gopher")

if [ -f "$TARGET_FILE" ]; then
    # 1. 조치 전 백업 생성
    BACKUP_FILE="${TARGET_FILE}_bak_$(date +%Y%m%d_%H%M%S)"
    cp -p "$TARGET_FILE" "$BACKUP_FILE"

    FIXED_ACCOUNTS=()
    
    for acc in "${SYSTEM_ACCOUNTS[@]}"; do
        if id "$acc" >/dev/null 2>&1; then
            CURRENT_SHELL=$(grep "^${acc}:" "$TARGET_FILE" | awk -F: '{print $NF}')
            
            if [[ "$CURRENT_SHELL" != "/bin/false" && "$CURRENT_SHELL" != "/sbin/nologin" ]]; then
                # 2. 쉘 변경 실행 (표준인 /sbin/nologin으로 통일)
                if usermod -s /sbin/nologin "$acc" >/dev/null 2>&1; then
                    FIXED_ACCOUNTS+=("$acc")
                fi
            fi
        fi
    done

    if [ ${#FIXED_ACCOUNTS[@]} -gt 0 ]; then
        ACTION_RESULT="SUCCESS"
        ACTION_LOG="성공: 계정(${FIXED_ACCOUNTS[*]})의 쉘을 /sbin/nologin으로 변경 완료. 백업: $BACKUP_FILE"
    else
        ACTION_RESULT="SUCCESS"
        ACTION_LOG="양호: 조치할 대상 계정이 없습니다."
    fi
else
    ACTION_LOG="오류: 조치 대상 파일($TARGET_FILE)이 없습니다."
fi

# 3. JSON 표준 출력
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