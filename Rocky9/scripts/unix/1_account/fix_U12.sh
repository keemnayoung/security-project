#!/bin/bash
# [조치] U-12 세션 종료 시간 설정

ID="U-12"
TARGET_FILE="/etc/profile"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"

if [ -f "$TARGET_FILE" ]; then
    # 1. 조치 전 백업 생성
    BACKUP_FILE="${TARGET_FILE}_bak_$(date +%Y%m%d_%H%M%S)"
    cp -p "$TARGET_FILE" "$BACKUP_FILE"

    # 2. 설정 변경 실행 (TMOUT=600 설정)
    if grep -q "TMOUT" "$TARGET_FILE"; then
        # 기존 설정이 있으면 수정
        sed -i 's/TMOUT=[0-9]*/TMOUT=600/g' "$TARGET_FILE"
    else
        # 기존 설정이 없으면 파일 끝에 추가
        echo "" >> "$TARGET_FILE"
        echo "TMOUT=600" >> "$TARGET_FILE"
        echo "export TMOUT" >> "$TARGET_FILE"
    fi

    # 3. 조치 결과 확인
    AFTER_VAL=$(grep -i "TMOUT" "$TARGET_FILE" | grep -v "^#" | cut -d= -f2 | xargs | tail -1)
    if [ "$AFTER_VAL" == "600" ]; then
        ACTION_RESULT="SUCCESS"
        ACTION_LOG="성공: 세션 종료 시간을 600초로 설정 완료. 백업: $BACKUP_FILE"
    else
        ACTION_LOG="실패: 설정 반영 중 오류가 발생했습니다."
    fi
else
    ACTION_LOG="오류: 조치 대상 파일($TARGET_FILE)이 없습니다."
fi

# 4. JSON 표준 출력
echo ""
cat << EOF
{
    "check_id": "$ID",
    "action_result": "$ACTION_RESULT",
    "action_log": "$ACTION_LOG",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF