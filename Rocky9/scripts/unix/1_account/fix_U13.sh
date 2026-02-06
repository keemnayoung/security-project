
#!/bin/bash
# [조치] U-13 안전한 비밀번호 암호화 알고리즘 사용

ID="U-13"
DEFS_FILE="/etc/login.defs"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"

if [ -f "$DEFS_FILE" ]; then
    # 1. 백업 생성
    BACKUP_FILE="${DEFS_FILE}_bak_$(date +%Y%m%d_%H%M%S)"
    cp -p "$DEFS_FILE" "$BACKUP_FILE"

    # 2. ENCRYPT_METHOD를 SHA512로 변경
    if grep -q "^ENCRYPT_METHOD" "$DEFS_FILE"; then
        sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/g' "$DEFS_FILE"
    else
        echo "ENCRYPT_METHOD SHA512" >> "$DEFS_FILE"
    fi

    # 3. 조치 결과 확인
    RESULT_VAL=$(grep "^ENCRYPT_METHOD" "$DEFS_FILE" | awk '{print $2}')
    if [ "$RESULT_VAL" == "SHA512" ]; then
        ACTION_RESULT="SUCCESS"
        ACTION_LOG="성공: 암호화 알고리즘을 SHA512로 변경 완료. 단, 기존 계정은 비밀번호 재설정이 필요합니다. 백업: $BACKUP_FILE"
    else
        ACTION_LOG="실패: 설정 변경 중 오류가 발생했습니다."
    fi
else
    ACTION_LOG="오류: 조치 대상 파일($DEFS_FILE)이 없습니다."
fi

# 4. JSON 표준 출력
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