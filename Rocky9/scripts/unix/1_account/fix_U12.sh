#!/bin/bash
# [조치] U-12 세션 종료 시간 설정

ID="U-12"
CATEGORY="계정관리"
TITLE="세션 종료 시간 설정"
IMPORTANCE="하"
TARGET_FILE="/etc/profile"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
ACTION_RESULT="FAIL"
CURRENT_STATUS="FAIL"
ACTION_LOG="N/A"

if [ -f "$TARGET_FILE" ]; then
    # 1. 안전한 복구를 위한 백업 생성
    cp -p "$TARGET_FILE" "${TARGET_FILE}_bak_$TIMESTAMP"

    # 2. [조치 정교화] 기존 TMOUT 관련 모든 설정(주석 포함) 제거 후 표준 설정 삽입
    sed -i '/TMOUT/d' "$TARGET_FILE"
    
    # 파일 끝에 설정 추가
    {
        echo ""
        echo "# Security Policy: Session Timeout"
        echo "TMOUT=600"
        echo "export TMOUT"
    } >> "$TARGET_FILE"

    # 3. [핵심 검증] 조치 후 실제 반영 값 확인
    AFTER_VAL=$(grep -i "^TMOUT=" "$TARGET_FILE" | cut -d= -f2 | sed 's/[^0-9]//g' | xargs)
    
    if [ "$AFTER_VAL" == "600" ]; then
        ACTION_RESULT="SUCCESS"
        CURRENT_STATUS="PASS"
        ACTION_LOG="성공: 세션 종료 시간을 600초로 설정 완료 및 검증 성공."
    else
        ACTION_LOG="실패: 설정 반영 후 검증 값이 일치하지 않습니다."
    fi
else
    ACTION_LOG="오류: 조치 대상 파일($TARGET_FILE)이 없습니다."
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