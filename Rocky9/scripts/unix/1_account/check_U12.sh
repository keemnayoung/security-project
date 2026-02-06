#!/bin/bash
# [진단] U-12 세션 종료 시간 설정

# 1. 항목 정보 정의
ID="U-12"
CATEGORY="계정관리"
TITLE="세션 종료 시간 설정"
IMPORTANCE="하"
TARGET_FILE="/etc/profile"

# 2. 진단 로직
STATUS="FAIL"
EVIDENCE="N/A"

if [ -f "$TARGET_FILE" ]; then
    # 파일 해시 추출 (무결성 검증용)
    FILE_HASH=$(sha256sum "$TARGET_FILE" | awk '{print $1}')
    
    # TMOUT 설정값 확인 (주석 제외)
    # 가이드 기준: 600초(10분) 이하
    TMOUT_VAL=$(grep -i "TMOUT" "$TARGET_FILE" | grep -v "^#" | cut -d= -f2 | xargs | tail -1)

    if [ ! -z "$TMOUT_VAL" ] && [ "$TMOUT_VAL" -le 600 ] && [ "$TMOUT_VAL" -gt 0 ]; then
        STATUS="PASS"
        EVIDENCE="양호: 세션 종료 시간이 ${TMOUT_VAL}초로 적절히 설정되어 있습니다."
    else
        STATUS="FAIL"
        if [ -z "$TMOUT_VAL" ]; then
            EVIDENCE="취약: TMOUT 설정이 존재하지 않습니다."
        else
            EVIDENCE="취약: 현재 설정값(${TMOUT_VAL}초)이 가이드 기준(600초 이하)을 초과합니다."
        fi
    fi
else
    STATUS="FAIL"
    EVIDENCE="오류: $TARGET_FILE 파일을 찾을 수 없습니다."
    FILE_HASH="NOT_FOUND"
fi

# 3. JSON 표준 출력
echo ""
cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "/etc/profile 파일에 TMOUT=600 및 export TMOUT를 설정하세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF