#!/bin/bash
# [점검] U-12 세션 종료 시간 설정

ID="U-12"
CATEGORY="계정관리"
TITLE="세션 종료 시간 설정"
IMPORTANCE="하"
TARGET_FILE="/etc/profile"

STATUS="FAIL"
EVIDENCE="N/A"

if [ -f "$TARGET_FILE" ]; then
    # 1. 파일 무결성 해시 추출
    FILE_HASH=$(sha256sum "$TARGET_FILE" | awk '{print $1}')
    
    # 2. [검증 강화] TMOUT 설정값 추출 (주석 제외 및 숫자만 정밀 추출)
    TMOUT_VAL=$(grep -i "TMOUT=" "$TARGET_FILE" | grep -v "^#" | cut -d= -f2 | sed 's/[^0-9]//g' | head -1)

    # 3. 결과 판별: 가이드 기준(600초 이하) 준수 여부 확인
    if [[ "$TMOUT_VAL" =~ ^[0-9]+$ ]] && [ "$TMOUT_VAL" -le 600 ] && [ "$TMOUT_VAL" -gt 0 ]; then
        STATUS="PASS"
        EVIDENCE="양호: 세션 종료 시간이 ${TMOUT_VAL}초로 적절히 설정되어 있습니다."
    else
        STATUS="FAIL"
        if [ -z "$TMOUT_VAL" ]; then
            EVIDENCE="취약: TMOUT 설정이 존재하지 않거나 비활성화되어 있습니다."
        else
            EVIDENCE="취약: 현재 설정값(${TMOUT_VAL}초)이 가이드 기준(600초 이하)을 초과합니다."
        fi
    fi
else
    STATUS="FAIL"
    EVIDENCE="취약: 설정 파일($TARGET_FILE) 누락"
    FILE_HASH="NOT_FOUND"
fi

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
    "file_hash": "$FILE_HASH",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF