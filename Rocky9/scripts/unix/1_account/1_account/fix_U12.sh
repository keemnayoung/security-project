#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 김나영
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID : U-12
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 하
# @Title : 세션 종료 시간 설정
# @Description : 사용자 세션 방치로 인한 보안 사고 예방을 위해 TMOUT 설정 조치
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-12"
CATEGORY="계정관리"
TITLE="세션 종료 시간 설정"
IMPORTANCE="하"
TARGET_FILE="/etc/profile"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
ACTION_RESULT="FAIL"
STATUS="FAIL"
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
        STATUS="PASS"
        ACTION_LOG="조치 완료. 세션 종료 시간을 600초로 설정 완료 및 검증 성공."
    else
        ACTION_LOG="조치 실패. 설정 반영 후 검증 값이 일치하지 않습니다."
    fi
else
    ACTION_LOG="오류: 조치 대상 파일($TARGET_FILE)이 없습니다."
fi

# 4. 표준 JSON 출력
echo ""
cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "KISA 가이드라인에 따른 보안 설정이 완료되었습니다.",
    "action_result": "$ACTION_RESULT",
    "action_log": "$ACTION_LOG",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF