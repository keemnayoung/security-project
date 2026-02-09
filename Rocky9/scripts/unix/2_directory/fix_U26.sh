#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 권순형
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-26
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Debian
# @Importance  : 상
# @Title       : /dev에 존재하지 않는 device 파일 점검
# @Description : /dev 디렉터리에 대한 파일 점검 후 존재하지 않는 device 파일을 제거
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#####################
# 검토 필요
#####################

# 1. 기본 변수 정의 (고정 템플릿)
ID="U-26"
TARGET_FILE="/dev"
ACTION_DATE=$(date +"%Y-%m-%d %H:%M:%S")

ACTION_RESULT="PASS"
ACTION_LOG="조치할 불필요한 device 파일이 발견되지 않음"
BEFORE_SETTING="불필요하거나 존재하지 않는 device 파일 없음"
AFTER_SETTING="불필요하거나 존재하지 않는 device 파일 없음"

# 2. 조치 로직
# /dev 내 일반 파일(-type f) 탐색
INVALID_FILES=$(find /dev -type f 2>/dev/null)

if [ -n "$INVALID_FILES" ]; then
    # 쉼표 구분 문자열 생성
    INVALID_FILES_CSV=$(echo "$INVALID_FILES" | paste -sd ", " -)

    BEFORE_SETTING="존재하는 불필요한 device 파일: $INVALID_FILES_CSV"

    # 파일 삭제 수행
    rm -f $INVALID_FILES 2>/dev/null

    # 삭제 후 재확인
    REMAIN_FILES=$(find /dev -type f 2>/dev/null)

    if [ -z "$REMAIN_FILES" ]; then
        ACTION_RESULT="SUCCESS"
        ACTION_LOG="불필요하거나 존재하지 않는 device 파일 삭제 완료"
        AFTER_SETTING="불필요한 device 파일 제거 완료"
    else
        REMAIN_FILES_CSV=$(echo "$REMAIN_FILES" | paste -sd ", " -)
        ACTION_RESULT="FAIL"
        ACTION_LOG="일부 device 파일 삭제 실패"
        AFTER_SETTING="잔존 파일: $REMAIN_FILES_CSV"
    fi
fi


# 3. 조치 결과 JSON 출력
echo ""

cat <<EOF
{
  "check_id": "$ID",
  "action_result": "$ACTION_RESULT",
  "before_setting": "$BEFORE_SETTING",
  "after_setting": "$AFTER_SETTING",
  "action_log": "$ACTION_LOG",
  "action_date": "$ACTION_DATE"
}
EOF