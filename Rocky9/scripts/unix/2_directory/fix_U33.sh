#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-33
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 하
# @Title       : 숨겨진 파일 및 디렉토리 검색 및 제거
# @Description : 숨겨진 파일 및 디렉토리 내 의심스러운 파일 존재 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

######################
# 수동 점검
######################

# 1. 기본 변수 정의 (U-01 구조 반영)
ID="U-33"
CATEGORY="파일 및 디렉토리 관리"
TITLE="숨겨진 파일 및 디렉토리 검색 및 제거"
IMPORTANCE="하"
ACTION_DATE=$(date "+%Y-%m-%d %H:%M:%S")

ACTION_RESULT=""
ACTION_LOG=""
BEFORE_SETTING=""
AFTER_SETTING=""
STATUS="PASS"
EVIDENCE=""


# 2. 숨겨진 파일 / 디렉토리 검색
HIDDEN_FILES=$(find / -type f -name ".*" 2>/dev/null | head -n 50 | sed ':a;N;$!ba;s/\n/\\n/g')
HIDDEN_DIRS=$(find / -type d -name ".*" 2>/dev/null | head -n 50 | sed ':a;N;$!ba;s/\n/\\n/g')

BEFORE_SETTING="Hidden_files:\\n$HIDDEN_FILES\\n\\nHidden_directories:\\n$HIDDEN_DIRS"

if [[ -n "$HIDDEN_FILES" || -n "$HIDDEN_DIRS" ]]; then
    STATUS="FAIL"
    ACTION_RESULT="MANUAL_REQUIRED"
    ACTION_LOG="숨겨진 파일 또는 디렉토리가 존재합니다. 관리자 확인 후 rm / rm -r로 제거 필요."
    AFTER_SETTING="수동 조치 필요"
    EVIDENCE="숨겨진 파일 또는 디렉토리 발견:\\n$HIDDEN_FILES\\n$HIDDEN_DIRS"
else
    STATUS="PASS"
    ACTION_RESULT="NO_ACTION_REQUIRED"
    ACTION_LOG="숨겨진 파일 및 디렉토리 없음"
    AFTER_SETTING="양호"
    EVIDENCE="숨겨진 파일 또는 디렉토리 없음"
fi


# 3. JSON 결과 출력
echo ""
cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "before_setting": "$BEFORE_SETTING",
    "after_setting": "$AFTER_SETTING",
    "action_result": "$ACTION_RESULT",
    "action_log": "$ACTION_LOG",
    "action_date": "$ACTION_DATE",
    "check_date": "$ACTION_DATE"
}
EOF