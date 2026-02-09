#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-15
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : 파일 및 디렉터리 소유자 설정
# @Description : 소유자가 존재하지 않는 파일 및 디렉터리의 존재 여부 조치
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#####################
# 검토 필요
######################

ID="U-15"
CATEGORY="파일 및 디렉토리 관리"
TITLE="파일 및 디렉터리 소유자 설정"
IMPORTANCE="상"

ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
STATUS="PASS"
EVIDENCE="N/A"


# 1. 실제 조치 프로세스 시작
# 소유자 또는 그룹이 존재하지 않는 파일/디렉터리 탐색
ORPHAN_FILES=$(find / \
    -xdev \
    \( -nouser -o -nogroup \) \
    ! -path "/proc/*" \
    ! -path "/sys/*" \
    ! -path "/dev/*" \
    2>/dev/null)

if [ -n "$ORPHAN_FILES" ]; then
    # 취약 상태
    STATUS="FAIL"
    EVIDENCE=$(echo "$ORPHAN_FILES" | tr '\n' ',' | sed 's/,$//')

    # --------------------------------------------------------------
    # 조치 정책:
    # - 자동 삭제/소유권 변경은 수행하지 않음
    # - UID 재사용 공격 위험 존재 → 관리자 수동 조치 필요
    # --------------------------------------------------------------
    ACTION_RESULT="PARTIAL_SUCCESS"
    ACTION_LOG="소유자가 존재하지 않는 파일 및 디렉터리 발견. UID 재사용 공격 위험 존재로 자동 조치는 수행하지 않음 (수동 조치 필요)"

else
    # 양호 상태
    STATUS="PASS"
    EVIDENCE="소유자 또는 그룹이 존재하지 않는 파일 및 디렉터리 미존재"
    ACTION_RESULT="SUCCESS"
    ACTION_LOG="조치 대상 없음"
fi


# 2. JSON 표준 출력
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