#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 권순형
# @Last Updated: 2026-02-05
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-15
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Debian
# @Importance  : 상
# @Title       : 파일 및 디렉터리 소유자 설정
# @Description : 소유자가 존재하지 않는 파일 및 디렉터리의 존재 여부 조치
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#####################
# 검토 필요
######################

ID="U-15"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
BEFORE_SETTING="N/A"
AFTER_SETTING="N/A"

# 1. 조치 대상 탐색 (위험 경로 제외)
ORPHAN_FILES_RAW=$(find / \
    -xdev \
    \( -nouser -o -nogroup \) \
    ! -path "/proc/*" \
    ! -path "/sys/*" \
    ! -path "/dev/*" \
    2>/dev/null)

# 조치 전 상태 기록
if [ -n "$ORPHAN_FILES_RAW" ]; then
    BEFORE_SETTING=$(echo "$ORPHAN_FILES_RAW" | tr '\n' ',' | sed 's/,$//')
else
    BEFORE_SETTING="조치 대상 없음"
fi

# 2. 조치 수행 (소유권 복구)
FIXED_COUNT=0
FIXED_TARGETS=()

if [ -n "$ORPHAN_FILES_RAW" ]; then
    while IFS= read -r TARGET; do
        [ -z "$TARGET" ] && continue

        # root:root 로 소유권 복구
        chown root "$TARGET" 2>/dev/null
        chgrp root "$TARGET" 2>/dev/null

        if [ $? -eq 0 ]; then
            FIXED_COUNT=$((FIXED_COUNT + 1))
            FIXED_TARGETS+=("$TARGET")
        fi
    done <<< "$ORPHAN_FILES_RAW"
fi

# 3. 조치 후 재점검
REMAIN_FILES=$(find / \
    -xdev \
    \( -nouser -o -nogroup \) \
    ! -path "/proc/*" \
    ! -path "/sys/*" \
    ! -path "/dev/*" \
    2>/dev/null)

if [ -z "$REMAIN_FILES" ]; then
    AFTER_SETTING="소유자가 존재하지 않는 파일 및 디렉터리 미존재"
else
    AFTER_SETTING=$(echo "$REMAIN_FILES" | tr '\n' ',' | sed 's/,$//')
fi

# 4. 결과 판단
if [ "$FIXED_COUNT" -gt 0 ]; then
    ACTION_RESULT="SUCCESS"
    ACTION_LOG="소유권 복구 완료: ${FIXED_COUNT}개 (${FIXED_TARGETS[*]})"
else
    ACTION_RESULT="SUCCESS"
    ACTION_LOG="조치 대상 없음"
fi

# 5. JSON 출력
echo ""
cat << EOF
{
    "check_id": "$ID",
    "action_result": "$ACTION_RESULT",
    "before_setting": "$BEFORE_SETTING",
    "after_setting": "$AFTER_SETTING",
    "action_log": "$ACTION_LOG",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF