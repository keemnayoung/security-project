#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-67
# @Category    : 로그 관리
# @Platform    : Rocky Linux
# @Importance  : 중
# @Title       : 로그 디렉터리 소유자 및 권한 설정
# @Description : 디렉터리 내 로그 파일의 소유자가 root이고, 권한이 644 이하로 설정
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 0. 기본 변수 정의
ID="U-67"
CATEGORY="로그 관리"
TITLE="로그 디렉터리 소유자 및 권한 설정"
IMPORTANCE="중"
TARGET_DIR="/var/log"

STATUS="FAIL"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
EVIDENCE="N/A"

ACTION_DATE=$(date +"%Y-%m-%d %H:%M:%S")
CHECK_DATE="$ACTION_DATE"

VULN_FOUND=0
FIXED_COUNT=0


# 1. 실제 조치 프로세스
if [ -d "$TARGET_DIR" ]; then
    while IFS= read -r file; do
        OWNER=$(stat -c %U "$file" 2>/dev/null)
        PERM=$(stat -c %a "$file" 2>/dev/null)

        # 취약 조건
        if [ "$OWNER" != "root" ] || [ "$PERM" -gt 644 ]; then
            VULN_FOUND=1

            chown root "$file" 2>/dev/null
            chmod 644 "$file" 2>/dev/null

            NEW_OWNER=$(stat -c %U "$file" 2>/dev/null)
            NEW_PERM=$(stat -c %a "$file" 2>/dev/null)

            if [ "$NEW_OWNER" = "root" ] && [ "$NEW_PERM" -le 644 ]; then
                FIXED_COUNT=$((FIXED_COUNT+1))
                ACTION_LOG+="조치 완료: $file (owner=$NEW_OWNER, perm=$NEW_PERM) | "
            else
                ACTION_LOG+="조치 실패: $file (owner=$NEW_OWNER, perm=$NEW_PERM) | "
            fi
        fi
    done < <(find "$TARGET_DIR" -type f 2>/dev/null)

    # 2. 조치 결과 판정
    if [ "$VULN_FOUND" -eq 0 ]; then
        STATUS="PASS"
        ACTION_RESULT="SUCCESS"
        ACTION_LOG="조치 대상 로그 파일 없음"
        EVIDENCE="모든 로그 파일의 소유자가 root이며 권한이 644 이하임"
    else
        if [ "$FIXED_COUNT" -gt 0 ]; then
            STATUS="PASS"
            ACTION_RESULT="SUCCESS"
            EVIDENCE="취약 로그 파일 조치 완료 (총 ${FIXED_COUNT}개 파일)"
        else
            STATUS="FAIL"
            ACTION_RESULT="PARTIAL_SUCCESS"
            EVIDENCE="취약 로그 파일이 존재하나 일부 또는 전체 조치 실패"
        fi
    fi
else
    STATUS="FAIL"
    ACTION_RESULT="ERROR"
    ACTION_LOG="/var/log 디렉터리가 존재하지 않음"
    EVIDENCE="조치 대상 디렉터리 없음"
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
    "guide": "KISA 가이드라인에 따른 로그 접근 통제 설정이 완료되었습니다.",
    "action_result": "$ACTION_RESULT",
    "action_log": "$ACTION_LOG",
    "action_date": "$ACTION_DATE",
    "check_date": "$CHECK_DATE"
}
EOF