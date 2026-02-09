#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.2
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-65
# @Category    : 로그 관리
# @Platform    : Rocky Linux
# @Importance  : 중
# @Title       : NTP 및 시각 동기화 설정
# @Description : NTP 및 시각 동기화 설정이 기준에 따라 적용
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-65"
CATEGORY="로그 관리"
TITLE="NTP 및 시각 동기화 설정"
IMPORTANCE="중"
TARGET_FILE="/var/log"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
STATUS="FAIL"
EVIDENCE=""

# 1. 로그 파일 점검 및 조치
if [ -d "$TARGET_FILE" ]; then

    # 취약 로그 파일 탐색 (root 소유 아님 or 권한 644 초과)
    VULN_FILES=$(find "$TARGET_FILE" -type f \( ! -user root -o -perm /133 \) 2>/dev/null)

    if [ -z "$VULN_FILES" ]; then
        ACTION_RESULT="NO_ACTION_REQUIRED"
        STATUS="PASS"
        ACTION_LOG="모든 로그 파일이 이미 적절한 소유자 및 권한을 유지하고 있습니다."
        EVIDENCE="취약 로그 파일 없음 (양호)"
    else
        # 조치 수행
        for file in $VULN_FILES; do
            chown root:root "$file" 2>/dev/null
            chmod 644 "$file" 2>/dev/null
        done

        # 재확인
        RECHECK=$(find "$TARGET_FILE" -type f \( ! -user root -o -perm /133 \) 2>/dev/null)

        if [ -z "$RECHECK" ]; then
            ACTION_RESULT="SUCCESS"
            STATUS="PASS"
            ACTION_LOG="취약 로그 파일의 소유자 및 권한을 root:root, 644로 조치 완료했습니다."
            EVIDENCE="조치된 파일:\n$VULN_FILES"
        else
            ACTION_RESULT="PARTIAL_SUCCESS"
            STATUS="FAIL"
            ACTION_LOG="일부 로그 파일 조치 실패. 수동 확인이 필요합니다."
            EVIDENCE="조치 실패 파일:\n$RECHECK"
        fi
    fi
else
    ACTION_RESULT="ERROR"
    STATUS="FAIL"
    ACTION_LOG="로그 디렉터리($TARGET_FILE)가 존재하지 않습니다."
    EVIDENCE="디렉터리 없음"
fi


# JSON 출력용 줄바꿈 이스케이프
EVIDENCE_ESCAPED=$(echo -e "$EVIDENCE" | sed ':a;N;$!ba;s/\n/\\n/g')


# 2. JSON 표준 출력
echo ""
cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE_ESCAPED",
    "guide": "KISA 가이드라인에 따른 로그 파일 접근 권한 설정을 수행했습니다.",
    "action_result": "$ACTION_RESULT",
    "action_log": "$ACTION_LOG",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF