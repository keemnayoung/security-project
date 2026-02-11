#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.2
# @Author: 권순형
# @Last Updated: 2026-02-10
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-17
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : 시스템 시작 스크립트 권한 설정
# @Description : 시스템 시작 스크립트 파일 권한 적절성 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================


# 1. 항목 정보 정의
ID="U-17"
CATEGORY="파일 및 디렉토리 관리"
TITLE="시스템 시작 스크립트 권한 설정"
IMPORTANCE="상"
STATUS="PASS"
EVIDENCE=""
GUIDE="해당 항목은 자동 조치 시 시스템 장애 위험이 커서 자동 조치 기능을 제공하지 않습니다. 관리자가 직접 시스템 시작 스크립트 파일(/etc/rc.d/*/*와 /etc/systemd/system/*)의 소유자를 root 또는 적절한 계정 사용자로 변경하고 권한도 o-w로 변경하십시오."
ACTION_RESULT="N/A"
IMPACT_LEVEL="LOW" 
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없으나, 기존에 넓은 권한이나 기본 설정에 의존하던 서비스, 스크립트, 사용자 계정은 권한 부족·접근 거부·동작 오류가 발생할 수 있어 사전 점검과 테스트가 필요합니다."
TARGET_FILE="N/A"
FILE_HASH="N/A"
CHECK_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

# 2. 진단 로직
TARGET_FILES=()
EVIDENCE_LINES=""
# init 방식
if [ -d /etc/rc.d ]; then
    INIT_FILES=$(readlink -f /etc/rc.d/*/* 2>/dev/null | sed 's/$/*/')
fi

# systemd 방식
if [ -d /etc/systemd/system ]; then
    SYSTEMD_FILES=$(readlink -f /etc/systemd/system/* 2>/dev/null | sed 's/$/*/')
fi

ALL_FILES=$(echo -e "$INIT_FILES\n$SYSTEMD_FILES" | sort -u)

if [ -z "$ALL_FILES" ]; then
    STATUS="PASS"
    ACTION_RESULT="SUCCESS"
    EVIDENCE="점검 대상 시스템 시작 스크립트 파일이 존재하지 않아 해당 보안 위협이 없습니다."

else
    for FILE in $ALL_FILES; do
        [ -e "$FILE" ] || continue

        OWNER=$(stat -c %U "$FILE")
        PERM=$(stat -c %A "$FILE")
        OTHERS_WRITE=$(echo "$PERM" | cut -c9)

        TARGET_FILES+=("$FILE")

        if [ "$OWNER" != "root" ] || [ "$OTHERS_WRITE" = "w" ]; then
            STATUS="FAIL"
            ACTION_RESULT="PARTIAL_SUCCESS"
            EVIDENCE_LINES+="$FILE (owner=$OWNER, perm=$PERM)\n"
        fi
    done
fi

TARGET_FILE=$(printf "%s " "${TARGET_FILES[@]}")
if [ -z "$EVIDENCE" ]; then
    STATUS="PASS"
    ACTION_RESULT="SUCCESS"
    EVIDENCE="시스템 시작 스크립트 파일의 소유자와 권한이 모두 적절하게 설정되어 있어 해당 보안 위협이 없습니다."
    GUIDE="KISA 보안 가이드라인을 준수하고 있습니다."
else
    EVIDENCE=$(printf "%s\\n" "${EVIDENCE_LINES[@]}" | sed 's/"/\\"/g')
fi


# 3. 마스터 템플릿 표준 출력
echo ""
cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "$GUIDE",
    "action_result": "$ACTION_RESULT",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$CHECK_DATE"
}
EOF