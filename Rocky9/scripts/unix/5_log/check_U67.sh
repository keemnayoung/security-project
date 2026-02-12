#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-67
# @Category    : 로그 관리
# @Platform    : Rocky Linux
# @Importance  : 중
# @Title       : 로그 디렉터리 소유자 및 권한 설정
# @Description : 로그에 대한 접근 통제 및 관리 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 1. 항목 정보 정의
ID="U-67"
CATEGORY="로그 관리"
TITLE="로그 디렉터리 소유자 및 권한 설정"
IMPORTANCE="중"
STATUS="PASS"
EVIDENCE=""
GUIDE="해당 항목은 자동 조치 시 시스템 장애 위험이 커서 자동 조치 기능을 제공하지 않습니다. 관리자가 직접 다른 시스템들과의 의존성을 파악하고 /var/log/ 디렉터리 내 로그 파일의 소유자를 root로 변경하고 권한도 644로 변경해주세요."
ACTION_RESULT="PARTIAL_SUCCESS"
IMPACT_LEVEL="LOW" 
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없으나, 일부 애플리케이션이나 로그 수집 에이전트가 로그 기록·수집에 실패할 수 있다는 영향이 발생할 수 있습니다."
TARGET_FILE="/var/log"
FILE_HASH="N/A"
CHECK_DATE=$(date +"%Y-%m-%d %H:%M:%S")

VULN_FILES=()

# 2. 진단 로직
if [ -d "$TARGET_FILE" ]; then
    while IFS= read -r file; do
        OWNER=$(stat -c %U "$file" 2>/dev/null)
        PERM=$(stat -c %a "$file" 2>/dev/null)

        if [ "$OWNER" != "root" ] || [ "$PERM" -gt 644 ]; then
            STATUS="FAIL"
            VULN_FILES+=("$file (owner=$OWNER, perm=$PERM)")
        fi
    done < <(find "$TARGET_FILE" -type f 2>/dev/null)
else
    STATUS="FAIL"
    EVIDENCE="/var/log 디렉터리가 존재하지 않습니다. 로그가 기록될 디렉터리를 생성해주길 바랍니다."
fi

if [ "$STATUS" = "FAIL" ] && [ ${#VULN_FILES[@]} -gt 0 ]; then
    ACTION_RESULT="PARTIAL_SUCCESS"
    EVIDENCE="/var/log 디렉터리에 다음과 같은 소유자 또는 권한 재설정이 필요한 파일들이 존재합니다. 보안을 위해 수동으로 권한을 변경해주시길 바랍니다. "
    EVIDENCE+=$(printf "%s, " "${VULN_FILES[@]}")
else
    ACTION_RESULT="SUCCESS"
fi


# 3. 마스터 JSON 출력
echo ""

cat <<EOF
{
    "check_id": "$CHECK_ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$(echo "$EVIDENCE" | sed ':a;N;$!ba;s/\n/ | /g')",
    "guide": " /var/log/ 디렉터리 내 로그 파일의 소유자를 root로 변경하고 권한도 644로 변경해주세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "N/A",
    "action_impact": "$ACTION_IMPACT",
    "impact_level": "$IMPACT_LEVEL",  
    "check_date": "$CHECK_DATE"
}
EOF

# 3. 마스터 템플릿 표준 출력
echo ""
cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$(echo -e "$EVIDENCE" | sed ':a;N;$!ba;s/\n/\\n/g' | sed 's/"/\\"/g')",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "guide": "$GUIDE",
    "action_result": "$ACTION_RESULT",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$CHECK_DATE"
}
EOF