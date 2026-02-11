#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.2
# @Author: 권순형
# @Last Updated: 2026-02-10
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-21
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : /etc/(r)syslog.conf 파일 소유자 및 권한 설정
# @Description : /etc/(r)syslog.conf 파일 권한 적절성 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 1. 항목 정보 정의
ID="U-21"
CATEGORY="파일 및 디렉토리 관리"
TITLE="/etc/(r)syslog.conf 파일 소유자 및 권한 설정"
IMPORTANCE="상"
STATUS="PASS"
EVIDENCE=""
IMPACT_LEVEL="LOW" 
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없으나, 드물게 비-root 프로세스가 설정 파일을 직접 건드리던 레거시 환경에서는 권한 오류가 발생할 수 있습니다."
GUIDE="/etc/(r)syslog.conf 파일 소유자를 root로 변경하고 권한도 640 이하로 변경해주세요."
TARGET_FILE=""
FILE_HASH="N/A"
CHECK_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

# 2. 진단 로직
LOG_FILES=("/etc/syslog.conf" "/etc/rsyslog.conf")
EVIDENCE_LINES=""
for FILE in "${LOG_FILES[@]}"; do
    if [ -f "$FILE" ]; then
        TARGET_FILE="$TARGET_FILE $FILE"

        OWNER=$(stat -c %U "$FILE")
        PERM=$(stat -c %a "$FILE")

        if [[ "$OWNER" =~ ^(root|bin|sys)$ ]] && [ "$PERM" -le 640 ]; then
            EVIDENCE+=""
        else
            STATUS="FAIL"
            EVIDENCE_LINES+="$FILE (owner=$OWNER, perm=$PERM); "
        fi
    fi
done

if [ -z "$TARGET_FILE" ]; then
    STATUS="FAIL"
    EVIDENCE="syslog 설정 파일이 존재하지 않습니다."
    GUIDE="대상 점검 파일이 존재하지 않습니다."
fi

if [ "$STATUS" == "PASS" ]; then
    EVIDENCE="/etc/(r)syslog.conf 파일의 소유자 및 권한이 모두 적절하게 설정되어 있어 이 항목에 대한 보안 위협이 없습니다."
    GUIDE="KISA 보안 가이드라인을 준수하고 있습니다."
else
    EVIDENCE="다음 파일의 소유자 또는 권한이 부적절하게 설정되어 있어 재설정이 필요합니다. "
    EVIDENCE+=$EVIDENCE_LINES
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
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "guide": "$GUIDE",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$CHECK_DATE"
}
EOF