#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.2
# @Author: 권순형
# @Last Updated: 2026-02-10
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-20
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : /etc/(x)inetd.conf 파일 소유자 및 권한 설정
# @Description : /etc/(x)inetd.conf 파일 권한 적절성 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 1. 항목 정보 정의
ID="U-20"
CATEGORY="파일 및 디렉토리 관리"
TITLE="/etc/(x)inetd.conf 파일 소유자 및 권한 설정"
IMPORTANCE="상"
STATUS="PASS"
EVIDENCE=""
IMPACT_LEVEL="LOW" 
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없으나, 일반 사용자나 일부 관리 도구가 systemd 설정을 직접 수정·읽지 못해 운영·자동화 작업에 영향이 있을 수 있습니다."
GUIDE="/etc/(x)inetd.conf 파일 또는 /etc/systemd 디렉터리 내 파일들의 소유자를 root로 변경하고 권한도 600 이하로 변경하십시오."
TARGET_FILE="/etc/inetd.conf /etc/xinetd.conf /etc/systemd/*"
FILE_HASH="N/A"
CHECK_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

# 2. 진단 로직
EVIDENCE_LINES=()

check_file() {
    local FILE="$1"

    if [ ! -e "$FILE" ]; then
        EVIDENCE+="[INFO] $FILE 파일이 존재하지 않음\n"
        return
    fi

    OWNER=$(stat -c %U "$FILE" 2>/dev/null)
    PERM=$(stat -c %a "$FILE" 2>/dev/null)

    if [ "$OWNER" != "root" ] || [ "$PERM" -gt 600 ]; then
        STATUS="FAIL"
        EVIDENCE_LINES+=("$FILE (owner=$OWNER, perm=$PERM)")
    fi
}

check_directory_files() {
    local DIR="$1"

    while IFS= read -r FILE; do
        OWNER=$(stat -c %U "$FILE" 2>/dev/null)
        PERM=$(stat -c %a "$FILE" 2>/dev/null)

        if [ "$OWNER" != "root" ] || [ "$PERM" -gt 600 ]; then
            STATUS="FAIL"
            EVIDENCE_LINES+=("$FILE (owner=$OWNER, perm=$PERM)")
        fi
    done < <(find "$DIR" -type f 2>/dev/null)
}

# inetd / xinetd 설정 파일 점검
check_file "/etc/inetd.conf"
check_file "/etc/xinetd.conf"

# systemd 설정 파일 및 디렉터리 점검
check_directory_files "/etc/systemd"

if [ "$STATUS" == "PASS" ]; then
    EVIDENCE="/etc/(x)inetd 또는 /etc/systemd 디렉터리 내 파일 소유자 및 권한이 모두 적절하게 설정되어 있어 이 항목에 대한 보안 위협이 없습니다."
    GUIDE="KISA 보안 가이드라인을 준수하고 있습니다."
else
    EVIDENCE="다음 파일들의 소유자 또는 권한이 부적절하게 설정되어 있어 재설정이 필요합니다."
    EVIDENCE+=$(printf "[")
    EVIDENCE+=$(printf "%s; " "${EVIDENCE_LINES[@]}")
    EVIDENCE+=$(printf "]")
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