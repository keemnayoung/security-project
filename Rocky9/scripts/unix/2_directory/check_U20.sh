#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
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
CHECK_ID="U-20"
CATEGORY="파일 및 디렉토리 관리"
TITLE="/etc/(x)inetd.conf 파일 소유자 및 권한 설정"
IMPORTANCE="상"
STATUS="PASS"
EVIDENCE=""
TARGET_FILE="/etc/inetd.conf /etc/xinetd.conf /etc/systemd/system.conf /etc/systemd/*"
CHECK_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IMPACT_LEVEL="LOW" 
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없으나, 일반 사용자나 일부 관리 도구가 systemd 설정을 직접 수정·읽지 못해 운영·자동화 작업에 영향이 있을 수 있습니다."


# 2. 진단 로직
check_file() {
    local FILE="$1"

    if [ ! -e "$FILE" ]; then
        EVIDENCE+="[INFO] $FILE 파일이 존재하지 않음\n"
        return
    fi

    OWNER=$(stat -c %U "$FILE" 2>/dev/null)
    PERM=$(stat -c %a "$FILE" 2>/dev/null)

    EVIDENCE+="[CHECK] $FILE (OWNER=$OWNER, PERMISSION=$PERM)\n"

    if [ "$OWNER" != "root" ] || [ "$PERM" -gt 600 ]; then
        STATUS="FAIL"
    fi
}

check_directory_files() {
    local DIR="$1"

    if [ ! -d "$DIR" ]; then
        EVIDENCE+="[INFO] $DIR 디렉터리가 존재하지 않음\n"
        return
    fi

    while IFS= read -r FILE; do
        OWNER=$(stat -c %U "$FILE" 2>/dev/null)
        PERM=$(stat -c %a "$FILE" 2>/dev/null)

        EVIDENCE+="[CHECK] $FILE (OWNER=$OWNER, PERMISSION=$PERM)\n"

        if [ "$OWNER" != "root" ] || [ "$PERM" -gt 600 ]; then
            STATUS="FAIL"
        fi
    done < <(find "$DIR" -type f 2>/dev/null)
}

# inetd / xinetd 설정 파일 점검
check_file "/etc/inetd.conf"
check_file "/etc/xinetd.conf"

# systemd 설정 파일 및 디렉터리 점검
check_file "/etc/systemd/system.conf"
check_directory_files "/etc/systemd"


# 3. 마스터 JSON 출력
echo ""
cat <<EOF
{
    "check_id": "$CHECK_ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$(echo -e "$EVIDENCE" | sed ':a;N;$!ba;s/\n/, /g; s/, $//')",
    "guide": "/etc/(x)inetd.conf 파일 소유자를 root로 변경하고 권한도 600 이하로 변경해주세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "N/A",
    "action_impact": "$ACTION_IMPACT",
    "impact_level": "$IMPACT_LEVEL",  
    "check_date": "$CHECK_DATE"
}
EOF