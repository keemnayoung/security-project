#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-07
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-63
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : sudo 명령어 접근 관리
# @Description : /etc/sudoers 파일 권한 적절성 여부 점검
# @Criteria_Good :  /etc/sudoers 파일 소유자가 root이고, 파일 권한이 640인 경우
# @Criteria_Bad : /etc/sudoers 파일 소유자가 root가 아니거나, 파일 권한이 640을 초과하는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-63 sudo 명령어 접근 관리

# 1. 항목 정보 정의
ID="U-63"
CATEGORY="서비스 관리"
TITLE="sudo 명령어 접근 관리"
IMPORTANCE="중"
TARGET_FILE="/etc/sudoers"

# 2. 진단 로직 (무결성 해시 포함)
STATUS="PASS"
EVIDENCE=""
FILE_HASH="NOT_FOUND"

VULNERABLE=0

if [ -f "$TARGET_FILE" ]; then
    FILE_HASH=$(sha256sum "$TARGET_FILE" 2>/dev/null | awk '{print $1}')
    
    # 소유자 확인
    OWNER=$(stat -c '%U' "$TARGET_FILE" 2>/dev/null)
    # 권한 확인
    PERMS=$(stat -c '%a' "$TARGET_FILE" 2>/dev/null)
    
    EVIDENCE="소유자: $OWNER, 권한: $PERMS"
    
    # 가이드: 소유자 root, 권한 640
    if [ "$OWNER" != "root" ]; then
        VULNERABLE=1
        EVIDENCE="$EVIDENCE - 소유자가 root가 아닙니다."
    fi
    
    if [ "$PERMS" -gt 640 ]; then
        VULNERABLE=1
        EVIDENCE="$EVIDENCE - 권한이 640을 초과합니다."
    fi
    
    if [ $VULNERABLE -eq 1 ]; then
        STATUS="FAIL"
        EVIDENCE="/etc/sudoers 파일의 설정이 미흡하여, 비인가 사용자가 sudo 권한을 조작할 수 있는 위험이 있습니다. $EVIDENCE"
    else
        STATUS="PASS"
        EVIDENCE="/etc/sudoers 파일이 적절하게 설정되어 있습니다. $EVIDENCE"
    fi
else
    STATUS="PASS"
    EVIDENCE="sudo가 설치되어 있지 않습니다 (/etc/sudoers 파일 없음)."
fi


IMPACT_LEVEL="LOW"
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없으나, /etc/sudoers 파일의 소유자·권한을 root/640으로 변경하는 과정에서 기존에 특정 사용자 또는 운영 절차가 해당 파일을 직접 수정·관리하던 환경이라면 권한 정책이 달라질 수 있으므로 적용 전 운영 방식(수정 주체/관리 절차)을 확인한 뒤 설정을 반영해야 합니다."

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
    "guide": "chown root:root /etc/sudoers && chmod 640 /etc/sudoers 명령으로 소유자 및 권한을 설정해야 합니다.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
