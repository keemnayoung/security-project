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
# @Platform : Rocky Linux 9
# @Importance : 중
# @Title : /etc/sudoers 파일 소유자 및 권한 설정
# @Description : /etc/sudoers 파일의 소유자가 root이고 권한이 640 이하인지 점검
# @Criteria_Good : 소유자가 root이고 권한이 640 이하인 경우
# @Criteria_Bad : 소유자가 root가 아니거나 권한이 640 초과인 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-63 /etc/sudoers 파일 소유자 및 권한 설정

# 1. 항목 정보 정의
ID="U-63"
CATEGORY="서비스관리"
TITLE="/etc/sudoers 파일 소유자 및 권한 설정"
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
        EVIDENCE="$EVIDENCE - 소유자가 root가 아님"
    fi
    
    if [ "$PERMS" -gt 640 ]; then
        VULNERABLE=1
        EVIDENCE="$EVIDENCE - 권한이 640 초과"
    fi
    
    if [ $VULNERABLE -eq 1 ]; then
        STATUS="FAIL"
        EVIDENCE="/etc/sudoers 파일 설정 미흡: $EVIDENCE"
    else
        STATUS="PASS"
        EVIDENCE="/etc/sudoers 파일 설정 양호: $EVIDENCE"
    fi
else
    STATUS="PASS"
    EVIDENCE="sudo 미사용 (/etc/sudoers 파일 없음 - 양호)"
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
    "guide": "chown root:root /etc/sudoers && chmod 440 /etc/sudoers 명령으로 소유자 및 권한을 설정하세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
