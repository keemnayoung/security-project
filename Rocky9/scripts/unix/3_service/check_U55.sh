#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-55
# @Category : 서비스 관리
# @Platform : LINUX
# @Importance : 상
# @Title : Anonymous FTP 비활성화
# @Description : ftp 계정의 로그인 쉘을 /bin/false 또는 /sbin/nologin 등으로 제한했는지 점검
# @Criteria_Good : ftp 계정이 없거나 로그인 쉘이 /bin/false 또는 /sbin/nologin 으로 설정된 경우
# @Criteria_Bad : ftp 계정의 로그인 쉘이 /bin/sh, /bin/bash 등 로그인이 가능한 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-55 Anonymous FTP 비활성화 (ftp 계정 쉘 제한)

# 1. 항목 정보 정의
ID="U-55"
CATEGORY="서비스관리"
TITLE="Anonymous FTP 비활성화"
IMPORTANCE="상"
TARGET_FILE="/etc/passwd"

# 2. 진단 로직 (무결성 해시 포함)
STATUS="PASS"
EVIDENCE=""
FILE_HASH="NOT_FOUND"

VULNERABLE=0

# ftp 계정 존재 여부 및 쉘 확인
if grep -q "^ftp:" "/etc/passwd"; then
    TARGET_FILE="/etc/passwd"
    FILE_HASH=$(sha256sum "$TARGET_FILE" 2>/dev/null | awk '{print $1}')
    
    # 7번째 필드(로그인 쉘) 추출
    SHELL=$(grep "^ftp:" "/etc/passwd" | awk -F: '{print $7}')
    
    # 로그인 불가 쉘 목록
    if [[ "$SHELL" == "/bin/false" || "$SHELL" == "/sbin/nologin" || "$SHELL" == "/usr/sbin/nologin" ]]; then
        STATUS="PASS"
        EVIDENCE="ftp 계정의 로그인 쉘이 제한됨($SHELL)"
    else
        STATUS="FAIL"
        EVIDENCE="ftp 계정의 로그인 쉘이 제한되지 않음($SHELL)"
    fi
else
    STATUS="PASS"
    EVIDENCE="ftp 계정이 존재하지 않음"
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
    "guide": "FTP 전용 계정의 쉘을 /sbin/nologin 또는 /bin/false로 설정: usermod -s /sbin/nologin ftp",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
