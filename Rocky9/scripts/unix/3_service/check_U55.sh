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
# @Platform : Rocky Linux
# @Importance : 중 
# @Title : FTP 계정 shell 제한
# @Description : FTP 기본 계정에 쉘 설정 여부 점검
# @Criteria_Good : FTP 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정
# @Criteria_Bad : FTP 서비스 사용 시 FTP 계정에 /bin/false 쉘 부여 설정
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-55 FTP 계정 shell 제한

# 1. 항목 정보 정의
ID="U-55"
CATEGORY="서비스 관리"
TITLE="FTP 계정 shell 제한"
IMPORTANCE="중"
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


IMPACT_LEVEL="LOW"
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없으나, FTP 계정에 로그인 쉘이 부여된 상태에서 작업하던 운영 방식이 있었다면 쉘 접근이 차단되므로 FTP 계정의 용도를 파일 전송으로 한정하고 관리자 계정 기반의 운영 절차로 전환해 적용해야 합니다."

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
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
