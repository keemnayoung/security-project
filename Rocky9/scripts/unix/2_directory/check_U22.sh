#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-22
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : /etc/services 파일 소유자 및 권한 설정
# @Description : /etc/services 파일 권한 적절성 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 1. 항목 정보 정의
CHECK_ID="U-22"
CATEGORY="파일 및 디렉토리 관리"
TITLE="/etc/services 파일 소유자 및 권한 설정"
IMPORTANCE="상"
TARGET_FILE="/etc/services"
IMPACT_LEVEL="LOW" 
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없으나, 잘못된 설정 시 일부 네트워크 서비스가 포트 정보를 참조하지 못해 서비스 연동에 영향을 줄 수 있습니다."
CHECK_DATE=$(date +"%Y-%m-%d %H:%M:%S")

STATUS="PASS"
EVIDENCE=""


# 2. 진단 로직

if [ ! -f "$TARGET_FILE" ]; then
    STATUS="FAIL"
    EVIDENCE="/etc/services 파일이 존재하지 않음"
else
    FILE_OWNER=$(stat -c %U "$TARGET_FILE")
    FILE_PERM=$(stat -c %a "$TARGET_FILE")

    # 소유자 확인 (root, bin, sys)
    if [[ "$FILE_OWNER" != "root" && "$FILE_OWNER" != "bin" && "$FILE_OWNER" != "sys" ]]; then
        STATUS="FAIL"
        EVIDENCE="소유자 부적절 (현재 소유자: $FILE_OWNER)"
    fi

    # 권한 확인 (644 이하)
    if [ "$FILE_PERM" -gt 644 ]; then
        STATUS="FAIL"
        if [ -n "$EVIDENCE" ]; then
            EVIDENCE="$EVIDENCE / 권한 부적절 (현재 권한: $FILE_PERM)"
        else
            EVIDENCE="권한 부적절 (현재 권한: $FILE_PERM)"
        fi
    fi

    if [ "$STATUS" = "PASS" ]; then
        EVIDENCE="소유자($FILE_OWNER) 및 권한($FILE_PERM) 설정 양호"
    fi
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
    "evidence": "$EVIDENCE",
    "guide": "/etc/services 파일 소유자를 root로 변경하고 권한도 644로 변경해주세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$( [ -f "$TARGET_FILE" ] && sha256sum "$TARGET_FILE" | awk '{print $1}' || echo "N/A" )",
    "action_impact": "$ACTION_IMPACT",
    "impact_level": "$IMPACT_LEVEL",  
    "check_date": "$CHECK_DATE"
}
EOF