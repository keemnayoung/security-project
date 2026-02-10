#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 김나영
# @Last Updated: 2026-02-09
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-04
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 비밀번호 파일 보호
# @Description : /etc/passwd 파일의 패스워드 암호화 및 /etc/shadow 파일 사용 여부 점검
# @Criteria_Good : 상용 시스템에서 쉐도우 패스워드 정책을 사용하는 경우
# @Criteria_Bad : 쉐도우 패스워드 정책을 사용하지 않고 패스워드가 노출되는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-04"
CATEGORY="계정관리"
TITLE="비밀번호 파일 보호"
IMPORTANCE="상"
PASSWD_FILE="/etc/passwd"
SHADOW_FILE="/etc/shadow"
IMPACT_LEVEL="LOW"
ACTION_IMPACT="리눅스 환경에서 pwconv 명령을 통한 쉐도우 패스워드 전환은 시스템 운영에 직접적인 영향이 거의 없습니다. 다만, HP-UX 시스템의 경우 Trusted Mode 전환 시 파일 시스템 구조 변경으로 인한 서비스 장애 위험이 있으므로 해당 OS 환경에서는 반드시 충분한 사전 테스트가 필요합니다."

STATUS="PASS"
EVIDENCE="N/A"

# 1. /etc/passwd 내 두 번째 필드가 'x'가 아닌 계정 추출
UNSHADOWED_USERS=$(awk -F: '$2 != "x" {print $1}' "$PASSWD_FILE" | xargs | sed 's/ /, /g')

if [ -f "$PASSWD_FILE" ] && [ -f "$SHADOW_FILE" ]; then
    if [ -z "$UNSHADOWED_USERS" ]; then
        STATUS="PASS"
        EVIDENCE="모든 계정의 패스워드가 쉐도우 정책에 따라 암호화되어 안전하게 보호되고 있음을 확인하였습니다."
    else
        STATUS="FAIL"
        EVIDENCE="패스워드 보호 정책(x)이 적용되지 않은 일부 계정($UNSHADOWED_USERS)이 식별되어 시스템 보안을 위한 조치가 필요합니다."
    fi
else
    STATUS="FAIL"
    EVIDENCE="비밀번호 암호화 정책을 관리하는 필수 설정 파일이 누락되어 정확한 점검이 불가능하므로, 시스템 파일 복구 조치가 필요합니다."
fi

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
    "guide": "pwconv 명령어를 실행하여 쉐도우 패스워드 정책을 적용하세요.",
    "target_file": "$PASSWD_FILE, $SHADOW_FILE",
    "file_hash": "${FILE_HASH:-N/A}",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF