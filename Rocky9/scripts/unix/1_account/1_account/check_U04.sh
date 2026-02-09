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

STATUS="PASS"
EVIDENCE="N/A"

# 1. /etc/passwd 내 두 번째 필드가 'x'가 아닌 계정 추출
UNSHADOWED_USERS=$(awk -F: '$2 != "x" {print $1}' "$PASSWD_FILE" | xargs | sed 's/ /, /g')

if [ -f "$PASSWD_FILE" ] && [ -f "$SHADOW_FILE" ]; then
    if [ -z "$UNSHADOWED_USERS" ]; then
        STATUS="PASS"
        EVIDENCE="모든 계정이 쉐도우 패스워드(x)를 사용하여 암호화 보호 중입니다."
    else
        STATUS="FAIL"
        EVIDENCE="암호화되지 않은 계정이 존재합니다. ($UNSHADOWED_USERS)"
    fi
else
    STATUS="FAIL"
    EVIDENCE="필수 파일($PASSWD_FILE 또는 $SHADOW_FILE)이 누락되었습니다."
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
    "guide": "pwconv 명령어를 실행하여 쉐도우 패스워드 정책을 적용하세요.",
    "target_file": "$PASSWD_FILE, $SHADOW_FILE",
    "file_hash": "${FILE_HASH:-N/A}",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF