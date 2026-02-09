  #!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-41
# @Category : 서비스 관리
# @Platform : LINUX
# @Importance : 상
# @Title : 불필요한 automountd 제거
# @Description : automount 또는 autofs 서비스가 비활성화되어 있는지 점검
# @Criteria_Good : automount/autofs 서비스가 비활성화된 경우
# @Criteria_Bad : 서비스가 활성화된 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-41 불필요한 automountd 제거

# 1. 항목 정보 정의
ID="U-41"
CATEGORY="서비스관리"
TITLE="불필요한 automountd 제거"
IMPORTANCE="상"
TARGET_FILE="N/A"

# 2. 진단 로직 (KISA 가이드 기준)
STATUS="PASS"
EVIDENCE=""
FILE_HASH="NOT_FOUND"

VULNERABLE=0

# [Step 1] automount 또는 autofs 서비스 활성화 여부 확인
# 가이드: systemctl list-units --type=service | grep -E "automount|autofs"
AUTOFS_SERVICES=$(systemctl list-units --type=service 2>/dev/null | grep -E "automount|autofs" | awk '{print $1}' | tr '\n' ' ')
if [ -n "$AUTOFS_SERVICES" ]; then
    VULNERABLE=1
    EVIDENCE="automount/autofs 서비스 활성화: $AUTOFS_SERVICES"
fi

# 결과 판단
if [ $VULNERABLE -eq 1 ]; then
    STATUS="FAIL"
    EVIDENCE="불필요한 automountd 서비스 활성화: $EVIDENCE"
else
    STATUS="PASS"
    EVIDENCE="automount/autofs 서비스가 비활성화되어 있음"
fi

# JSON 출력 전 특수문자 제거
EVIDENCE=$(echo "$EVIDENCE" | tr '\n\r\t' '   ' | sed 's/"/\\"/g')

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
    "guide": "automount 서비스가 불필요한 경우 systemctl stop autofs && systemctl disable autofs로 비활성화하세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
