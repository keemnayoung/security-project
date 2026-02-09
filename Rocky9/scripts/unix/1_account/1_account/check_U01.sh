# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 김나영
# @Last Updated: 2026-02-09
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-01
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : root 계정 원격 접속 제한
# @Description : 원격 터미널 서비스를 통한 root 계정의 직접 접속 제한 여부 점검
# @Criteria_Good : 원격 접속 시 root 계정 접속을 제한한 경우
# @Criteria_Bad : 원격 접속 시 root 계정 접속을 허용한 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 1. 항목 정보 정의
ID="U-01"
CATEGORY="계정관리"
TITLE="root 계정 원격 접속 제한"
IMPORTANCE="상"
TARGET_FILE="/etc/ssh/sshd_config"

# 2. 진단 로직 (무결성 해시 포함)
STATUS="FAIL"
EVIDENCE="N/A"

if [ -f "$TARGET_FILE" ]; then
    # sshd 설정값 확인
   VAL=$(sshd -T 2>/dev/null | grep -i "permitrootlogin" | awk '{print $2}')
    # 원본 파일 해시 추출
    FILE_HASH=$(sha256sum "$TARGET_FILE" | awk '{print $1}')

    if [[ "$VAL" == "no" ]]; then
        STATUS="PASS"
        EVIDENCE="PermitRootLogin 설정이 'no'로 되어 있습니다."
    else
        STATUS="FAIL"
        EVIDENCE="현재 설정값: $VAL (취약 - 원격 root 접속 허용)"
    fi
else
    STATUS="PASS"
    EVIDENCE="SSH 서비스가 존재하지 않음"
    FILE_HASH="NOT_FOUND"
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
    "guide": "sshd_config 파일에서 PermitRootLogin을 no로 설정하여 root 원격 접속을 차단하세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF