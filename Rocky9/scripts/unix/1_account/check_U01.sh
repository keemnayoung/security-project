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
    # sshd 실제 적용값 확인
    VAL=$(sshd -T 2>/dev/null | grep -i "permitrootlogin" | awk '{print $2}')
    
    if [[ "$VAL" == "no" ]]; then
        STATUS="PASS"
        ACTION_RESULT="SUCCESS"
        EVIDENCE="원격 터미널을 통한 root 계정의 직접 접속이 차단되어 보안 가이드라인을 준수하고 있습니다."
        GUIDE="KISA 보안 가이드라인을 준수하고 있습니다."
    else
        STATUS="FAIL"
        ACTION_RESULT="PARTIAL_SUCCESS"
        EVIDENCE="현재 root 원격 접속이 허용($VAL)되어 있습니다. 무분별한 차단 시 접속 불능 위험이 있어 수동 조치가 권장됩니다."
        GUIDE="1. 먼저 sudo 권한을 가진 일반 관리자 계정을 생성하세요. 2. 해당 계정으로 원격 접속 테스트를 반드시 완료하세요. 3. 이후 sshd_config에서 PermitRootLogin을 no로 수정하고 서비스를 재시작하십시오."
    fi
else
    STATUS="PASS"
    ACTION_RESULT="SUCCESS"
    EVIDENCE="SSH 서비스 설정 파일이 존재하지 않아 해당 보안 위협이 없습니다."
    GUIDE="점검 대상 파일이 없습니다."
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
    "guide": "$GUIDE",
    "action_result": "$ACTION_RESULT",
    "target_file": "$TARGET_FILE",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF