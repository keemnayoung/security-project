#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 김나영
# @Last Updated: 2026-02-09
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-07
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 하
# @Title : 불필요한 계정 제거
# @Description : 시스템에 기본적으로 생성되어 있으나 사용하지 않는 계정(lp, uucp 등)의 존재 여부 점검
# @Criteria_Good : 불필요한 계정이 삭제되거나 잠금 설정된 경우
# @Criteria_Bad : 불필요한 계정이 활성화되어 있는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 1. 항목 정보 정의
ID="U-07"
CATEGORY="계정관리"
TITLE="불필요한 계정 제거"
IMPORTANCE="하"
TARGET_FILE="/etc/passwd"

# KISA 가이드 및 현업 표준 불필요 계정 목록
DEFAULT_UNUSED_ACCOUNTS=("lp" "uucp" "nuucp")
FOUND_ACCOUNTS=()

# 2. 진단 로직
STATUS="FAIL"
EVIDENCE="N/A"

if [ -f "$TARGET_FILE" ]; then
    # 불필요 계정 존재 여부 전수 조사
    for acc in "${DEFAULT_UNUSED_ACCOUNTS[@]}"; do
        if grep -q "^${acc}:" "$TARGET_FILE"; then
            FOUND_ACCOUNTS+=("$acc")
        fi
    done

    # 결과 판별
    if [ ${#FOUND_ACCOUNTS[@]} -gt 0 ]; then
        STATUS="FAIL"
        # [핵심] 조치 버튼을 숨기기 위해 PARTIAL_SUCCESS 설정
        ACTION_RESULT="PARTIAL_SUCCESS"
        EVIDENCE="시스템에 불필요한 기본 계정(${FOUND_ACCOUNTS[*]})이 식별되었습니다. 자동 삭제 시 관련 서비스 장애 위험이 있어 수동 조치가 권장됩니다."
        GUIDE="1. 식별된 계정(${FOUND_ACCOUNTS[*]})이 현재 시스템에서 특정 서비스를 구동 중인지 확인하세요. 2. 사용하지 않는 것이 확실하다면 'userdel <계정명>' 명령으로 삭제하십시오. 3. 삭제가 불안하다면 쉘을 /sbin/nologin으로 변경하여 로그인을 차단하는 방법도 있습니다."
    else
        STATUS="PASS"
        ACTION_RESULT="SUCCESS"
        EVIDENCE="시스템 운영에 불필요한 기본 계정이 존재하지 않아 보안 가이드라인을 준수하고 있습니다."
        GUIDE="KISA 보안 가이드라인을 준수하고 있습니다."
    fi
else
    STATUS="FAIL"
    ACTION_RESULT="PARTIAL_SUCCESS"
    EVIDENCE="사용자 정보 설정 파일($TARGET_FILE)이 식별되지 않아 정확한 계정 점검이 불가능합니다."
    GUIDE="시스템 환경에 맞는 계정 설정 파일 존재 여부를 수동으로 점검하십시오."
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