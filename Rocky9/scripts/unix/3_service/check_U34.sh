#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-34
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : Finger 서비스 비활성화
# @Description : Finger 서비스 비활성화 여부 점검
# @Criteria_Good : Finger 서비스가 비활성화된 경우
# @Criteria_Bad : Finger 서비스가 활성화된 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-34 Finger 서비스 비활성화

# 1. 항목 정보 정의
ID="U-34"
CATEGORY="서비스 관리"
TITLE="Finger 서비스 비활성화"
IMPORTANCE="상"
TARGET_FILE="N/A"

# 2. 진단 로직 (KISA 가이드 기준)
STATUS="PASS"
EVIDENCE=""
FILE_HASH="NOT_FOUND"

FINGER_ACTIVE=0

# [LINUX - inetd] /etc/inetd.conf 파일 내 Finger 서비스 활성화 여부 확인
# 가이드: Finger 서비스 항목이 주석 처리되지 않은 경우 취약
if [ -f "/etc/inetd.conf" ]; then
    TARGET_FILE="/etc/inetd.conf"
    FILE_HASH=$(sha256sum "$TARGET_FILE" 2>/dev/null | awk '{print $1}')
    # 선행 공백 후 주석(#)도 제외
    if grep -Ev "^[[:space:]]*#" "$TARGET_FILE" 2>/dev/null | grep -qE "^[[:space:]]*finger([[:space:]]|$)"; then
        FINGER_ACTIVE=1
        EVIDENCE="$EVIDENCE /etc/inetd.conf에 Finger 서비스가 활성화되어 있습니다."
    fi
fi

# [LINUX - xinetd] /etc/xinetd.d/finger 파일 내 disable 옵션 확인
# 가이드: finger의 disable 옵션이 no인 경우 취약
if [ -f "/etc/xinetd.d/finger" ]; then
    TARGET_FILE="/etc/xinetd.d/finger"
    FILE_HASH=$(sha256sum "$TARGET_FILE" 2>/dev/null | awk '{print $1}')
    # 주석 라인 제외 + disable=no 인 경우 취약
    if grep -Ev "^[[:space:]]*#" "$TARGET_FILE" 2>/dev/null | grep -qiE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no([[:space:]]|$)"; then
        FINGER_ACTIVE=1
        EVIDENCE="$EVIDENCE /etc/xinetd.d/finger 설정에서 disable = no로 설정되어 있습니다."
    fi
fi

# 결과 판단
if [ $FINGER_ACTIVE -eq 1 ]; then
    STATUS="FAIL"
    EVIDENCE="Finger 서비스가 활성화되어 있어, 외부에서 시스템 사용자 정보를 조회할 수 있는 위험이 있습니다. $EVIDENCE"
else
    STATUS="PASS"
    EVIDENCE="Finger 서비스가 비활성화되어 있습니다."
fi

IMPACT_LEVEL="LOW" 
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없으나, finger 서비스를 운영·진단 목적 등으로 실제 사용 중인 경우 해당 기능이 더 이상 제공되지 않으므로 적용 전 사용 여부를 반드시 확인하고 필요 시 대체 절차를 마련해야 합니다."

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
    "guide": "xinetd에서 finger 서비스를 disable=yes로 설정하거나, inetd.conf에서 finger 라인을 주석처리 후 서비스를 재시작해야 합니다.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
