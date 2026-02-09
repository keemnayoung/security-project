#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-44
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : tftp, talk 서비스 비활성화
# @Description : tftp, talk, ntalk 서비스의 활성화 여부 점검
# @Criteria_Good : tftp, talk, ntalk 서비스가 비활성화된 경우
# @Criteria_Bad : tftp, talk, ntalk 서비스가 활성화된 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-44 tftp, talk 서비스 비활성화

# 1. 항목 정보 정의
ID="U-44"
CATEGORY="서비스 관리"
TITLE="tftp, talk 서비스 비활성화"
IMPORTANCE="상"
TARGET_FILE="N/A"

# 2. 진단 로직 (KISA 가이드 기준)
STATUS="PASS"
EVIDENCE=""
FILE_HASH="NOT_FOUND"

VULNERABLE=0
SERVICES=("tftp" "talk" "ntalk")

# [inetd] /etc/inetd.conf 파일 내 tftp, talk, ntalk 서비스 활성화 여부 확인
# 가이드: cat /etc/inetd.conf
if [ -f "/etc/inetd.conf" ]; then
    TARGET_FILE="/etc/inetd.conf"
    FILE_HASH=$(sha256sum "$TARGET_FILE" 2>/dev/null | awk '{print $1}')
    for svc in "${SERVICES[@]}"; do
        if grep -v "^#" "$TARGET_FILE" 2>/dev/null | grep -qE "^[[:space:]]*$svc"; then
            VULNERABLE=1
            EVIDENCE="$EVIDENCE /etc/inetd.conf에 $svc 활성화;"
        fi
    done
fi

# [xinetd] /etc/xinetd.d/ 디렉터리 내 존재하는 tftp, talk, ntalk 파일에 대해 서비스 활성화 여부 확인
# 가이드: disable = no 확인
if [ -d "/etc/xinetd.d" ]; then
    for svc in "${SERVICES[@]}"; do
        if [ -f "/etc/xinetd.d/$svc" ]; then
            if grep -qiE "disable\s*=\s*no" "/etc/xinetd.d/$svc" 2>/dev/null; then
                VULNERABLE=1
                EVIDENCE="$EVIDENCE /etc/xinetd.d/$svc에서 disable=no;"
            fi
        fi
    done
fi

# [systemd] 서비스 활성화 여부 확인
# 가이드: systemctl list-units --type=service | grep -E "tftp|talk|ntalk"
# 가이드에 따라 서비스명 정규식으로 확인
SYSTEMD_SERVICES=$(systemctl list-units --type=service 2>/dev/null | grep -E "tftp|talk|ntalk" | awk '{print $1}' | tr '\n' ' ')
if [ -n "$SYSTEMD_SERVICES" ]; then
    VULNERABLE=1
    EVIDENCE="$EVIDENCE systemd 서비스 활성화: $SYSTEMD_SERVICES;"
fi

# 결과 판단
if [ $VULNERABLE -eq 1 ]; then
    STATUS="FAIL"
    EVIDENCE="tftp, talk 서비스 활성화:$EVIDENCE"
else
    STATUS="PASS"
    EVIDENCE="tftp, talk, ntalk 서비스가 비활성화되어 있음"
fi

# JSON 출력 전 특수문자 제거
EVIDENCE=$(echo "$EVIDENCE" | tr '\n\r\t' '   ' | sed 's/"/\\"/g')


IMPACT_LEVEL="LOW"
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없으나, 환경에 따라 tftp가 초기 데이터 호출 등 특정 절차에 사용되는 경우가 있을 수 있으므로 실제 사용 여부를 확인한 뒤 불필요한 경우에 한해 비활성화해야 합니다."

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
    "guide": "xinetd에서 tftp, talk 서비스를 disable=yes로 설정하거나 systemctl stop tftp.socket talk으로 비활성화하세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
