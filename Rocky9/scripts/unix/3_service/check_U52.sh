#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-52
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : Telnet 서비스 비활성화
# @Description : 원격 접속 시 Telnet 프로토콜 사용 여부 점검
# @Criteria_Good : 원격 접속 시 Telnet 프로토콜을 비활성화하고 있는 경우
# @Criteria_Bad : 원격 접속 시 Telnet 프로토콜을 사용하는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-52 Telnet 서비스 비활성화

# 1. 항목 정보 정의
ID="U-52"
CATEGORY="서비스 관리"
TITLE="Telnet 서비스 비활성화"
IMPORTANCE="중"
TARGET_FILE="/etc/inetd.conf"

# 2. 진단 로직 (무결성 해시 포함)
STATUS="PASS"
EVIDENCE=""
FILE_HASH="NOT_FOUND"

VULNERABLE=0

# [Step 1] inetd.conf 내 Telnet 활성화 여부 확인
if [ -f "/etc/inetd.conf" ]; then
    TARGET_FILE="/etc/inetd.conf"
    FILE_HASH=$(sha256sum "$TARGET_FILE" 2>/dev/null | awk '{print $1}')
    if grep -v "^#" "$TARGET_FILE" 2>/dev/null | grep -qE "^[[:space:]]*telnet"; then
        VULNERABLE=1
        EVIDENCE="$EVIDENCE /etc/inetd.conf에 Telnet이 활성화되어 있습니다."
    fi
fi

# [Step 2] xinetd.d/telnet 활성화 여부 확인
if [ -f "/etc/xinetd.d/telnet" ]; then
    if grep -qiE "disable\s*=\s*no" "/etc/xinetd.d/telnet" 2>/dev/null; then
        VULNERABLE=1
        EVIDENCE="$EVIDENCE /etc/xinetd.d/telnet에서 disable=no로 설정되어 있습니다."
    fi
fi

# [Step 3] systemd Telnet 소켓/서비스 활성화 여부 확인
# 가이드: systemctl list-units --type=socket | grep telnet
if systemctl list-units --type=socket 2>/dev/null | grep -q "telnet"; then
    VULNERABLE=1
    EVIDENCE="$EVIDENCE systemd Telnet 소켓이 활성화되어 있습니다."
fi
if systemctl list-units --type=service 2>/dev/null | grep -q telnet; then
    VULNERABLE=1
    EVIDENCE="$EVIDENCE systemd Telnet 서비스가 활성화되어 있습니다."
fi

# [Step 4] SSH 서비스 실행 여부 확인 (점검 보조)
# 가이드: systemctl list-units --type=service | grep sshd
if ! systemctl list-units --type=service 2>/dev/null | grep -q sshd; then
    # SSH가 안 켜져 있으면 경고성 메시지 추가
    EVIDENCE="$EVIDENCE SSH 서비스가 실행 중이지 않습니다(확인 필요)."
fi

# 결과 판단
if [ $VULNERABLE -eq 1 ]; then
    STATUS="FAIL"
    EVIDENCE="Telnet 서비스가 활성화되어 있어, 통신 내용이 평문으로 노출될 수 있는 위험이 있습니다. $EVIDENCE"
else
    STATUS="PASS"
    EVIDENCE="Telnet 서비스가 비활성화되어 있습니다."
    if [[ "$EVIDENCE" == *"SSH 서비스 미실행"* ]]; then
        STATUS="PASS" # Telnet 꺼진게 중요하므로 PASS 처리하되 Evidence에는 남김
    fi
fi


IMPACT_LEVEL="LOW"
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없으나, Telnet 기반으로 원격 접속을 수행하던 운영 절차가 있었다면 더 이상 사용이 불가능해지므로 SSH 기반 접속으로 전환한 뒤 적용해야 합니다."

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
    "guide": "Telnet 대신 SSH를 사용하고, systemctl stop telnet.socket && systemctl disable telnet.socket으로 비활성화해야 합니다.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
