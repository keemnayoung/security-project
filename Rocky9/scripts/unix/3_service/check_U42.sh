#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-42
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 불필요한 RPC 서비스 비활성화
# @Description : 불필요한 RPC 서비스의 실행 여부 점검
# @Criteria_Good : 불필요한 RPC 서비스가 비활성화된 경우
# @Criteria_Bad : 불필요한 RPC 서비스가 활성화된 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-42 불필요한 RPC 서비스 비활성화

# 1. 항목 정보 정의
ID="U-42"
CATEGORY="서비스 관리"
TITLE="불필요한 RPC 서비스 비활성화"
IMPORTANCE="상"
TARGET_FILE="N/A"

# 2. 진단 로직 (KISA 가이드 기준)
STATUS="PASS"
EVIDENCE=""
FILE_HASH="NOT_FOUND"

VULNERABLE=0

# [inetd] /etc/inetd.conf 파일 내 불필요한 RPC 서비스 활성화 여부 확인
# 가이드: cat /etc/inetd.conf
if [ -f "/etc/inetd.conf" ]; then
    TARGET_FILE="/etc/inetd.conf"
    FILE_HASH=$(sha256sum "$TARGET_FILE" 2>/dev/null | awk '{print $1}')
    # rpc로 시작하는 서비스 확인
    if grep -v "^#" "$TARGET_FILE" 2>/dev/null | grep -qE "^[[:space:]]*rpc"; then
        VULNERABLE=1
        RPC_INETD=$(grep -v "^#" "$TARGET_FILE" 2>/dev/null | grep -E "^[[:space:]]*rpc" | awk '{print $1}' | tr '\n' ' ')
        EVIDENCE="$EVIDENCE /etc/inetd.conf에 RPC 서비스가 활성화되어 있습니다."
    fi
fi

# [xinetd] /etc/xinetd.d/ 디렉터리 내 존재하는 불필요한 RPC 서비스 활성화 여부 확인
# 가이드: cat /etc/xinetd.d/<파일명>
if [ -d "/etc/xinetd.d" ]; then
    for conf in /etc/xinetd.d/*; do
        if [ -f "$conf" ]; then
            # rpc 관련 파일이거나 service rpc 포함하는 경우
            if echo "$conf" | grep -qi "rpc" || grep -q "service.*rpc" "$conf" 2>/dev/null; then
                if grep -qiE "disable\s*=\s*no" "$conf" 2>/dev/null; then
                    VULNERABLE=1
                    EVIDENCE="$EVIDENCE $(basename $conf)에서 disable=no로 설정되어 있습니다."
                fi
            fi
        fi
    done
fi

# [systemd] 불필요한 RPC 서비스 활성화 여부 확인
# 가이드: systemctl list-units --type=service | grep rpc
RPC_SERVICES=$(systemctl list-units --type=service 2>/dev/null | grep rpc | awk '{print $1}' | tr '\n' ' ')
if [ -n "$RPC_SERVICES" ]; then
    VULNERABLE=1
    EVIDENCE="$EVIDENCE systemd RPC 서비스가 활성화되어 있습니다."
fi

# 결과 판단
if [ $VULNERABLE -eq 1 ]; then
    STATUS="FAIL"
    EVIDENCE="불필요한 RPC 서비스가 활성화되어 있어, 원격 호출을 통한 비인가 접근이 발생할 수 있는 위험이 있습니다. $EVIDENCE"
else
    STATUS="PASS"
    EVIDENCE="불필요한 RPC 서비스가 비활성화되어 있습니다."
fi

# JSON 출력 전 특수문자 제거
EVIDENCE=$(echo "$EVIDENCE" | tr '\n\r\t' '   ' | sed 's/"/\\"/g')

IMPACT_LEVEL="LOW"
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없으나, 비활성화 대상 RPC 서비스가 특정 운영 기능에 사용 중인 경우가 있을 수 있으므로 적용 전 사용 여부를 확인한 뒤 불필요 서비스에 한해 중지·비활성화해야 합니다."

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
    "guide": "RPC 서비스가 불필요한 경우 systemctl stop rpcbind && systemctl disable rpcbind로 비활성화해야 합니다.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
