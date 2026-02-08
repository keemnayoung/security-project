#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-36
# @Category : 서비스 관리
# @Platform : LINUX
# @Importance : 상
# @Title : r 계열 서비스 비활성화
# @Description : rsh, rlogin, rexec 등 r 계열 서비스가 비활성화되어 있는지 점검
# @Criteria_Good : 불필요한 r 계열 서비스가 비활성화된 경우
# @Criteria_Bad : 불필요한 r 계열 서비스가 활성화된 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-36 r 계열 서비스 비활성화

# 1. 항목 정보 정의
ID="U-36"
CATEGORY="서비스관리"
TITLE="r 계열 서비스 비활성화"
IMPORTANCE="상"
TARGET_FILE="N/A"

# 2. 진단 로직 (KISA 가이드 기준)
STATUS="PASS"
EVIDENCE=""
FILE_HASH="NOT_FOUND"

VULNERABLE=0
R_SERVICES=("rsh" "rlogin" "rexec" "shell" "login" "exec")

# [inetd] /etc/inetd.conf 파일 내 불필요한 r 계열 서비스 활성화 여부 확인
# 가이드: 주석 처리되지 않은 r 계열 서비스 확인
if [ -f "/etc/inetd.conf" ]; then
    TARGET_FILE="/etc/inetd.conf"
    FILE_HASH=$(sha256sum "$TARGET_FILE" 2>/dev/null | awk '{print $1}')
    for svc in "${R_SERVICES[@]}"; do
        if grep -v "^#" "$TARGET_FILE" 2>/dev/null | grep -qE "^[[:space:]]*$svc"; then
            VULNERABLE=1
            EVIDENCE="$EVIDENCE /etc/inetd.conf에 $svc 활성화;"
        fi
    done
fi

# [xinetd] /etc/xinetd.d/<파일> 내 불필요한 r 계열 서비스 활성화 여부 확인
# 가이드: disable = no인 경우 취약
for svc in "${R_SERVICES[@]}"; do
    if [ -f "/etc/xinetd.d/$svc" ]; then
        TARGET_FILE="/etc/xinetd.d/$svc"
        if grep -qiE "disable\s*=\s*no" "$TARGET_FILE" 2>/dev/null; then
            VULNERABLE=1
            EVIDENCE="$EVIDENCE /etc/xinetd.d/$svc에서 disable=no;"
        fi
    fi
done

# [systemd] 불필요한 r 계열 서비스 활성화 여부 확인
# 가이드: # systemctl list-units --type=service | grep -E "rlogin|rsh|rexec"
SYSTEMD_SERVICES=$(systemctl list-units --type=service 2>/dev/null | grep -E "rlogin|rsh|rexec" | awk '{print $1}')
if [ -n "$SYSTEMD_SERVICES" ]; then
    VULNERABLE=1
    EVIDENCE="$EVIDENCE systemd r계열 서비스 활성화: $SYSTEMD_SERVICES;"
fi

# 결과 판단
if [ $VULNERABLE -eq 1 ]; then
    STATUS="FAIL"
    EVIDENCE="r 계열 서비스 활성화:$EVIDENCE"
else
    STATUS="PASS"
    EVIDENCE="r 계열 서비스가 비활성화되어 있음"
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
    "guide": "xinetd에서 rsh, rlogin, rexec 서비스를 disable=yes로 설정하고, /etc/hosts.equiv 및 .rhosts 파일을 삭제하세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
