#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-38
# @Category : 서비스 관리
# @Platform : LINUX
# @Importance : 상
# @Title : DoS 공격에 취약한 서비스 비활성화
# @Description : 사용하지 않는 DoS 공격에 취약한 서비스의 실행 여부 점검
# @Criteria_Good : echo, discard, daytime, chargen 서비스가 비활성화된 경우
# @Criteria_Bad : 해당 서비스가 활성화된 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-38 DoS 공격에 취약한 서비스 비활성화

# 1. 항목 정보 정의
ID="U-38"
CATEGORY="서비스관리"
TITLE="DoS 공격에 취약한 서비스 비활성화"
IMPORTANCE="상"
TARGET_FILE="N/A"

# 2. 진단 로직 (KISA 가이드 기준)
STATUS="PASS"
EVIDENCE=""
FILE_HASH="NOT_FOUND"

VULNERABLE=0

# DoS 취약 서비스 목록
# 가이드: echo, discard, daytime, chargen
DOS_SERVICES=("echo" "discard" "daytime" "chargen")

# [inetd] /etc/inetd.conf 파일 내 서비스 활성화 여부 확인
# 가이드: 주석 처리되지 않은 서비스 확인
if [ -f "/etc/inetd.conf" ]; then
    TARGET_FILE="/etc/inetd.conf"
    FILE_HASH=$(sha256sum "$TARGET_FILE" 2>/dev/null | awk '{print $1}')
    for svc in "${DOS_SERVICES[@]}"; do
        if grep -v "^#" "$TARGET_FILE" 2>/dev/null | grep -qE "^[[:space:]]*$svc"; then
            VULNERABLE=1
            EVIDENCE="$EVIDENCE /etc/inetd.conf에 $svc 활성화;"
        fi
    done
fi

# [xinetd] /etc/xinetd.d/<파일명> 파일 내 서비스 활성화 여부 확인
# 가이드: disable = no인 경우 취약
if [ -d "/etc/xinetd.d" ]; then
    for svc in "${DOS_SERVICES[@]}"; do
        if [ -f "/etc/xinetd.d/$svc" ]; then
            if grep -qiE "disable\s*=\s*no" "/etc/xinetd.d/$svc" 2>/dev/null; then
                VULNERABLE=1
                EVIDENCE="$EVIDENCE /etc/xinetd.d/$svc에서 disable=no;"
            fi
        fi
    done
fi

# [systemd] 서비스 활성화 여부 확인
# 가이드: systemctl list-units --type=service | grep -E "echo|discard|daytime|chargen"
SYSTEMD_SERVICES=$(systemctl list-units --type=service 2>/dev/null | grep -E "echo|discard|daytime|chargen" | awk '{print $1}')
if [ -n "$SYSTEMD_SERVICES" ]; then
    VULNERABLE=1
    EVIDENCE="$EVIDENCE systemd 서비스 활성화: $SYSTEMD_SERVICES;"
fi

# 결과 판단
if [ $VULNERABLE -eq 1 ]; then
    STATUS="FAIL"
    EVIDENCE="DoS 취약 서비스 활성화:$EVIDENCE"
else
    STATUS="PASS"
    EVIDENCE="DoS 공격에 취약한 서비스(echo,discard,daytime,chargen)가 비활성화됨"
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
    "guide": "xinetd에서 echo, discard, daytime, chargen 서비스를 disable=yes로 설정하고 xinetd를 재시작하세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
