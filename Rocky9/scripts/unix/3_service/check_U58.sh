#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-58
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : 불필요한 SNMP 서비스 구동 점검
# @Description : SNMP 서비스 활성화 여부 점검
# @Criteria_Good : SNMP 서비스를 사용하지 않는 경우
# @Criteria_Bad :  SNMP 서비스를 사용하는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-58 불필요한 SNMP 서비스 구동 점검

# 1. 항목 정보 정의
ID="U-58"
CATEGORY="서비스 관리"
TITLE="불필요한 SNMP 서비스 구동 점검"
IMPORTANCE="중"
TARGET_FILE="/usr/sbin/snmpd"

# 2. 진단 로직 (무결성 해시 포함)
STATUS="PASS"
EVIDENCE=""
FILE_HASH="NOT_FOUND"

VULNERABLE=0

# 가이드: systemctl list-units --type=service | grep snmpd
# SNMP 서비스(snmpd) 활성화 여부 확인
# 업무상 사용하는지는 스크립트로 판단 불가하므로 활성화 시 기본적으론 FAIL(또는 MANUAL) 처리
# 여기서는 활성화 여부만 체크

if systemctl list-units --type=service 2>/dev/null | grep -q snmpd; then
    VULNERABLE=1
    EVIDENCE="SNMP 서비스(snmpd)가 활성화되어 있습니다."
    
    # 바이너리 해시 확인
    if command -v snmpd &>/dev/null; then
        TARGET_FILE=$(command -v snmpd)
        FILE_HASH=$(sha256sum "$TARGET_FILE" 2>/dev/null | awk '{print $1}')
    fi
else
    # 프로세스 확인 추가 (가이드엔 없으나 확실히 하기 위해)
    if pgrep -x "snmpd" >/dev/null; then
        VULNERABLE=1
        EVIDENCE="SNMP 프로세스(snmpd)가 실행 중입니다."
    else
        STATUS="PASS"
        EVIDENCE="SNMP 서비스가 비활성화되어 있습니다."
    fi
fi

if [ $VULNERABLE -eq 1 ]; then
    STATUS="FAIL"
    EVIDENCE="불필요한 SNMP 서비스가 활성화되어 있어, 시스템 정보가 노출될 수 있는 위험이 있습니다. $EVIDENCE"
fi


IMPACT_LEVEL="LOW"
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없으나, 운영·모니터링 목적 등으로 SNMP 서비스를 실제 사용 중인 환경이라면 서비스 중지/비활성화 시 모니터링 연동이 중단될 수 있으므로 적용 전 사용 여부와 대체 모니터링 경로를 확인한 뒤 조치를 반영해야 합니다."

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
    "guide": "SNMP 서비스가 불필요한 경우 systemctl stop snmpd && systemctl disable snmpd로 비활성화해야 합니다.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
