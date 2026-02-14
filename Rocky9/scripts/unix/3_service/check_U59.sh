#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-59
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상 
# @Title : 안전한 SNMP 버전 사용
# @Description : 안전한 SNMP 버전 사용 여부 점검
# @Criteria_Good : SNMP 서비스를 v3 이상으로 사용하는 경우
# @Criteria_Bad : SNMP 서비스를 v2 이하로 사용하는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-59 안전한 SNMP 버전 사용

# 1. 항목 정보 정의
ID="U-59"
CATEGORY="서비스 관리"
TITLE="안전한 SNMP 버전 사용"
IMPORTANCE="상"
TARGET_FILE="/etc/snmp/snmpd.conf"

# 2. 진단 로직 (무결성 해시 포함)
STATUS="PASS"
EVIDENCE=""
FILE_HASH="NOT_FOUND"

VULNERABLE=0

# SNMP 서비스 활성화 여부 확인
# 가이드: systemctl list-units --type=service | grep snmpd
if ! systemctl list-units --type=service 2>/dev/null | grep -q snmpd && ! pgrep -x snmpd >/dev/null; then
    STATUS="PASS"
    EVIDENCE="SNMP 서비스가 비활성화되어 있습니다."
else
    # 활성화 상태면 설정 파일 점검
    CONF_FILES=("/etc/snmp/snmpd.conf" "/usr/share/snmp/snmpd.conf")
    FOUND=0
    
    for conf in "${CONF_FILES[@]}"; do
        if [ -f "$conf" ]; then
            FOUND=1
            TARGET_FILE="$conf"
            FILE_HASH=$(sha256sum "$TARGET_FILE" 2>/dev/null | awk '{print $1}')
            
            # v3 사용자 설정 확인 (rouser, rwuser, createUser)
            V3_USER_CHECK=$(grep -E "^(rouser|rwuser|createUser)" "$conf" 2>/dev/null)

            if [ -n "$V3_USER_CHECK" ]; then
                EVIDENCE="$EVIDENCE $conf: SNMPv3 사용자 설정이 확인되어 안전한 SNMP 버전(SNMPv3)을 사용하고 있습니다."
            else
                VULNERABLE=1
                EVIDENCE="$EVIDENCE $conf: SNMPv3 사용자 설정이 없어 SNMPv1/v2c 사용이 추정됩니다."
            fi
        fi
    done
    
    if [ $FOUND -eq 0 ]; then
        STATUS="PASS"
        EVIDENCE="SNMP 서비스가 실행 중이나 설정 파일을 찾을 수 없습니다."
    elif [ $VULNERABLE -eq 1 ]; then
        STATUS="FAIL"
        EVIDENCE="SNMP 서비스 보안 설정이 미흡하여, 시스템 정보가 노출될 수 있는 위험이 있습니다. $EVIDENCE"
    fi
fi

# JSON 출력 전 특수문자 제거
EVIDENCE=$(echo "$EVIDENCE" | tr '\n\r\t' '   ' | sed 's/"/\\"/g')


IMPACT_LEVEL="LOW"
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없으나, 기존에 SNMP v1/v2c 기반으로 연동된 장비·모니터링 시스템이 있다면 서비스가 비활성화 되므로, 적용 전 연동 대상을 확인한 뒤 안전한 버전으로 전환해야 합니다"

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
    "guide": "SNMPv3를 사용해야 하며, SNMPv1/v2c는 비활성화해야 합니다.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
