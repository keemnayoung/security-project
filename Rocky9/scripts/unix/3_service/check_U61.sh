#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-07
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-61
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : SNMP Access Control 설정
# @Description : SNMP 접근 제어 설정 여부 점검
# @Criteria_Good : SNMP 서비스에 접근 제어 설정이 되어 있는 경우
# @Criteria_Bad : SNMP 서비스에 접근 제어 설정이 되어 있지 않은 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-61 SNMP Access Control 설정

# 1. 항목 정보 정의
ID="U-61"
CATEGORY="서비스 관리"
TITLE="SNMP Access Control 설정"
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
    CONF="/etc/snmp/snmpd.conf"
    
    if [ -f "$CONF" ]; then
        FILE_HASH=$(sha256sum "$CONF" 2>/dev/null | awk '{print $1}')
        
        # [Redhat 계열] com2sec 설정에서 네트워크 주소 확인
        # 가이드: com2sec notConfigUser <허용할 네트워크 주소> <String값>
        # default는 모든 호스트 허용 -> 취약
        COM2SEC=$(grep -v "^#" "$CONF" | grep "com2sec")
        
        if [ -n "$COM2SEC" ]; then
            if echo "$COM2SEC" | grep -qE "\sdefault\s"; then
                VULNERABLE=1
                EVIDENCE="com2sec 설정에 default(모든 호스트) 허용: $COM2SEC"
            else
                EVIDENCE="com2sec 설정에 특정 네트워크가 제한되어 있습니다."
            fi
        fi
        
        # rocommunity/rwcommunity 호환성 확인
        ROCOMMUNITY=$(grep -v "^#" "$CONF" | grep -E "^rocommunity|^rwcommunity")
        
        if [ -n "$ROCOMMUNITY" ]; then
            # 네트워크 주소 없이 Community만 있으면 모든 호스트 허용
            # rocommunity <string> 만 있으면 취약, rocommunity <string> <network> 있으면 양호
            while IFS= read -r line; do
                # 필드 수 확인 (2개면 취약, 3개 이상이면 양호)
                FIELDS=$(echo "$line" | awk '{print NF}')
                if [ "$FIELDS" -le 2 ]; then
                    VULNERABLE=1
                    EVIDENCE="$EVIDENCE rocommunity/rwcommunity에 네트워크 제한 없음: $line"
                fi
            done <<< "$ROCOMMUNITY"
        fi
        
        if [ -z "$COM2SEC" ] && [ -z "$ROCOMMUNITY" ]; then
            EVIDENCE="SNMP 접근 설정을 찾을 수 없습니다 (확인 필요)."
        fi
    else
        STATUS="PASS"
        EVIDENCE="$CONF 파일이 존재하지 않습니다."
    fi
    
    if [ $VULNERABLE -eq 1 ]; then
        STATUS="FAIL"
        EVIDENCE="SNMP 접근 제어가 미흡하여, 모든 호스트에서 시스템 정보에 접근할 수 있는 위험이 있습니다. $EVIDENCE"
    fi
fi


IMPACT_LEVEL="LOW"
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없으나, SNMP 접근 제어가 강화되면서 기존에 허용되지 않았던 관리 구간(호스트/IP)에서 접근이 차단될 수 있으므로 운영에 필요한 허용 대상을 사전에 식별하고 정책에 맞게 접근 제어를 반영해야 합니다"

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
    "guide": "snmpd.conf에서 agentAddress를 특정 IP로 제한하고, com2sec에서 default 대신 특정 네트워크 대역으로 설정해야 합니다.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
