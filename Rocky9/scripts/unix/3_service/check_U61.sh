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
# @Platform : Rocky Linux 9
# @Importance : 중
# @Title : SNMP 접근 제어 설정
# @Description : SNMP 접근이 특정 네트워크 주소로 제한되어 있는지 점검
# @Criteria_Good : SNMP 접근이 허용된 네트워크 주소로만 제한된 경우
# @Criteria_Bad : SNMP 접근이 모든 호스트(default)에 허용된 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-61 SNMP 접근 제어 설정

# 1. 항목 정보 정의
ID="U-61"
CATEGORY="서비스관리"
TITLE="SNMP 접근 제어 설정"
IMPORTANCE="중"
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
    EVIDENCE="SNMP 서비스가 비활성화되어 있음"
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
                EVIDENCE="com2sec 설정에 특정 네트워크 제한됨"
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
            EVIDENCE="SNMP 접근 설정을 찾을 수 없음 (확인 필요)"
        fi
    else
        STATUS="PASS"
        EVIDENCE="$CONF 파일이 존재하지 않음"
    fi
    
    if [ $VULNERABLE -eq 1 ]; then
        STATUS="FAIL"
        EVIDENCE="SNMP 접근 제어 미흡: $EVIDENCE"
    fi
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
    "guide": "snmpd.conf에서 agentAddress를 특정 IP로 제한하고, com2sec에서 default 대신 특정 네트워크 대역으로 설정하세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
