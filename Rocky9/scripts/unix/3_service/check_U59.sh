#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-59
# @Category : 서비스 관리
# @Platform : LINUX
# @Importance : 중
# @Title : SNMP 서비스 보안 설정 (SNMPv3 사용)
# @Description : SNMP 서비스 사용 시 SNMPv3를 사용하여 보안을 강화했는지 점검
# @Criteria_Good : SNMPv3를 사용하거나, SNMP 서비스를 사용하지 않는 경우
# @Criteria_Bad : SNMPv1/v2c를 사용하며 Community String이 취약(public/private)한 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-59 SNMP 서비스 보안 설정 (SNMPv3 사용)

# 1. 항목 정보 정의
ID="U-59"
CATEGORY="서비스관리"
TITLE="SNMP 서비스 보안 설정 (SNMPv3 사용)"
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
    # 활성화 상태면 설정 파일 점검
    CONF_FILES=("/etc/snmp/snmpd.conf" "/usr/share/snmp/snmpd.conf")
    FOUND=0
    
    for conf in "${CONF_FILES[@]}"; do
        if [ -f "$conf" ]; then
            FOUND=1
            TARGET_FILE="$conf"
            FILE_HASH=$(sha256sum "$TARGET_FILE" 2>/dev/null | awk '{print $1}')
            
            # v3 사용자 설정 확인 (rouser, rwuser, createUser)
            V3_USER_CHECK=$(grep -E "^(rouser|rwuser|createUser)" "$conf")
            
            # v1/v2c Community String 확인 (rocommunity, rwcommunity)
            COMMUNITY_CHECK=$(grep -E "^(rocommunity|rwcommunity)" "$conf" | grep -v "^#")
            
            if [ -n "$V3_USER_CHECK" ]; then
                EVIDENCE="$EVIDENCE $conf: SNMPv3 사용자 설정 발견;"
                
                # v3가 있어도 v1/v2c가 열려있고 public/private이면 취약할 수 있음.
                # 그러나 가이드는 "SNMPv3 사용 여부"를 강조함.
                if [ -n "$COMMUNITY_CHECK" ]; then
                    if echo "$COMMUNITY_CHECK" | grep -qE "public|private"; then
                        VULNERABLE=1
                        EVIDENCE="$EVIDENCE SNMPv3 설정은 있으나, 취약한 Community String(public/private)이 활성화됨;"
                    fi
                else
                    STATUS="PASS"
                    EVIDENCE="$EVIDENCE SNMPv3 사용 중이며 Community String 설정 없음(안전);"
                fi
            else
                # V3 설정이 없음
                VULNERABLE=1
                EVIDENCE="$EVIDENCE $conf: SNMPv3 사용자 설정이 없음(v1/v2c 사용 추정);"
                
                if [ -n "$COMMUNITY_CHECK" ]; then
                     EVIDENCE="$EVIDENCE Community String 설정 존재($COMMUNITY_CHECK);"
                fi
            fi
        fi
    done
    
    if [ $FOUND -eq 0 ]; then
        STATUS="PASS"
        EVIDENCE="SNMP 서비스 실행 중이나 설정 파일을 찾을 수 없음"
    elif [ $VULNERABLE -eq 1 ]; then
        STATUS="FAIL"
        EVIDENCE="SNMP 서비스 보안 설정 미흡: $EVIDENCE"
    fi
fi

# JSON 출력 전 특수문자 제거
EVIDENCE=$(echo "$EVIDENCE" | tr '\n\r\t' '   ' | sed 's/"/\\"/g')

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
    "guide": "SNMPv3 사용을 권장, SNMPv1/v2c 사용 시 community string을 복잡하게 변경하세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
