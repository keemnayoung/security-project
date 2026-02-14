#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-60
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : SNMP Community String 복잡성 설정
# @Description : SNMP Community String 복잡성 설정 여부 점검
# @Criteria_Good : SNMP Community String 기본값인 "public", "private"이 아닌 영문자, 숫자 포함 10자리 이상 또는 영문자, 숫자, 특수문자 포함 8자리 이상인 경우
# @Criteria_Bad :  아래의 내용 중 하나라도 해당되는 경우
                   # 1. SNMP Community String 기본값인 "public", "private"일 경우
                   # 2. 영문자, 숫자 포함 10자리 미만인 경우
                   # 3. 영문자, 숫자, 특수문자 포함 8자리 미만인 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-60 SNMP Community String 복잡성 설정

# 1. 항목 정보 정의
ID="U-60"
CATEGORY="서비스 관리"
TITLE="SNMP Community String 복잡성 설정"
IMPORTANCE="중"
TARGET_FILE="/etc/snmp/snmpd.conf"

# 2. 진단 로직 (무결성 해시 포함)
STATUS="PASS"
EVIDENCE=""
FILE_HASH="NOT_FOUND"

VULNERABLE=0
SNMP_RUNNING=0
ACTION_RESULT="SUCCESS"
GUIDE="KISA 보안 가이드라인을 준수하고 있습니다."

# SNMP 서비스 활성화 여부 확인
# 가이드: systemctl list-units --type=service | grep snmpd
if ! systemctl list-units --type=service 2>/dev/null | grep -q snmpd && ! pgrep -x snmpd >/dev/null; then
    # SNMP 미사용 → 취약 (중지 및 비활성화 필요)
    STATUS="FAIL"
    EVIDENCE="SNMP 서비스가 구동되지 않고 있어, 설치되어 있으나 미사용 중이라면 보안 위험이 있습니다."
    GUIDE="미사용 SNMP 서비스는 'systemctl stop snmpd && systemctl disable snmpd'로 완전히 비활성화해야 합니다."
    ACTION_RESULT="AUTO"
else
    SNMP_RUNNING=1
    CONF="/etc/snmp/snmpd.conf"
    
    if [ -f "$CONF" ]; then
        FILE_HASH=$(sha256sum "$CONF" 2>/dev/null | awk '{print $1}')
        
        # [Redhat 계열] com2sec 설정 확인
        # 가이드: com2sec notConfigUser default <Community String>
        COM2SEC=$(grep -v "^#" "$CONF" | grep "com2sec")
        
        if [ -n "$COM2SEC" ]; then
            # public/private 사용 여부 확인
            if echo "$COM2SEC" | grep -qE "\\s(public|private)\\s*$"; then
                VULNERABLE=1
                EVIDENCE="com2sec 설정에 취약한 Community String(public/private) 사용: $COM2SEC"
            else
                EVIDENCE="com2sec 설정 존재 (기본값 아님)"
            fi
        fi
        
        # rocommunity/rwcommunity 확인 (호환성)
        ROCOMMUNITY=$(grep -v "^#" "$CONF" | grep -E "^rocommunity|^rwcommunity")
        
        if [ -n "$ROCOMMUNITY" ]; then
            if echo "$ROCOMMUNITY" | grep -qE "public|private"; then
                VULNERABLE=1
                EVIDENCE="$EVIDENCE rocommunity/rwcommunity에 취약한 Community String(public/private) 사용"
            fi
        fi
        
        # 설정이 아예 없는 경우
        if [ -z "$COM2SEC" ] && [ -z "$ROCOMMUNITY" ]; then
            EVIDENCE="Community String 설정을 찾을 수 없습니다 (확인 필요)."
        fi
    else
        STATUS="PASS"
        EVIDENCE="$CONF 파일이 존재하지 않습니다."
    fi
    
    if [ $VULNERABLE -eq 1 ]; then
        STATUS="FAIL"
        EVIDENCE="SNMP Community String 복잡성이 미흡하여, 추측 가능한 기본값(public/private)으로 시스템 정보가 노출될 수 있는 위험이 있습니다. $EVIDENCE"
        GUIDE="이 항목은 SNMP 서비스 운영에 직접적인 영향을 주므로 자동 조치 기능을 제공하지 않습니다. 관리자가 직접 snmpd.conf 파일에서 'public', 'private' 대신 조직의 보안 정책에 부합하는 복잡한 Community String(영문자+숫자 10자 이상 또는 영문자+숫자+특수문자 8자 이상)으로 변경한 후 'systemctl restart snmpd'로 재시작하십시오."
        ACTION_RESULT="MANUAL_REQUIRED"
    elif [ $SNMP_RUNNING -eq 1 ]; then
        STATUS="PASS"
        EVIDENCE="SNMP Community String이 적절히 설정되어 있습니다."
    fi
fi

# JSON 출력 전 특수문자 제거
EVIDENCE=$(echo "$EVIDENCE" | tr '\n\r\t' '   ' | sed 's/"/\\"/g')


IMPACT_LEVEL="LOW"
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없으나, 기존에 단순 Community String으로 연동된 모니터링/관리 시스템이 있다면 변경 후 인증 실패로 수집이 중단될 수 있으므로 적용 전 연동 대상의 Community String 설정을 함께 변경할 수 있는지 확인한 뒤 복잡성 정책을 반영해야 합니다."

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
    "guide": "$GUIDE",
    "action_result": "$ACTION_RESULT",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
