#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-59
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상 
# @Title : 안전한 SNMP 버전 사용
# @Description : 안전한 SNMP 버전 사용 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-59 안전한 SNMP 버전 사용

# 1. 항목 정보 정의
ID="U-59"
CATEGORY="서비스 관리"
TITLE="안전한 SNMP 버전 사용"
IMPORTANCE="상"
TARGET_FILE="/etc/snmp/snmpd.conf"

# 2. 보완 로직
ACTION_RESULT="SUCCESS"
ACTION_LOG=""

# 가이드: systemctl list-units --type=service | grep snmpd
if ! systemctl list-units --type=service 2>/dev/null | grep -q snmpd && ! pgrep -x snmpd >/dev/null; then
    ACTION_RESULT="SUCCESS"
    ACTION_LOG="SNMP 서비스가 비활성화되어 있습니다."
else
    CONF="/etc/snmp/snmpd.conf"
    if [ ! -f "$CONF" ]; then
        CONF="/usr/share/snmp/snmpd.conf"
    fi
    
    if [ -f "$CONF" ]; then
        # v3 사용자 설정 확인
        V3_USER=$(grep -E "^(rouser|rwuser|createUser)" "$CONF" 2>/dev/null)
        
        if [ -n "$V3_USER" ]; then
            # 이미 v3 사용 중
            ACTION_RESULT="SUCCESS"
            ACTION_LOG="SNMPv3 사용자 설정이 이미 존재하여 안전한 SNMP 버전을 사용 중입니다."
        else
            # v1/v2 사용 중 → 수동 조치 안내
            ACTION_RESULT="MANUAL"
            ACTION_LOG="SNMP v1/v2 사용이 감지되었습니다. SNMPv3로 업그레이드가 필요합니다. 다음 명령어로 SNMPv3 사용자를 생성하십시오: 'net-snmp-create-v3-user -ro -A <인증암호> -X <암호화암호> -a SHA -x AES <사용자명>' 생성 후 'systemctl restart snmpd'로 재시작하십시오. 기존 v1/v2 Community String은 snmpd.conf에서 주석 처리하거나 삭제하십시오."
        fi
    else
        ACTION_RESULT="FAIL"
        ACTION_LOG="snmpd.conf 파일을 찾을 수 없습니다."
    fi
fi

if [ "$ACTION_RESULT" == "SUCCESS" ]; then
    STATUS="PASS"
    EVIDENCE="안전한 SNMP 버전 사용 환경이 구성되어 있습니다."
elif [ "$ACTION_RESULT" == "MANUAL" ]; then
    STATUS="MANUAL"
    EVIDENCE="SNMP v1/v2 사용이 감지되었습니다. SNMPv3로 업그레이드가 필요합니다."
else
    STATUS="FAIL"
    EVIDENCE="SNMP 설정 파일 확인이 필요합니다."
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
    "guide": "KISA 가이드라인에 따른 보안 설정이 완료되었습니다.",
    "action_result": "$ACTION_RESULT",
    "action_log": "$ACTION_LOG",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
