#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-07
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-61
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : SNMP Access Control 설정
# @Description : SNMP 접근 제어 설정 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-61 SNMP Access Control 설정

# 1. 항목 정보 정의
ID="U-61"
CATEGORY="서비스 관리"
TITLE="SNMP Access Control 설정"
IMPORTANCE="상"
TARGET_FILE="/etc/snmp/snmpd.conf"

# 2. 보완 로직
ACTION_RESULT="MANUAL"
ACTION_LOG=""

# 가이드: systemctl list-units --type=service | grep snmpd
if ! systemctl list-units --type=service 2>/dev/null | grep -q snmpd && ! pgrep -x snmpd >/dev/null; then
    ACTION_RESULT="SUCCESS"
    ACTION_LOG="SNMP 서비스가 비활성화되어 있습니다."
else
    CONF="/etc/snmp/snmpd.conf"
    
    if [ -f "$CONF" ]; then
        cp "$CONF" "${CONF}.bak_$(date +%Y%m%d_%H%M%S)"
        
        # [Redhat 계열] com2sec 설정에서 default를 127.0.0.1로 변경
        # 가이드: com2sec notConfigUser <허용할 네트워크 주소> <String값>
        if grep -v "^#" "$CONF" | grep -qE "com2sec.*\sdefault\s"; then

            # default를 127.0.0.1로 변경 (로컬만 허용)
            sed -i 's/\(com2sec\s\+\S\+\s\+\)default\(\s\)/\1127.0.0.1\2/g' "$CONF"
            ACTION_LOG="$ACTION_LOG com2sec default를 127.0.0.1로 변경했습니다."

            ACTION_RESULT="SUCCESS"
        fi
        
        # rocommunity/rwcommunity에 네트워크 주소 추가 (없는 경우)
        # 복잡한 로직이므로 수동 조치 권고
        if grep -v "^#" "$CONF" | grep -qE "^(rocommunity|rwcommunity)\s+\S+$"; then
            ACTION_LOG="$ACTION_LOG rocommunity/rwcommunity에 네트워크 제한이 없어 수동 조치가 필요합니다."
            ACTION_RESULT="MANUAL"
        fi
        
        if [ "$ACTION_RESULT" == "SUCCESS" ]; then
            systemctl restart snmpd 2>/dev/null
            ACTION_LOG="$ACTION_LOG SNMP 서비스를 재시작했습니다."
        fi
        
        [ -z "$ACTION_LOG" ] && ACTION_LOG="변경 사항이 없습니다."
    else
        ACTION_RESULT="FAIL"
        ACTION_LOG="$CONF 파일이 존재하지 않습니다."
    fi
fi

if [ "$ACTION_RESULT" == "SUCCESS" ]; then
    ACTION_LOG="SNMP 접근 제어 설정을 수정하여 로컬호스트만 허용하도록 설정했습니다."
    STATUS="PASS"
    EVIDENCE="SNMP 접근 제어가 적절히 설정되어 있습니다."
elif [ "$ACTION_RESULT" == "MANUAL" ]; then
    ACTION_LOG="SNMP 접근 제어 설정의 수동 확인이 필요합니다."
    STATUS="MANUAL"
    EVIDENCE="수동 확인이 필요합니다."
else
    STATUS="$ACTION_RESULT"
    EVIDENCE="SNMP 설정 파일 확인이 필요합니다."
fi

# 3. 마스터 템플릿 표준 출렵
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
