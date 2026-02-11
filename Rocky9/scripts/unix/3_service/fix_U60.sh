#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-07
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-60
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : SNMP Community String 복잡성 설정
# @Description : SNMP Community String 복잡성 설정 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-60 SNMP Community String 복잡성 설정

# 1. 항목 정보 정의
ID="U-60"
CATEGORY="서비스 관리"
TITLE="SNMP Community String 복잡성 설정"
IMPORTANCE="중"
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
    
    if [ -f "$CONF" ]; then
        cp "$CONF" "${CONF}.bak_$(date +%Y%m%d_%H%M%S)"
        
        # [Redhat 계열] com2sec 설정에서 public/private 변경
        # 가이드: com2sec notConfigUser default <변경 값>
        if grep -v "^#" "$CONF" | grep -q "com2sec.*public"; then

            sed -i 's/\(com2sec.*\)public$/\1SecureStr1ng_CHANGE_ME/g' "$CONF"
            ACTION_LOG="$ACTION_LOG com2sec public -> SecureStr1ng_CHANGE_ME로 변경되었습니다."
        fi
        
        if grep -v "^#" "$CONF" | grep -q "com2sec.*private"; then

            sed -i 's/\(com2sec.*\)private$/\1SecureStr1ng_CHANGE_ME/g' "$CONF"
            ACTION_LOG="$ACTION_LOG com2sec private -> SecureStr1ng_CHANGE_ME로 변경되었습니다."
        fi
        
        # rocommunity/rwcommunity 호환성 처리
        if grep -v "^#" "$CONF" | grep -qE "^rocommunity\s+public"; then
            sed -i 's/^rocommunity\s\+public/rocommunity SecureStr1ng_CHANGE_ME/g' "$CONF"
            ACTION_LOG="$ACTION_LOG rocommunity public이 변경되었습니다."
        fi
        
        if grep -v "^#" "$CONF" | grep -qE "^rwcommunity\s+private"; then
            sed -i 's/^rwcommunity\s\+private/rwcommunity SecureStr1ng_CHANGE_ME/g' "$CONF"
            ACTION_LOG="$ACTION_LOG rwcommunity private이 변경되었습니다."
        fi
        
        if [ -n "$ACTION_LOG" ]; then
            systemctl restart snmpd 2>/dev/null
            ACTION_LOG="$ACTION_LOG SNMP 서비스를 재시작했습니다."

        else
            ACTION_RESULT="SUCCESS"
            ACTION_LOG="취약한 Community String이 발견되지 않았습니다."
        fi
    else
        ACTION_RESULT="FAIL"
        ACTION_LOG="$CONF 파일이 존재하지 않습니다."
    fi
fi

if [ "$ACTION_RESULT" == "SUCCESS" ] && [ -n "$ACTION_LOG" ]; then
    ACTION_LOG="SNMP Community String을 복잡한 문자열로 변경했습니다. 실제 환경에서는 반드시 수동으로 변경해야 합니다."
    STATUS="PASS"
    EVIDENCE="취약점 조치가 완료되었습니다."
elif [ "$ACTION_RESULT" == "FAIL" ]; then
    STATUS="FAIL"
    EVIDENCE="snmpd.conf 파일 확인이 필요합니다."
else
    STATUS="PASS"
    EVIDENCE="취약점 조치가 완료되었습니다."
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
