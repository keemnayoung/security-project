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
# @Platform : Rocky Linux 9
# @Importance : 중
# @Title : SNMP Community String 복잡성 설정
# @Description : SNMP Community String을 추측하기 어려운 값으로 변경
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-60 SNMP Community String 복잡성 설정

# 1. 항목 정보 정의
ID="U-60"
CATEGORY="서비스관리"
TITLE="SNMP Community String 복잡성 설정"
IMPORTANCE="중"
TARGET_FILE="/etc/snmp/snmpd.conf"

# 2. 보완 로직
ACTION_RESULT="SUCCESS"
BEFORE_SETTING=""
AFTER_SETTING=""
ACTION_LOG=""

# 가이드: systemctl list-units --type=service | grep snmpd
if ! systemctl list-units --type=service 2>/dev/null | grep -q snmpd && ! pgrep -x snmpd >/dev/null; then
    ACTION_RESULT="SUCCESS"
    ACTION_LOG="SNMP 서비스가 비활성화되어 있음"
else
    CONF="/etc/snmp/snmpd.conf"
    
    if [ -f "$CONF" ]; then
        cp "$CONF" "${CONF}.bak_$(date +%Y%m%d_%H%M%S)"
        
        # [Redhat 계열] com2sec 설정에서 public/private 변경
        # 가이드: com2sec notConfigUser default <변경 값>
        if grep -v "^#" "$CONF" | grep -q "com2sec.*public"; then
            BEFORE_SETTING="com2sec public 사용"
            sed -i 's/\(com2sec.*\)public$/\1SecureStr1ng_CHANGE_ME/g' "$CONF"
            ACTION_LOG="$ACTION_LOG com2sec public -> SecureStr1ng_CHANGE_ME 변경;"
        fi
        
        if grep -v "^#" "$CONF" | grep -q "com2sec.*private"; then
            BEFORE_SETTING="$BEFORE_SETTING com2sec private 사용"
            sed -i 's/\(com2sec.*\)private$/\1SecureStr1ng_CHANGE_ME/g' "$CONF"
            ACTION_LOG="$ACTION_LOG com2sec private -> SecureStr1ng_CHANGE_ME 변경;"
        fi
        
        # rocommunity/rwcommunity 호환성 처리
        if grep -v "^#" "$CONF" | grep -qE "^rocommunity\s+public"; then
            sed -i 's/^rocommunity\s\+public/rocommunity SecureStr1ng_CHANGE_ME/g' "$CONF"
            ACTION_LOG="$ACTION_LOG rocommunity public 변경;"
        fi
        
        if grep -v "^#" "$CONF" | grep -qE "^rwcommunity\s+private"; then
            sed -i 's/^rwcommunity\s\+private/rwcommunity SecureStr1ng_CHANGE_ME/g' "$CONF"
            ACTION_LOG="$ACTION_LOG rwcommunity private 변경;"
        fi
        
        if [ -n "$ACTION_LOG" ]; then
            systemctl restart snmpd 2>/dev/null
            ACTION_LOG="$ACTION_LOG SNMP 서비스 재시작;"
            AFTER_SETTING="Community String 변경 완료 (SecureStr1ng_CHANGE_ME - 반드시 수동 변경 필요)"
        else
            ACTION_RESULT="SUCCESS"
            ACTION_LOG="취약한 Community String이 발견되지 않음"
        fi
    else
        ACTION_RESULT="FAIL"
        ACTION_LOG="$CONF 파일이 존재하지 않음"
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
    "action_result": "$ACTION_RESULT",
    "before_setting": "$BEFORE_SETTING",
    "after_setting": "$AFTER_SETTING",
    "action_log": "$ACTION_LOG",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
