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
        
        # [Redhat 계열] com2sec 설정에서 default를 127.0.0.1로 변경
        # 가이드: com2sec notConfigUser <허용할 네트워크 주소> <String값>
        if grep -v "^#" "$CONF" | grep -qE "com2sec.*\sdefault\s"; then
            BEFORE_SETTING="com2sec default 사용"
            # default를 127.0.0.1로 변경 (로컬만 허용)
            sed -i 's/\(com2sec\s\+\S\+\s\+\)default\(\s\)/\1127.0.0.1\2/g' "$CONF"
            ACTION_LOG="$ACTION_LOG com2sec default -> 127.0.0.1 변경;"
            AFTER_SETTING="127.0.0.1로 제한 (수동으로 허용할 네트워크 주소 확인 필요)"
            ACTION_RESULT="SUCCESS"
        fi
        
        # rocommunity/rwcommunity에 네트워크 주소 추가 (없는 경우)
        # 복잡한 로직이므로 수동 조치 권고
        if grep -v "^#" "$CONF" | grep -qE "^(rocommunity|rwcommunity)\s+\S+$"; then
            ACTION_LOG="$ACTION_LOG rocommunity/rwcommunity에 네트워크 제한 없음 - 수동 조치 필요;"
            ACTION_RESULT="MANUAL"
        fi
        
        if [ "$ACTION_RESULT" == "SUCCESS" ]; then
            systemctl restart snmpd 2>/dev/null
            ACTION_LOG="$ACTION_LOG SNMP 서비스 재시작;"
        fi
        
        [ -z "$ACTION_LOG" ] && ACTION_LOG="변경 사항 없음"
    else
        ACTION_RESULT="FAIL"
        ACTION_LOG="$CONF 파일이 존재하지 않음"
    fi
fi

# 3. 마스터 템플릿 표준 출력
echo ""

STATUS="$ACTION_RESULT"
EVIDENCE="$ACTION_LOG"
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
    "action_impact": 
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
