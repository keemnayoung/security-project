#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-59
# @Category : 서비스 관리
# @Platform : LINUX
# @Importance : 중
# @Title : SNMP 서비스 보안 설정 (SNMPv3 사용)
# @Description : SNMP Community String 제거 및 SNMPv3 사용자 생성
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-59 SNMP 서비스 보안 설정

# 1. 항목 정보 정의
ID="U-59"
CATEGORY="서비스관리"
TITLE="SNMP 서비스 보안 설정 (SNMPv3 사용)"
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
    ACTION_LOG="SNMP 서비스가 활성화되어 있지 않음 (U-58에서 조치됨)"
else
    CONF="/etc/snmp/snmpd.conf"
    if [ ! -f "$CONF" ]; then
        CONF="/usr/share/snmp/snmpd.conf"
    fi
    
    if [ -f "$CONF" ]; then
        BEFORE_SETTING="SNMP 설정 확인"
        
        # 1. Community String 주석 처리 (public/private)
        if grep -E "^(rocommunity|rwcommunity)" "$CONF" | grep -qE "public|private"; then
            cp "$CONF" "${CONF}.bak_$(date +%Y%m%d_%H%M%S)"
            sed -i 's/^\(rocommunity.*public\)/#\1/g' "$CONF"
            sed -i 's/^\(rwcommunity.*private\)/#\1/g' "$CONF"
            ACTION_LOG="$ACTION_LOG 취약한 Community String 주석 처리;"
        fi
        
        # 2. SNMPv3 사용자 추가 (없을 경우)
        if ! grep -q "^createUser" "$CONF" && ! grep -q "^rouser" "$CONF"; then
            echo "# SNMPv3 User Configuration" >> "$CONF"
            # 가이드 예시: createUser myuser SHA myauthpass AES myprivpass
            # 실제 환경에서는 비밀번호 변경 필요
            echo "createUser secureUser SHA secureAuthPass AES securePrivPass" >> "$CONF"
            echo "rouser secureUser" >> "$CONF"
            ACTION_LOG="$ACTION_LOG SNMPv3 예시 사용자(secureUser) 추가 (비밀번호 변경 권장);"
        fi
        
        systemctl restart snmpd 2>/dev/null
        AFTER_SETTING="SNMPv3 설정 적용 완료"
    else
        ACTION_RESULT="FAIL"
        ACTION_LOG="snmpd.conf 파일을 찾을 수 없음"
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
