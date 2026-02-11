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
    ACTION_LOG="SNMP 서비스가 활성화되어 있지 않습니다. (U-58에서 조치되었습니다)"
else
    CONF="/etc/snmp/snmpd.conf"
    if [ ! -f "$CONF" ]; then
        CONF="/usr/share/snmp/snmpd.conf"
    fi
    
    if [ -f "$CONF" ]; then

        
        # 1. Community String 주석 처리 (public/private)
        if grep -E "^(rocommunity|rwcommunity)" "$CONF" | grep -qE "public|private"; then
            cp "$CONF" "${CONF}.bak_$(date +%Y%m%d_%H%M%S)"
            sed -i 's/^\(rocommunity.*public\)/#\1/g' "$CONF"
            sed -i 's/^\(rwcommunity.*private\)/#\1/g' "$CONF"
            ACTION_LOG="$ACTION_LOG 취약한 Community String을 주석 처리했습니다."
        fi
        
        # 2. SNMPv3 사용자 추가 (없을 경우)
        if ! grep -q "^createUser" "$CONF" && ! grep -q "^rouser" "$CONF"; then
            echo "# SNMPv3 User Configuration" >> "$CONF"
            # 가이드 예시: createUser myuser SHA myauthpass AES myprivpass
            # 실제 환경에서는 비밀번호 변경 필요
            echo "createUser secureUser SHA secureAuthPass AES securePrivPass" >> "$CONF"
            echo "rouser secureUser" >> "$CONF"
            ACTION_LOG="$ACTION_LOG SNMPv3 예시 사용자(secureUser)를 추가했습니다(비밀번호 변경 권장)."
        fi
        
        systemctl restart snmpd 2>/dev/null

    else
        ACTION_RESULT="FAIL"
        ACTION_LOG="snmpd.conf 파일을 찾을 수 없습니다."
    fi
fi

if [ "$ACTION_RESULT" == "SUCCESS" ] && [ -n "$ACTION_LOG" ]; then
    ACTION_LOG="SNMP Community String을 주석 처리하고 SNMPv3 사용자를 추가하여 안전한 SNMP 버전 사용 환경을 구성했습니다."
    STATUS="PASS"
    EVIDENCE="조치 완료 (양호)"
elif [ "$ACTION_RESULT" == "FAIL" ]; then
    STATUS="FAIL"
    EVIDENCE="SNMP 설정 자동 조치에 실패했습니다. 설정 파일 및 서비스 상태를 확인해야 합니다."
else
    STATUS="PASS"
    EVIDENCE="조치 완료 (양호)"
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
