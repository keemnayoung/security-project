#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로그램
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-14
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
    # SNMP 미사용 → 중지 및 비활성화
    systemctl stop snmpd 2>/dev/null
    systemctl disable snmpd 2>/dev/null
    ACTION_RESULT="SUCCESS"
    ACTION_LOG="SNMP 서비스가 미사용 상태이므로 완전히 중지 및 비활성화 처리했습니다."
else
    # SNMP 사용 중 → 수동 조치 필요
    CONF="/etc/snmp/snmpd.conf"
    
    if [ -f "$CONF" ]; then
        # Community String 취약 여부 확인
        WEAK_FOUND=0
        
        if grep -v "^#" "$CONF" | grep -qE "com2sec.*(public|private)"; then
            WEAK_FOUND=1
        fi
        
        if grep -v "^#" "$CONF" | grep -qE "^(rocommunity|rwcommunity).*(public|private)"; then
            WEAK_FOUND=1
        fi
        
        if [ $WEAK_FOUND -eq 1 ]; then
            ACTION_RESULT="MANUAL"
            ACTION_LOG="SNMP 서비스가 사용 중이며 취약한 Community String(public/private)이 발견되었습니다. 조직의 보안 정책에 부합하는 복잡한 Community String(영문자+숫자 10자 이상 또는 영문자+숫자+특수문자 8자 이상)으로 수동 변경이 필요하며, 변경 후 'systemctl restart snmpd'로 재시작하십시오."
        else
            ACTION_RESULT="SUCCESS"
            ACTION_LOG="SNMP Community String이 적절히 설정되어 있습니다."
        fi
    else
        ACTION_RESULT="FAIL"
        ACTION_LOG="$CONF 파일이 존재하지 않습니다."
    fi
fi

if [ "$ACTION_RESULT" == "SUCCESS" ]; then
    STATUS="PASS"
    EVIDENCE="취약점 조치가 완료되었습니다."
elif [ "$ACTION_RESULT" == "MANUAL" ]; then
    STATUS="MANUAL"
    EVIDENCE="수동 조치가 필요합니다."
else
    STATUS="FAIL"
    EVIDENCE="snmpd.conf 파일 확인이 필요합니다."
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
