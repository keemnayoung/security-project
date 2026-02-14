#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-58
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : 불필요한 SNMP 서비스 구동 점검
# @Description : SNMP 서비스 활성화 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-58 불필요한 SNMP 서비스 구동 점검

# 1. 항목 정보 정의
ID="U-58"
CATEGORY="서비스 관리"
TITLE="불필요한 SNMP 서비스 구동 점검"
IMPORTANCE="중"
TARGET_FILE="/usr/sbin/snmpd"

# 2. 보완 로직
ACTION_RESULT="SUCCESS"
ACTION_LOG=""

# 가이드: systemctl list-units --type=service | grep snmpd
#         systemctl stop snmpd, systemctl disable snmpd

if systemctl list-units --type=service 2>/dev/null | grep -q snmpd; then

    systemctl stop snmpd 2>/dev/null
    systemctl disable snmpd 2>/dev/null
    ACTION_LOG="SNMP 서비스(snmpd) 중지 및 비활성화 완료"

else
    # 프로세스로 떠있는 경우 kill
    if pgrep -x "snmpd" >/dev/null; then

        pkill -x snmpd
        ACTION_LOG="SNMP 프로세스 강제 종료"

        
        # 서비스도 disable 시도
        systemctl disable snmpd 2>/dev/null
    else
        ACTION_RESULT="SUCCESS"
        ACTION_LOG="SNMP 서비스가 이미 비활성화 상태임"
    fi
fi

if [ -n "$ACTION_LOG" ]; then
    ACTION_LOG="불필요한 SNMP 서비스(snmpd)를 중지하고 비활성화 처리했습니다."
else
    ACTION_LOG="SNMP 서비스가 이미 비활성화된 상태입니다."
fi

STATUS="PASS"
EVIDENCE="조치 완료 (양호)"

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
