#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-28
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : 접속 IP 및 포트 제한
# @Description : 허용할 호스트에 대한 접속 IP주소 제한 및 포트 제한 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 1. 항목 정보 정의
ID="U-28"
CATEGORY="파일 및 디렉토리 관리"
TITLE="접속 IP 및 포트 제한"
IMPORTANCE="상"
STATUS="PASS"
EVIDENCE=""
GUIDE="해당 항목은 자동 조치 시 시스템 장애 위험이 커서 자동 조치 기능을 제공하지 않습니다. 관리자가 직접 OS에 기본으로 제공하는 방화벽 애플리케이션이나 TCP Wrapper와 같은 호스트별 서비스 제한하고 애플리케이션을 사용하여 접근 허용 IP를 등록해주세요."
ACTION_RESULT="N/A"
IMPACT_LEVEL="HIGH" 
ACTION_IMPACT="허용된 IP와 포트만 접속 가능하도록 제한되면서 관리자나 외부 시스템이 기존에 사용하던 접속 경로가 차단되어 일시적인 서비스 접근 장애가 발생할 수 있습니다."
TARGET_FILE="N/A"
FILE_HASH="N/A"
CHECK_DATE=$(date +"%Y-%m-%d %H:%M:%S")


# 2. 진단 로직

EVIDENCE_LINES=()

# TCP Wrapper 점검
if [ -f /etc/hosts.allow ] && [ -f /etc/hosts.deny ]; then
    if grep -q "^ALL:ALL" /etc/hosts.deny && grep -Ev '^\s*$|^\s*#' /etc/hosts.allow >/dev/null 2>&1; then
        TARGET_FILE="/etc/hosts.allow, /etc/hosts.deny, "
    else   
        STATUS="FAIL"
        ACTION_RESULT="PARTIAL_SUCCESS"
        EVIDENCE_LINES+=("TCP Wrapper의 /etc/hosts.allow 또는 /etc/hosts.deny 접근 제한 설정이 확인되지 않습니다.")
    fi
fi

# iptables 점검
if command -v iptables >/dev/null 2>&1; then
    IPTABLES_RULES=$(iptables -L INPUT -n 2>/dev/null | grep ACCEPT | grep -E 'dpt:')
    if [ -n "$IPTABLES_RULES" ]; then
        TARGET_FILE+="iptables, "
    else   
        STATUS="FAIL"
        ACTION_RESULT="PARTIAL_SUCCESS"
        EVIDENCE_LINES+=("iptables의 INPUT 체인에 IP 및 포트 기반 접근제한 정책 설정이 확인되지 않습니다.")
    fi
fi

# firewalld 점검
if command -v firewall-cmd >/dev/null 2>&1; then
    if firewall-cmd --state >/dev/null 2>&1; then
        FIREWALLD_RULES=$(firewall-cmd --list-rich-rules 2>/dev/null)
        if [ -n "$FIREWALLD_RULES" ]; then
            TARGET_FILE+="firewalld, "
        else   
            STATUS="FAIL"
            ACTION_RESULT="PARTIAL_SUCCESS"
            EVIDENCE_LINES+=("firewalld에 rich-rule 기반 IP 및 포트 접근제한 설정 확인되지 않습니다.")
        fi
    fi
fi

# UFW 점검
if command -v ufw >/dev/null 2>&1; then
    if ufw status | grep -q "Status: active"; then
        UFW_RULES=$(ufw status numbered | grep -E 'ALLOW.*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
        if [ -n "$UFW_RULES" ]; then
            TARGET_FILE+="ufw, "
        else   
            STATUS="FAIL"
            ACTION_RESULT="PARTIAL_SUCCESS"
            EVIDENCE_LINES+=("UFW에 IP 및 포트 기반 접근 허용 정책이 확인되지 않습니다.")
        fi
    fi
fi

if [ "$STATUS" = "PASS" ]; then
    ACTION_RESULT="SUCCESS"
    EVIDENCE="TCP wrapper, iptables, firewalld, UFW에 접속 IP 주소 제한 및 포트 제한이 모두 적절하게 설정되어 있어 보안 위협이 없습니다."
    GUIDE="KISA 보안 가이드라인을 준수하고 있습니다."
else
    EVIDENCE="다음 서비스에 대하여 접속 IP 및 포트 제한이 되고 있지 않습니다. ("
    EVIDENCE+=$(printf "%s " "${EVIDENCE_LINES[@]}")
    EVIDENCE+=")"
    EVIDENCE+="보안을 위해 수동 설정이 필요합니다."
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
    "guide": "$GUIDE",
    "action_result": "$ACTION_RESULT",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$CHECK_DATE"
}
EOF