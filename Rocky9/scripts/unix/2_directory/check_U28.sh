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
CHECK_ID="U-28"
CATEGORY="파일 및 디렉토리 관리"
TITLE="접속 IP 및 포트 제한"
IMPORTANCE="상"
STATUS="FAIL"
EVIDENCE=""
TARGET_FILE="N/A"
IMPACT_LEVEL="HIGH" 
ACTION_IMPACT="허용된 IP와 포트만 접속 가능하도록 제한되면서 관리자나 외부 시스템이 기존에 사용하던 접속 경로가 차단되어 일시적인 서비스 접근 장애가 발생할 수 있습니다."
CHECK_DATE=$(date +"%Y-%m-%d %H:%M:%S")

# 2. 진단 로직
# TCP Wrapper 점검
if [ -f /etc/hosts.allow ] && [ -f /etc/hosts.deny ]; then
    if grep -q "^ALL:ALL" /etc/hosts.deny && grep -Ev '^\s*$|^\s*#' /etc/hosts.allow >/dev/null 2>&1; then
        STATUS="PASS"
        EVIDENCE="TCP Wrapper 접근제한 설정 확인 (/etc/hosts.allow, /etc/hosts.deny)"
        TARGET_FILE="/etc/hosts.allow, /etc/hosts.deny"
    fi
fi

# iptables 점검
if [ "$STATUS" = "FAIL" ] && command -v iptables >/dev/null 2>&1; then
    IPTABLES_RULES=$(iptables -L INPUT -n 2>/dev/null | grep ACCEPT | grep -E 'dpt:')
    if [ -n "$IPTABLES_RULES" ]; then
        STATUS="PASS"
        EVIDENCE="iptables INPUT 체인에 IP 및 포트 기반 접근제한 정책 존재"
        TARGET_FILE="iptables"
    fi
fi

# firewalld 점검
if [ "$STATUS" = "FAIL" ] && command -v firewall-cmd >/dev/null 2>&1; then
    if firewall-cmd --state >/dev/null 2>&1; then
        FIREWALLD_RULES=$(firewall-cmd --list-rich-rules 2>/dev/null)
        if [ -n "$FIREWALLD_RULES" ]; then
            STATUS="PASS"
            EVIDENCE="firewalld rich-rule 기반 IP 및 포트 접근제한 설정 확인"
            TARGET_FILE="firewalld"
        fi
    fi
fi

# UFW 점검
if [ "$STATUS" = "FAIL" ] && command -v ufw >/dev/null 2>&1; then
    if ufw status | grep -q "Status: active"; then
        UFW_RULES=$(ufw status numbered | grep -E 'ALLOW.*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
        if [ -n "$UFW_RULES" ]; then
            STATUS="PASS"
            EVIDENCE="UFW에 IP 및 포트 기반 접근 허용 정책 존재"
            TARGET_FILE="ufw"
        fi
    fi
fi

if [ "$STATUS" = "FAIL" ]; then
    EVIDENCE="IP 및 포트 기반 접근제한 설정(TCP Wrapper, iptables, firewalld, UFW) 미확인"
fi

# 3. 마스터 JSON 출력
echo ""
cat <<EOF
{
    "check_id": "$CHECK_ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "OS에 기본으로 제공하는 방화벽 애플리케이션이나 TCP Wrapper와 같은 호스트별 서비스 제한하고 애플리케이션을 사용하여 접근 허용 IP를 등록해주세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "N/A",
    "action_impact": "$ACTION_IMPACT",
    "impact_level": "$IMPACT_LEVEL",  
    "check_date": "$CHECK_DATE"
}
EOF