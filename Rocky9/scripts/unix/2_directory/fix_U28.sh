#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-28
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : 접속 IP 및 포트 제한
# @Description : 접속을 허용할 특정 호스트에 대한 IP주소 및 포트 제한 설정
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

######################
# 검토 필요 (수동 설정)
#####################

# 0. 기본 정보 정의
ID="U-28"
CATEGORY="파일 및 디렉토리 관리"
TITLE="접속 IP 및 포트 제한"
IMPORTANCE="상"

STATUS="FAIL"
ACTION_RESULT="MANUAL_REQUIRED"
ACTION_LOG="N/A"
EVIDENCE="N/A"

CHECK_DATE=$(date '+%Y-%m-%d %H:%M:%S')
ACTION_DATE=$(date '+%Y-%m-%d %H:%M:%S')

# 1. 실제 조치 프로세스 (상태 수집)
FIND_FLAG=0
DETAIL_LOG=""

# TCP Wrapper
if [ -f /etc/hosts.allow ] && [ -f /etc/hosts.deny ]; then
    if grep -q "^ALL:ALL" /etc/hosts.deny && \
       grep -Ev '^\s*$|^\s*#' /etc/hosts.allow >/dev/null 2>&1; then
        FIND_FLAG=1
        DETAIL_LOG+="TCP Wrapper 접근제한 설정 확인\n"
    fi
fi

# iptables
if command -v iptables >/dev/null 2>&1; then
    IPT_RULE=$(iptables -L INPUT -n 2>/dev/null | grep ACCEPT | grep dpt)
    if [ -n "$IPT_RULE" ]; then
        FIND_FLAG=1
        DETAIL_LOG+="iptables IP 및 포트 제한 정책 존재\n"
    fi
fi

# firewalld
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    FW_RULE=$(firewall-cmd --list-rich-rules 2>/dev/null)
    if [ -n "$FW_RULE" ]; then
        FIND_FLAG=1
        DETAIL_LOG+="firewalld rich-rule 접근제한 설정 존재\n"
    fi
fi

# UFW
if command -v ufw >/dev/null 2>&1; then
    if ufw status | grep -q "Status: active"; then
        UFW_RULE=$(ufw status numbered | grep ALLOW | grep -E '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
        if [ -n "$UFW_RULE" ]; then
            FIND_FLAG=1
            DETAIL_LOG+="UFW IP 기반 접근제한 정책 존재\n"
        fi
    fi
fi

# 2. 결과 판단
if [ "$FIND_FLAG" -eq 1 ]; then
    STATUS="PASS"
    ACTION_RESULT="SUCCESS"
    ACTION_LOG="접근 IP 및 포트 제한 설정이 확인되어 추가 조치가 필요하지 않습니다."
    EVIDENCE="IP 및 포트 기반 접근제한 설정 존재 (양호)"
else
    STATUS="FAIL"
    ACTION_RESULT="MANUAL_REQUIRED"
    ACTION_LOG="접근 IP 및 포트 제한 설정이 확인되지 않아 자동 조치를 수행하지 않았습니다. 정책에 따라 수동 설정이 필요합니다."
    EVIDENCE="접근제한 정책 미설정 (취약)"
fi


# 3. JSON 표준 출력 (U-01 형식과 동일)
echo ""
cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "OS 기본 방화벽 또는 TCP Wrapper를 이용하여 허용 IP 및 포트를 제한 설정해야 합니다.",
    "action_result": "$ACTION_RESULT",
    "action_log": "$ACTION_LOG",
    "action_date": "$ACTION_DATE",
    "check_date": "$CHECK_DATE"
}
EOF