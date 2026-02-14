#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-49
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : DNS 보안 버전 패치
# @Description : BIND 최신 버전 사용 유무 및 주기적 보안 패치 여부 점검
# @Criteria_Good : 주기적으로 패치를 관리하는 경우
# @Criteria_Bad : 주기적으로 패치를 관리하고 있지 않은 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-49 DNS 보안 버전 패치

# 1. 항목 정보 정의
ID="U-49"
CATEGORY="서비스 관리"
TITLE="DNS 보안 버전 패치"
IMPORTANCE="상"
TARGET_FILE="/usr/sbin/named"

# ===== 버전 설정 (수정 가능) =====
REQUIRED_VERSION="9.20.18"
# ==================================

# 2. 진단 로직 (무결성 해시 포함)
STATUS="PASS"
EVIDENCE=""
FILE_HASH="NOT_FOUND"

VULNERABLE=0
DNS_VERSION=""

# 버전 비교 함수
version_compare() {
    # $1: 현재 버전, $2: 요구 버전
    # 반환: 0 (같음), 1 (현재 > 요구), 2 (현재 < 요구)
    
    local ver1=$1
    local ver2=$2
    
    # 버전 숫자만 추출 (예: BIND 9.20.18 -> 9.20.18)
    ver1=$(echo "$ver1" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    ver2=$(echo "$ver2" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    
    if [ -z "$ver1" ] || [ -z "$ver2" ]; then
        return 3  # 버전 파싱 실패
    fi
    
    # 버전 분해
    local IFS='.'
    local ver1_arr=($ver1)
    local ver2_arr=($ver2)
    
    # Major 버전 비교
    if [ ${ver1_arr[0]} -gt ${ver2_arr[0]} ]; then
        return 1
    elif [ ${ver1_arr[0]} -lt ${ver2_arr[0]} ]; then
        return 2
    fi
    
    # Minor 버전 비교
    if [ ${ver1_arr[1]} -gt ${ver2_arr[1]} ]; then
        return 1
    elif [ ${ver1_arr[1]} -lt ${ver2_arr[1]} ]; then
        return 2
    fi
    
    # Patch 버전 비교
    if [ ${ver1_arr[2]} -gt ${ver2_arr[2]} ]; then
        return 1
    elif [ ${ver1_arr[2]} -lt ${ver2_arr[2]} ]; then
        return 2
    fi
    
    return 0  # 같음
}

# [Step 1] DNS 서비스 활성화 여부 확인
# 가이드: systemctl list-units --type=service | grep named
if systemctl list-units --type=service 2>/dev/null | grep -q "named"; then
    DNS_ACTIVE=1
else
    DNS_ACTIVE=0
fi

# [Step 2] BIND 버전 확인
# 가이드: named -v
if command -v named &>/dev/null; then
    DNS_VERSION=$(named -v 2>/dev/null)
    TARGET_FILE=$(command -v named)
    FILE_HASH=$(sha256sum "$TARGET_FILE" 2>/dev/null | awk '{print $1}')
fi

if [ $DNS_ACTIVE -eq 1 ]; then
    # DNS 서비스가 활성화된 경우
    if [ -n "$DNS_VERSION" ]; then
        # 버전 비교
        version_compare "$DNS_VERSION" "$REQUIRED_VERSION"
        COMPARE_RESULT=$?
        
        if [ $COMPARE_RESULT -eq 2 ]; then
            # 현재 버전이 요구 버전보다 낮음
            STATUS="FAIL"
            EVIDENCE="DNS 서비스($DNS_VERSION)가 실행 중이며, 요구 버전($REQUIRED_VERSION)보다 낮아 보안 패치가 필요합니다."
            GUIDE="이 항목은 시스템 전체 DNS 서비스에 영향을 줄 수 있어 자동 조치 기능을 제공하지 않습니다. 관리자가 직접 'dnf update bind' 명령으로 최신 보안 패치를 적용한 후 'systemctl restart named'로 서비스를 재시작하십시오. 패치 적용 전 반드시 영향도를 평가하고 변경관리 절차에 따라 단계적으로 적용하십시오."
            ACTION_RESULT="MANUAL_REQUIRED"
        elif [ $COMPARE_RESULT -eq 3 ]; then
            # 버전 비교 실패
            STATUS="FAIL"
            EVIDENCE="DNS 서비스($DNS_VERSION)가 실행 중이나 버전 형식을 파싱할 수 없어 수동 점검이 필요합니다."
            GUIDE="이 항목은 시스템 전체 DNS 서비스에 영향을 줄 수 있어 자동 조치 기능을 제공하지 않습니다. 관리자가 직접 'dnf update bind' 명령으로 최신 보안 패치를 적용한 후 'systemctl restart named'로 서비스를 재시작하십시오. 패치 적용 전 반드시 영향도를 평가하고 변경관리 절차에 따라 단계적으로 적용하십시오."
            ACTION_RESULT="MANUAL_REQUIRED"
        else
            # 현재 버전이 요구 버전 이상
            STATUS="PASS"
            EVIDENCE="DNS 서비스($DNS_VERSION)가 요구 버전($REQUIRED_VERSION) 이상으로 적절히 패치되어 있습니다."
            GUIDE="KISA 보안 가이드라인을 준수하고 있습니다."
            ACTION_RESULT="SUCCESS"
        fi
    else
        # 버전 확인 불가
        STATUS="FAIL"
        EVIDENCE="DNS 서비스가 실행 중이나 버전을 확인할 수 없어 수동 점검이 필요합니다."
        GUIDE="이 항목은 시스템 전체 DNS 서비스에 영향을 줄 수 있어 자동 조치 기능을 제공하지 않습니다. 관리자가 직접 'dnf update bind' 명령으로 최신 보안 패치를 적용한 후 'systemctl restart named'로 서비스를 재시작하십시오."
        ACTION_RESULT="MANUAL_REQUIRED"
    fi
else
    STATUS="PASS"
    EVIDENCE="DNS 서비스가 비활성화되어 있습니다."
    GUIDE="KISA 보안 가이드라인을 준수하고 있습니다."
    ACTION_RESULT="SUCCESS"
fi


IMPACT_LEVEL="HIGH"
ACTION_IMPACT="DNS 서비스 보안 패치 적용 시 시스템 및 서비스에 영향을 줄 수 있습니다. 특히 DNS 서비스는 패치 적용에 따른 서비스 영향 정도를 정확히 파악한 뒤 주기적인 패치 적용 정책을 수립하여 운영에 미칠 수 있는 영향을 충분히 고려하고 단계적으로 적용해야 합니다."

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
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
