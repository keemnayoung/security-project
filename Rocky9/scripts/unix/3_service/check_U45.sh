#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-45
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 메일 서비스 버전 점검
# @Description : 취약한 버전의 메일 서비스 이용 여부 점검
# @Criteria_Good :  메일 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정
# @Criteria_Bad : 메일 서비스 사용 시 패치 관리 정책을 수립하여 주기적으로 패치 적용 설정
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-45 메일 서비스 버전 점검

# 1. 항목 정보 정의
ID="U-45"
CATEGORY="서비스 관리"
TITLE="메일 서비스 버전 점검"
IMPORTANCE="상"
TARGET_FILE="/etc/mail/sendmail.cf"

# ===== 버전 설정 (수정 가능) =====
SENDMAIL_REQUIRED_VERSION="8.18.2"
POSTFIX_REQUIRED_VERSION="3.10.7"
EXIM_REQUIRED_VERSION="4.99.1"
# ==================================

# 2. 진단 로직 (무결성 해시 포함)
STATUS="PASS"
EVIDENCE=""
FILE_HASH="NOT_FOUND"

VULNERABLE=0
MAIL_VERSION=""
MAIL_SERVICE=""

# 버전 비교 함수
version_compare() {
    # $1: 현재 버전, $2: 요구 버전
    # 반환: 0 (같음), 1 (현재 > 요구), 2 (현재 < 요구), 3 (파싱 실패)
    
    local ver1=$1
    local ver2=$2
    
    # 버전 숫자만 추출 (예: 8.18.2)
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

# [Sendmail]
# 가이드: sendmail -d0 -bt
if command -v sendmail &>/dev/null; then
    # 버전 정보만 추출
    MAIL_VERSION=$(sendmail -d0 < /dev/null 2>/dev/null | grep -i "Version" | awk '{print $2}')
    if systemctl is-active sendmail >/dev/null 2>&1; then
        MAIL_SERVICE="sendmail"
        TARGET_FILE="/etc/mail/sendmail.cf"
        
        if [ -n "$MAIL_VERSION" ]; then
            version_compare "$MAIL_VERSION" "$SENDMAIL_REQUIRED_VERSION"
            COMPARE_RESULT=$?
            
            if [ $COMPARE_RESULT -eq 2 ]; then
                VULNERABLE=1
                EVIDENCE="$EVIDENCE Sendmail($MAIL_VERSION)이 실행 중이며, 요구 버전($SENDMAIL_REQUIRED_VERSION)보다 낮아 보안 패치가 필요합니다."
            elif [ $COMPARE_RESULT -eq 3 ]; then
                VULNERABLE=1
                EVIDENCE="$EVIDENCE Sendmail($MAIL_VERSION)이 실행 중이나 버전 형식을 파싱할 수 없어 수동 점검이 필요합니다."
            else
                STATUS="PASS"
                EVIDENCE="$EVIDENCE Sendmail($MAIL_VERSION)이 요구 버전($SENDMAIL_REQUIRED_VERSION) 이상으로 적절히 패치되어 있습니다."
            fi
        else
            VULNERABLE=1
            EVIDENCE="$EVIDENCE Sendmail이 실행 중이나 버전을 확인할 수 없어 수동 점검이 필요합니다."
        fi
    fi
fi

# [Postfix]
# 가이드: postconf mail_version
if command -v postconf &>/dev/null; then
    MAIL_VERSION=$(postconf mail_version 2>/dev/null | cut -d= -f2 | xargs)
    if systemctl is-active postfix >/dev/null 2>&1; then
        MAIL_SERVICE="postfix"
        TARGET_FILE="/etc/postfix/main.cf"
        
        if [ -n "$MAIL_VERSION" ]; then
            version_compare "$MAIL_VERSION" "$POSTFIX_REQUIRED_VERSION"
            COMPARE_RESULT=$?
            
            if [ $COMPARE_RESULT -eq 2 ]; then
                VULNERABLE=1
                EVIDENCE="$EVIDENCE Postfix($MAIL_VERSION)가 실행 중이며, 요구 버전($POSTFIX_REQUIRED_VERSION)보다 낮아 보안 패치가 필요합니다."
            elif [ $COMPARE_RESULT -eq 3 ]; then
                VULNERABLE=1
                EVIDENCE="$EVIDENCE Postfix($MAIL_VERSION)가 실행 중이나 버전 형식을 파싱할 수 없어 수동 점검이 필요합니다."
            else
                STATUS="PASS"
                EVIDENCE="$EVIDENCE Postfix($MAIL_VERSION)가 요구 버전($POSTFIX_REQUIRED_VERSION) 이상으로 적절히 패치되어 있습니다."
            fi
        else
            VULNERABLE=1
            EVIDENCE="$EVIDENCE Postfix가 실행 중이나 버전을 확인할 수 없어 수동 점검이 필요합니다."
        fi
    else
        # 사용하지 않는데 프로세스가 있으면 취약
        if ps -ef | grep -v grep | grep -q postfix; then
             VULNERABLE=1
             EVIDENCE="$EVIDENCE Postfix 서비스가 중지되었으나 프로세스가 잔존합니다."
        fi
    fi
fi

# [Exim]
# 가이드: exim --version
if command -v exim &>/dev/null || command -v exim4 &>/dev/null; then
    MAIL_VERSION=$(exim --version 2>/dev/null | head -1 | awk '{print $3}')
    if systemctl is-active exim4 >/dev/null 2>&1; then
        MAIL_SERVICE="exim"
        TARGET_FILE="/etc/exim4/exim4.conf"
        
        if [ -n "$MAIL_VERSION" ]; then
            version_compare "$MAIL_VERSION" "$EXIM_REQUIRED_VERSION"
            COMPARE_RESULT=$?
            
            if [ $COMPARE_RESULT -eq 2 ]; then
                VULNERABLE=1
                EVIDENCE="$EVIDENCE Exim($MAIL_VERSION)이 실행 중이며, 요구 버전($EXIM_REQUIRED_VERSION)보다 낮아 보안 패치가 필요합니다."
            elif [ $COMPARE_RESULT -eq 3 ]; then
                VULNERABLE=1
                EVIDENCE="$EVIDENCE Exim($MAIL_VERSION)이 실행 중이나 버전 형식을 파싱할 수 없어 수동 점검이 필요합니다."
            else
                STATUS="PASS"
                EVIDENCE="$EVIDENCE Exim($MAIL_VERSION)이 요구 버전($EXIM_REQUIRED_VERSION) 이상으로 적절히 패치되어 있습니다."
            fi
        else
            VULNERABLE=1
            EVIDENCE="$EVIDENCE Exim이 실행 중이나 버전을 확인할 수 없어 수동 점검이 필요합니다."
        fi
    else
        if ps -ef | grep -v grep | grep -q exim; then
             VULNERABLE=1
             EVIDENCE="$EVIDENCE Exim 서비스가 중지되었으나 프로세스가 잔존합니다."
        fi
    fi
fi

# 결과 판단
if [ $VULNERABLE -eq 1 ]; then
    STATUS="FAIL"
    EVIDENCE="메일 서비스 버전이 미흡하거나 프로세스 상태가 비정상이어, 보안 취약점에 노출될 수 있는 위험이 있습니다. $EVIDENCE"
    GUIDE="이 항목은 시스템 전체 메일 서비스에 영향을 줄 수 있어 자동 조치 기능을 제공하지 않습니다. 관리자가 직접 각 메일 서비스에 맞는 최신 보안 패치를 적용하거나, 불필요시 'systemctl stop [서비스명] && systemctl disable [서비스명]'으로 비활성화하십시오. 패치 적용 전 반드시 영향도를 평가하고 변경관리 절차에 따라 단계적으로 적용하십시오."
    ACTION_RESULT="MANUAL_REQUIRED"
elif [ -z "$MAIL_SERVICE" ]; then
    STATUS="PASS"
    EVIDENCE="메일 서비스가 실행되지 않고 있습니다."
    GUIDE="KISA 보안 가이드라인을 준수하고 있습니다."
    ACTION_RESULT="SUCCESS"
fi


IMPACT_LEVEL="HIGH"
ACTION_IMPACT="메일 서비스 보안 패치 적용 시 시스템 및 서비스의 구성 변경 또는 서비스 재시작이 수반될 수 있어 운영 중 서비스 영향이 발생할 수 있습니다. 특히 운영 중단 가능성과 적용 범위를 사전에 평가한 뒤 변경관리 절차에 따라 단계적으로 적용해야 합니다."

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
