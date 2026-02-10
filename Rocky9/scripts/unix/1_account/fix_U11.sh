#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 김나영
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID : U-11
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 하
# @Title : 사용자 shell 점검
# @Description : 로그인이 필요하지 않은 시스템 계정에 로그인 제한 쉘(/sbin/nologin) 부여
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-11"
CATEGORY="계정관리"
TITLE="사용자 shell 점검"
IMPORTANCE="하"
TARGET_FILE="/etc/passwd"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
ACTION_RESULT="FAIL"
STATUS="FAIL"
ACTION_LOG="N/A"

SYSTEM_ACCOUNTS=("daemon" "bin" "sys" "adm" "listen" "nobody" "nobody4" "noaccess" "diag" "operator" "games" "gopher")

if [ -f "$TARGET_FILE" ]; then
    # 1. 조치 전 백업 생성
    cp -p "$TARGET_FILE" "${TARGET_FILE}_bak_$TIMESTAMP"

    FIXED_ACCOUNTS=()
    
    # 2. 대상 계정 쉘 변경 수행
    for acc in "${SYSTEM_ACCOUNTS[@]}"; do
        if id "$acc" >/dev/null 2>&1; then
            CURRENT_SHELL=$(grep "^${acc}:" "$TARGET_FILE" | awk -F: '{print $NF}')
            
            if [[ "$CURRENT_SHELL" != "/bin/false" && "$CURRENT_SHELL" != "/sbin/nologin" ]]; then
                # 표준인 /sbin/nologin으로 변경 실행
                if usermod -s /sbin/nologin "$acc" >/dev/null 2>&1; then
                    FIXED_ACCOUNTS+=("$acc")
                fi
            fi
        fi
    done

    # 3. [핵심 검증] 조치 후 실제 파일 반영 여부 확인
    STILL_VULN=0
    for acc in "${SYSTEM_ACCOUNTS[@]}"; do
        if id "$acc" >/dev/null 2>&1; then
            CHECK_SHELL=$(grep "^${acc}:" "$TARGET_FILE" | awk -F: '{print $NF}')
            if [[ "$CHECK_SHELL" != "/bin/false" && "$CHECK_SHELL" != "/sbin/nologin" ]]; then
                ((STILL_VULN++))
            fi
        fi
    done

    # 4. 결과 판정
    if [ "$STILL_VULN" -eq 0 ]; then
        ACTION_RESULT="SUCCESS"
        STATUS="PASS"
        if [ ${#FIXED_ACCOUNTS[@]} -gt 0 ]; then
            ACTION_LOG="시스템 계정(${FIXED_ACCOUNTS[*]})을 통한 비정상적인 로그인을 차단하기 위해 쉘 환경을 /sbin/nologin으로 변경하고 조치를 완료하였습니다."
        else
            ACTION_LOG="모든 시스템 계정에 이미 로그인 제한 설정이 적용되어 있어 추가 설정 변경 없이 조치를 완료하였습니다."
        fi
    else
        ACTION_RESULT="PARTIAL_SUCCESS"
        STATUS="FAIL"
        ACTION_LOG="쉘 환경 변경 작업을 시도하였으나 일부 계정의 설정이 반영되지 않아, 관리자의 수동 점검 및 조치가 필요합니다."
    fi
else
    ACTION_RESULT="ERROR"
    STATUS="FAIL"
    ACTION_LOG="사용자 정보 설정 파일($TARGET_FILE)이 식별되지 않아 자동 조치 프로세스를 완료할 수 없습니다."
fi

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