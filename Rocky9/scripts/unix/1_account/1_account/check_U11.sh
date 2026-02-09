#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 김나영
# @Last Updated: 2026-02-09
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-11
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 하
# @Title : 사용자 shell 점검
# @Description : 로그인이 필요하지 않은 시스템 계정에 로그인 제한 쉘이 설정되어 있는지 점검
# @Criteria_Good : 로그인이 불필요한 계정에 nologin 또는 false 쉘이 설정된 경우
# @Criteria_Bad : 로그인이 불필요한 계정에 bash, sh 등 로그인 가능한 쉘이 설정된 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-11"
CATEGORY="계정관리"
TITLE="사용자 shell 점검"
IMPORTANCE="하"
TARGET_FILE="/etc/passwd"

STATUS="PASS"
EVIDENCE="N/A"
VULN_ACCOUNTS=()

# KISA 가이드 기반 점검 대상 시스템 계정 목록
SYSTEM_ACCOUNTS=("daemon" "bin" "sys" "adm" "listen" "nobody" "nobody4" "noaccess" "diag" "operator" "games" "gopher")

if [ -f "$TARGET_FILE" ]; then
    # 1. 파일 무결성 해시 추출
    FILE_HASH=$(sha256sum "$TARGET_FILE" | awk '{print $1}')
    
    # 2. 시스템 계정별 쉘 설정 전수 조사
    for acc in "${SYSTEM_ACCOUNTS[@]}"; do
        # 계정 라인 추출
        LINE=$(grep "^${acc}:" "$TARGET_FILE")
        if [ -n "$LINE" ]; then
            # 현재 설정된 쉘 추출
            CURRENT_SHELL=$(echo "$LINE" | awk -F: '{print $NF}')
            
            # /bin/false 또는 /sbin/nologin이 아닌 쉘 사용 시 취약으로 판별]; then"]
            if [[ "$CURRENT_SHELL" != "/bin/false" && "$CURRENT_SHELL" != "/sbin/nologin" ]]; then
                VULN_ACCOUNTS+=("$acc($CURRENT_SHELL)")
            fi
        fi
    done

    # 3. 결과 판정} -gt 0 ]; then"]
    if [ ${#VULN_ACCOUNTS[@]} -gt 0 ]; then
        STATUS="FAIL"
        EVIDENCE="로그인이 제한되어야 할 계정의 쉘 설정이 부적절합니다.[${VULN_ACCOUNTS[*]}]"
    else
        STATUS="PASS"
        EVIDENCE="모든 시스템 계정에 로그인 제한 쉘(/sbin/nologin 등)이 부여되어 있습니다."
    fi
else
    STATUS="FAIL"
    EVIDENCE="필수 설정 파일($TARGET_FILE) 누락"
    FILE_HASH="NOT_FOUND"
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
    "guide": "로그인이 불필요한 계정에 /sbin/nologin 또는 /bin/false 쉘을 부여하세요.",
    "file_hash": "$FILE_HASH",
    "target_file": "$TARGET_FILE",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF