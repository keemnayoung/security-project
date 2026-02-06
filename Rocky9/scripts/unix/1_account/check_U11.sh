#!/bin/bash
# [진단] U-11 사용자 shell 점검

# 1. 항목 정보 정의
ID="U-11"
CATEGORY="계정관리"
TITLE="사용자 shell 점검"
IMPORTANCE="하"
TARGET_FILE="/etc/passwd"

# 2. 진단 로직
STATUS="PASS"
EVIDENCE="N/A"
VULN_ACCOUNTS=()

# 점검 대상 시스템 계정 목록 (가이드 참고)
SYSTEM_ACCOUNTS=("daemon" "bin" "sys" "adm" "listen" "nobody" "nobody4" "noaccess" "diag" "operator" "games" "gopher")

if [ -f "$TARGET_FILE" ]; then
    # 파일 해시 추출
    FILE_HASH=$(sha256sum "$TARGET_FILE" | awk '{print $1}')
    
    for acc in "${SYSTEM_ACCOUNTS[@]}"; do
        # 계정이 존재하는지 확인
        LINE=$(grep "^${acc}:" "$TARGET_FILE")
        if [ ! -z "$LINE" ]; then
            # 현재 설정된 쉘 추출
            CURRENT_SHELL=$(echo "$LINE" | awk -F: '{print $NF}')
            
            # /bin/false 또는 /sbin/nologin이 아닌 경우 취약으로 판단
            if [[ "$CURRENT_SHELL" != "/bin/false" && "$CURRENT_SHELL" != "/sbin/nologin" ]]; then
                VULN_ACCOUNTS+=("$acc($CURRENT_SHELL)")
            fi
        fi
    done

    if [ ${#VULN_ACCOUNTS[@]} -gt 0 ]; then
        STATUS="FAIL"
        EVIDENCE="취약: 쉘 제한이 필요한 계정 발견 [${VULN_ACCOUNTS[*]}]"
    else
        STATUS="PASS"
        EVIDENCE="양호: 모든 시스템 계정에 로그인 제한 쉘이 부여되어 있습니다."
    fi
else
    STATUS="FAIL"
    EVIDENCE="오류: $TARGET_FILE 파일을 찾을 수 없습니다."
    FILE_HASH="NOT_FOUND"
fi

# 3. JSON 표준 출력
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
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF