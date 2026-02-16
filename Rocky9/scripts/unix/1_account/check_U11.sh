#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.0
# @Author: 김나영
# @Last Updated: 2026-02-13
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


# 기본 변수
ID="U-11"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/passwd"
CHECK_COMMAND='[ -f /etc/passwd ] && egrep "^(daemon|bin|sys|adm|listen|nobody|nobody4|noaccess|diag|operator|games|gopher):" /etc/passwd || echo "passwd_not_found_or_no_targets"'

REASON_LINE=""
DETAIL_CONTENT=""

VULN_ACCOUNTS=()

# 점검 대상 시스템 계정 목록
SYSTEM_ACCOUNTS=("daemon" "bin" "sys" "adm" "listen" "nobody" "nobody4" "noaccess" "diag" "operator" "games" "gopher")

# (추가) 허용 로그인 제한 쉘 목록: Rocky/RHEL 계열에서 /usr/sbin/nologin 경로도 고려
ALLOWED_SHELLS=("/bin/false" "/sbin/nologin" "/usr/sbin/nologin")

is_allowed_shell() {
    local shell="$1"
    for a in "${ALLOWED_SHELLS[@]}"; do
        [ "$shell" = "$a" ] && return 0
    done
    return 1
}

# 파일 존재 여부에 따른 분기
if [ -f "$TARGET_FILE" ]; then
    # 시스템 계정별 쉘 설정 전수 조사(반복문)
    for acc in "${SYSTEM_ACCOUNTS[@]}"; do
        LINE=$(grep "^${acc}:" "$TARGET_FILE" 2>/dev/null)

        if [ -n "$LINE" ]; then
            CURRENT_SHELL=$(echo "$LINE" | awk -F: '{print $NF}')

            # (개선) 허용 쉘 목록에 없으면 취약
            if ! is_allowed_shell "$CURRENT_SHELL"; then
                VULN_ACCOUNTS+=("$acc shell=$CURRENT_SHELL")
            fi
        fi
    done

    # 결과에 따른 PASS/FAIL 결정
    if [ ${#VULN_ACCOUNTS[@]} -gt 0 ]; then
        STATUS="FAIL"
        REASON_LINE="로그인이 불필요한 시스템 계정에 실행 가능한 쉘이 부여되어 해당 계정을 통한 비정상 로그인 및 권한 오남용 가능성이 있으므로 취약합니다. 해당 계정의 쉘을 /sbin/nologin 또는 /bin/false로 변경해야 합니다."
        DETAIL_CONTENT="$(printf "%s\n" "${VULN_ACCOUNTS[@]}")"
    else
        STATUS="PASS"
        REASON_LINE="로그인이 불필요한 시스템 계정에 로그인 제한 쉘(/sbin/nologin 또는 /bin/false)이 적용되어 비정상 로그인이 차단되므로 이 항목에 대한 보안 위협이 없습니다."
        DETAIL_CONTENT="all_system_accounts_have_nologin_shell"
    fi
else
    STATUS="FAIL"
    REASON_LINE="사용자 정보 파일(/etc/passwd)이 존재하지 않아 시스템 계정의 쉘 설정을 점검할 수 없으므로 취약합니다. /etc/passwd 파일을 복구한 뒤 시스템 계정에 로그인 제한 쉘이 적용되어 있는지 점검해야 합니다."
    DETAIL_CONTENT="passwd_not_found"
fi

# raw_evidence 구성 (첫 줄: 평가 이유 / 다음 줄부터: 현재 설정값)
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

# JSON escape 처리 (따옴표, 줄바꿈)
RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/"/\\"/g' \
  | sed ':a;N;$!ba;s/\n/\\n/g')

# scan_history 저장용 JSON 출력
echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF