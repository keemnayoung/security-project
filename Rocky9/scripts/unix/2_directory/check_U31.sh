#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-31
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 중
# @Title       : 홈디렉토리 소유자 및 권한 설정
# @Description : 홈 디렉토리의 소유자 외 타 사용자가 해당 홈 디렉토리를 수정할 수 없도록 제한 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================


# 기본 변수
ID="U-31"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/passwd"
CHECK_COMMAND='while IFS=: read -r u _ _ _ _ h _; do [ -d "$h" ] && stat -c "%n owner=%U perm=%a" "$h"; done < /etc/passwd'

DETAIL_CONTENT=""
REASON_LINE=""
VULN_LINES=""
FOUND_VULN="N"

# /etc/passwd를 순회하며 홈 디렉터리 소유자/권한 점검
while IFS=: read -r USER _ _ _ _ HOME _; do
    [ -d "$HOME" ] || continue

    OWNER=$(stat -c %U "$HOME" 2>/dev/null | tr -d '[:space:]')
    PERM=$(stat -c %a "$HOME" 2>/dev/null | tr -d '[:space:]')

    # other write 여부 확인 (마지막 자리)
    OTHER_DIGIT=$((PERM % 10))

    # 조건 위반 시 취약 목록에 추가 (소유자 불일치 또는 other write 존재)
    if [[ "$OWNER" != "$USER" || "$OTHER_DIGIT" -ge 2 ]]; then
        STATUS="FAIL"
        FOUND_VULN="Y"
        VULN_LINES+="${USER}:${HOME} owner=${OWNER} perm=${PERM}"$'\n'
    fi
done < /etc/passwd

# 결과에 따른 평가 이유 및 detail 구성
if [ "$FOUND_VULN" = "Y" ]; then
    REASON_LINE="사용자 홈 디렉터리의 소유자가 해당 계정과 다르거나 타 사용자(other) 쓰기 권한이 허용되어 홈 디렉터리 내 파일이 임의로 변조될 위험이 있으므로 취약합니다. 각 홈 디렉터리의 소유자를 해당 사용자로 변경하고 타 사용자 쓰기 권한을 제거해야 합니다."
    DETAIL_CONTENT="$(printf "%s" "$VULN_LINES" | sed 's/[[:space:]]*$//')"
else
    STATUS="PASS"
    REASON_LINE="사용자 홈 디렉터리의 소유자가 해당 계정으로 설정되어 있고 타 사용자(other) 쓰기 권한이 제거되어 있어 홈 디렉터리 변조 위험이 없으므로 이 항목에 대한 보안 위협이 없습니다."
    DETAIL_CONTENT="all_homes_ok"
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