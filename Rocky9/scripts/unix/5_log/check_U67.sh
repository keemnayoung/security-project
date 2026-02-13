#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-67
# @Category    : 로그 관리
# @Platform    : Rocky Linux
# @Importance  : 중
# @Title       : 로그 디렉터리 소유자 및 권한 설정
# @Description : 로그에 대한 접근 통제 및 관리 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-67"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/var/log"
CHECK_COMMAND='[ -d /var/log ] && find /var/log -type f -print0 2>/dev/null | xargs -0 -I{} stat -c "%n owner=%U perm=%a" "{}" 2>/dev/null || echo "/var/log dir_not_found"'

REASON_LINE=""
DETAIL_CONTENT=""
FOUND_VULN="N"
VULN_LINES=""

# /var/log 존재 여부에 따른 분기
if [ -d "$TARGET_FILE" ]; then
    # 로그 파일들을 순회하며 소유자/권한 점검
    while IFS= read -r file; do
        OWNER=$(stat -c %U "$file" 2>/dev/null)
        PERM=$(stat -c %a "$file" 2>/dev/null)

        if [ "$OWNER" != "root" ] || [ "$PERM" -gt 644 ]; then
            STATUS="FAIL"
            FOUND_VULN="Y"
            VULN_LINES+="$file owner=$OWNER perm=$PERM"$'\n'
        fi
    done < <(find "$TARGET_FILE" -type f 2>/dev/null)
else
    STATUS="FAIL"
    FOUND_VULN="Y"
    VULN_LINES="/var/log dir_not_found"
fi

# 결과에 따른 평가 이유 및 detail 구성
if [ "$FOUND_VULN" = "Y" ]; then
    REASON_LINE="/var/log 디렉터리 내 일부 로그 파일의 소유자가 root가 아니거나 권한이 644 초과로 설정되어 비인가 사용자가 로그를 변조하거나 열람 범위를 확대할 위험이 있으므로 취약합니다. 해당 로그 파일의 소유자를 root로 변경하고 권한을 644 이하로 제한해야 합니다."
    DETAIL_CONTENT="$(printf "%s" "$VULN_LINES" | sed 's/[[:space:]]*$//')"
else
    STATUS="PASS"
    REASON_LINE="/var/log 디렉터리 내 로그 파일의 소유자가 root로 설정되어 있고 권한이 644 이하로 제한되어 로그 변조 위험이 없으므로 이 항목에 대한 보안 위협이 없습니다."
    DETAIL_CONTENT="all_log_files_ok"
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