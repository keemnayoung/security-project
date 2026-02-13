#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-27
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : $HOME/.rhosts, hosts.equiv 사용 금지
# @Description : $HOME/.rhosts 및 /etc/hosts.equiv 파일에 대해 적절한 소유자 및 접근 권한 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-27"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

CHECK_COMMAND='ps -ef | grep -E "rlogin|rsh|rexec" | grep -v grep; ( [ -f /etc/hosts.equiv ] && stat -c "%n owner=%U perm=%a" /etc/hosts.equiv ); find /home -name ".rhosts" -type f -print0 2>/dev/null | xargs -0 -I{} stat -c "%n owner=%U perm=%a" "{}" 2>/dev/null; grep -nE "^[[:space:]]*\\+" /etc/hosts.equiv /home/*/.rhosts 2>/dev/null'

TARGET_FILE="/etc/hosts.equiv /home/*/.rhosts"
DETAIL_CONTENT=""
REASON_LINE=""

VULN_LINES=""
FOUND_VULN="N"

# rlogin/rsh/rexec 서비스(프로세스) 사용 여부 확인
SERVICE_USED=$(ps -ef | grep -E 'rlogin|rsh|rexec' | grep -v grep)

# 홈 디렉터리 내 .rhosts 파일 수집
RHOSTS_FILES=$(find /home -name ".rhosts" -type f 2>/dev/null)

# 서비스 미사용이면 설정 파일이 존재하더라도 위험도는 낮지만, 정책상 파일/설정은 점검
if [ -z "$SERVICE_USED" ]; then
    SERVICE_LINE="service_used=NO"
else
    SERVICE_LINE="service_used=YES"
fi

# /etc/hosts.equiv + .rhosts 파일들을 순회하며 소유자/권한/'+' 설정 점검
for file in /etc/hosts.equiv $RHOSTS_FILES; do
    [ -f "$file" ] || continue

    OWNER=$(stat -c %U "$file" 2>/dev/null)
    PERM=$(stat -c %a "$file" 2>/dev/null)
    PLUS_EXIST=$(grep -nE '^[[:space:]]*\+' "$file" 2>/dev/null)

    # /etc/hosts.equiv 소유자 점검 (root만 허용)
    if [[ "$file" == "/etc/hosts.equiv" && "$OWNER" != "root" ]]; then
        FOUND_VULN="Y"
        VULN_LINES+="$file owner=$OWNER perm=$PERM (owner_must_be_root)"$'\n'
    fi

    # .rhosts 소유자 점검 (해당 사용자 또는 root 허용)
    if [[ "$file" != "/etc/hosts.equiv" ]]; then
        FILE_USER=$(basename "$(dirname "$file")")
        if [[ "$OWNER" != "$FILE_USER" && "$OWNER" != "root" ]]; then
            FOUND_VULN="Y"
            VULN_LINES+="$file owner=$OWNER perm=$PERM (owner_must_be_$FILE_USER_or_root)"$'\n'
        fi
    fi

    # 권한 점검 (600 이하)
    if [ "$PERM" -gt 600 ]; then
        FOUND_VULN="Y"
        VULN_LINES+="$file owner=$OWNER perm=$PERM (perm_must_be_600_or_less)"$'\n'
    fi

    # '+' 포함 여부 점검
    if [ -n "$PLUS_EXIST" ]; then
        FOUND_VULN="Y"
        VULN_LINES+="$file has_plus_entry (line: $(echo "$PLUS_EXIST" | head -n 1 | cut -d: -f1))"$'\n'
    fi
done

# 점검 결과에 따른 PASS/FAIL 및 reason/detail 구성
if [ "$FOUND_VULN" = "Y" ]; then
    STATUS="FAIL"
    REASON_LINE="/etc/hosts.equiv 또는 사용자 홈의 .rhosts 파일에서 소유자/권한 설정이 부적절하거나 '+' 허용 설정이 존재하여 인증 우회 및 무단 원격 접속으로 악용될 위험이 있으므로 취약합니다. 해당 파일의 소유자를 root 또는 해당 사용자로 설정하고 권한을 600 이하로 제한하며 '+' 허용 설정을 제거해야 합니다."
    DETAIL_CONTENT="$SERVICE_LINE"$'\n'"$VULN_LINES"
else
    STATUS="PASS"
    if [ -z "$SERVICE_USED" ]; then
        REASON_LINE="rlogin, rsh, rexec 서비스가 실행 중이지 않고 /etc/hosts.equiv 및 .rhosts 파일에 '+' 허용 설정이 없으며 소유자/권한이 안전하게 제한되어 있으므로 이 항목에 대한 보안 위협이 없습니다."
    else
        REASON_LINE="rlogin, rsh, rexec 서비스가 실행 중이더라도 /etc/hosts.equiv 및 .rhosts 파일에 '+' 허용 설정이 없고 소유자/권한이 안전하게 제한되어 있어 인증 우회 위험이 없으므로 이 항목에 대한 보안 위협이 없습니다."
    fi
    DETAIL_CONTENT="$SERVICE_LINE"$'\n'"all_files_ok"
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