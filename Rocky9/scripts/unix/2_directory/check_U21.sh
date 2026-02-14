#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.2
# @Author: 권순형
# @Last Updated: 2026-02-10
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-21
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : /etc/(r)syslog.conf 파일 소유자 및 권한 설정
# @Description : /etc/(r)syslog.conf 파일 권한 적절성 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-21"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/syslog.conf /etc/rsyslog.conf"
CHECK_COMMAND='for f in /etc/syslog.conf /etc/rsyslog.conf; do if [ -f "$f" ]; then stat -c "%n owner=%U perm=%a" "$f"; else echo "$f not_found"; fi; done'

LOG_FILES=("/etc/syslog.conf" "/etc/rsyslog.conf")
TARGET_FILES=()
FOUND_ANY="N"
FOUND_VULN="N"
VULN_LINES=""

REASON_LINE=""
DETAIL_CONTENT=""

# 대상 파일을 순회하며 소유자/권한 점검
for FILE in "${LOG_FILES[@]}"; do
    if [ -f "$FILE" ]; then
        FOUND_ANY="Y"
        TARGET_FILES+=("$FILE")

        OWNER=$(stat -c %U "$FILE" 2>/dev/null)
        PERM=$(stat -c %a "$FILE" 2>/dev/null)

        if [[ "$OWNER" =~ ^(root|bin|sys)$ ]] && [ "$PERM" -le 640 ]; then
            :
        else
            STATUS="FAIL"
            FOUND_VULN="Y"
            VULN_LINES+="$FILE owner=$OWNER perm=$PERM"$'\n'
        fi
    fi
done

# 대상 파일이 하나도 없으면: 가이드상 필수 취약 조건이 아니므로 PASS(점검대상 없음) 처리
if [ "$FOUND_ANY" = "N" ]; then
    STATUS="PASS"
    REASON_LINE="syslog 설정 파일(/etc/syslog.conf, /etc/rsyslog.conf)이 시스템에 존재하지 않습니다. 이는 rsyslog/syslog 구성이 다른 경로로 관리되거나 서비스가 미사용인 경우일 수 있으므로 본 항목은 점검대상 없음으로 판단합니다. (해당 서비스 사용 시 설정 파일 존재 여부 및 소유자(root/bin/sys), 권한 640 이하를 확인 필요)"
    DETAIL_CONTENT="file_not_found"
    TARGET_FILE=""
else
    # target_file은 실제 존재하는 파일만 공백으로 연결
    TARGET_FILE=$(printf "%s " "${TARGET_FILES[@]}" | sed 's/[[:space:]]*$//')

    # 취약/양호에 따른 평가 이유 및 detail 구성
    if [ "$FOUND_VULN" = "Y" ]; then
        REASON_LINE="/etc/(r)syslog.conf 파일의 소유자가 root/bin/sys가 아니거나 권한이 640 초과로 설정되어 비인가 사용자가 로그 설정을 변경할 위험이 있으므로 취약합니다. 소유자를 root(또는 bin/sys)로 변경하고 권한을 640 이하로 설정해야 합니다."
        DETAIL_CONTENT="$(printf "%s" "$VULN_LINES" | sed 's/[[:space:]]*$//')"
    else
        STATUS="PASS"
        REASON_LINE="/etc/(r)syslog.conf 파일의 소유자가 root/bin/sys로 설정되어 있고 권한이 640 이하로 제한되어 로그 설정 파일의 임의 수정 위험이 없으므로 양호합니다."
        DETAIL_CONTENT="all_files_ok"
    fi
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
