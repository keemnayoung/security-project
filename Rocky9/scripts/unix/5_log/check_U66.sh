#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-66
# @Category    : 로그 관리
# @Platform    : Rocky Linux
# @Importance  : 중
# @Title       : 정책에 따른 시스템 로깅 설정
# @Description : 내부 정책에 따른 시스템 로깅 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-66"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/rsyslog.conf /etc/rsyslog.d/default.conf"
CHECK_COMMAND='for f in /etc/rsyslog.conf /etc/rsyslog.d/default.conf; do [ -f "$f" ] && echo "[FILE] $f" && egrep -n "^[[:space:]]*(\*\.info;mail\.none;authpriv\.none;cron\.none[[:space:]]+/var/log/messages|auth,authpriv\.\*[[:space:]]+/var/log/secure|mail\.\*[[:space:]]+/var/log/maillog|cron\.\*[[:space:]]+/var/log/cron|\*\.alert[[:space:]]+/dev/console|\*\.emerg[[:space:]]+\*)" "$f"; done; for l in /var/log/messages /var/log/secure /var/log/maillog /var/log/cron; do [ -f "$l" ] && echo "[LOGFILE] $l exists" || echo "[LOGFILE] $l missing"; done'

REASON_LINE=""
DETAIL_CONTENT=""
FOUND_VULN="N"
DETAIL_LINES=""

REQUIRED_POLICIES=(
    "*.info;mail.none;authpriv.none;cron.none /var/log/messages"
    "auth,authpriv.* /var/log/secure"
    "mail.* /var/log/maillog"
    "cron.* /var/log/cron"
    "*.alert /dev/console"
    "*.emerg *"
)

CONFIG_FOUND="N"
POLICY_OK="Y"

# 설정 파일 존재 및 정책 존재 여부 점검
for FILE in /etc/rsyslog.conf /etc/rsyslog.d/default.conf; do
    if [ -f "$FILE" ]; then
        CONFIG_FOUND="Y"

        for POLICY in "${REQUIRED_POLICIES[@]}"; do
            # 정규식 특수문자 최소 처리(* 만 이스케이프). 기존 로직 의도 유지
            if ! grep -E "^[[:space:]]*${POLICY//\*/\\*}" "$FILE" >/dev/null 2>&1; then
                POLICY_OK="N"
                FOUND_VULN="Y"
                DETAIL_LINES+="$FILE missing_policy=$POLICY"$'\n'
            fi
        done
    fi
done

if [ "$CONFIG_FOUND" = "N" ]; then
    STATUS="FAIL"
    FOUND_VULN="Y"
    DETAIL_LINES+="rsyslog_config_not_found"$'\n'
fi

# 로그 파일 존재 여부 점검
LOG_FILES=(
    "/var/log/messages"
    "/var/log/secure"
    "/var/log/maillog"
    "/var/log/cron"
)

for LOG in "${LOG_FILES[@]}"; do
    if [ ! -f "$LOG" ]; then
        STATUS="FAIL"
        FOUND_VULN="Y"
        DETAIL_LINES+="logfile_missing=$LOG"$'\n'
    fi
done

# 결과에 따른 PASS/FAIL 및 reason/detail 구성
if [ "$FOUND_VULN" = "Y" ]; then
    STATUS="FAIL"
    REASON_LINE="rsyslog 설정 파일에 필수 로그 기록 정책이 누락되었거나 주요 로그 파일이 생성되지 않아 보안 감사 및 사고 분석에 필요한 로그가 충분히 수집되지 않을 위험이 있으므로 취약합니다. rsyslog 설정 파일에 내부 정책에 따른 로깅 규칙을 반영하고 로그 파일이 정상 생성되도록 설정해야 합니다."
    DETAIL_CONTENT="$(printf "%s" "$DETAIL_LINES" | sed 's/[[:space:]]*$//')"
else
    STATUS="PASS"
    REASON_LINE="rsyslog 설정 파일에 필수 로그 기록 정책이 설정되어 있고 주요 로그 파일이 존재하여 보안 감사 및 사고 분석에 필요한 로그가 정상적으로 수집되므로 이 항목에 대한 보안 위협이 없습니다."
    DETAIL_CONTENT="all_required_policies_present\nall_log_files_exist"
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