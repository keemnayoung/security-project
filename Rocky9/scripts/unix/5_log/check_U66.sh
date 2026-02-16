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

# 점검 대상(존재하는 것만 사용)
CONFIG_CANDIDATES=(/etc/rsyslog.conf /etc/rsyslog.d/*.conf /etc/rsyslog.d/default.conf)
LOG_FILES=(/var/log/messages /var/log/secure /var/log/maillog /var/log/cron)

TARGET_FILE="/etc/rsyslog.conf /etc/rsyslog.d/*.conf"
CHECK_COMMAND='(command -v systemctl >/dev/null 2>&1 && systemctl is-active rsyslog 2>/dev/null || true); (pgrep -a rsyslogd 2>/dev/null || true); for f in /etc/rsyslog.conf /etc/rsyslog.d/*.conf /etc/rsyslog.d/default.conf; do [ -f "$f" ] && echo "[FILE] $f" && grep -nEv "^[[:space:]]*#|^[[:space:]]*$" "$f" | head -n 200; done; for l in /var/log/messages /var/log/secure /var/log/maillog /var/log/cron; do [ -f "$l" ] && echo "[LOGFILE] $l exists" || echo "[LOGFILE] $l missing"; done'

REASON_LINE=""
DETAIL_CONTENT=""
DETAIL_LINES=""

# JSON escape
json_escape() {
  echo "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g'
}

# 1) 실제 존재하는 설정 파일 수집
CONF_FILES=()
for f in "${CONFIG_CANDIDATES[@]}"; do
  [ -f "$f" ] && CONF_FILES+=("$f")
done

# 2) rsyslog 동작 여부(최소)
RSYSLOG_RUNNING="N"
if command -v systemctl >/dev/null 2>&1; then
  systemctl is-active --quiet rsyslog 2>/dev/null && RSYSLOG_RUNNING="Y"
fi
pgrep -x rsyslogd >/dev/null 2>&1 && RSYSLOG_RUNNING="Y"

# 3) 필수 정책(가이드 표 기준) 확인: “어느 파일/몇 번째 줄에서” 찾았는지 기록
#    형식: ID|정규식|설명(사람이 읽기용)
REQUIRED=$(
cat <<'EOF'
P1|\*\.info;mail\.none;authpriv\.none;cron\.none[[:space:]]+/var/log/messages|*.info;mail.none;authpriv.none;cron.none -> /var/log/messages
P2|auth,authpriv\.\*[[:space:]]+/var/log/secure|auth,authpriv.* -> /var/log/secure
P3|mail\.\*[[:space:]]+/var/log/maillog|mail.* -> /var/log/maillog
P4|cron\.\*[[:space:]]+/var/log/cron|cron.* -> /var/log/cron
P5|\*\.alert[[:space:]]+/dev/console|*.alert -> /dev/console
P6|\*\.emerg[[:space:]]+\*|*.emerg -> *
EOF
)

MISSING=""
FOUND_SUMMARY=""

if [ "${#CONF_FILES[@]}" -eq 0 ]; then
  STATUS="FAIL"
  DETAIL_LINES+="rsyslog_config_not_found\n"
else
  while IFS='|' read -r key re desc; do
    [ -z "${key:-}" ] && continue
    hit="N"
    for cf in "${CONF_FILES[@]}"; do
      # 주석/공백 라인 제외하고 매칭되는 “첫 1개”만 뽑아도 충분(필수만)
      m=$(grep -nE "$re" "$cf" 2>/dev/null | head -n 1 || true)
      if [ -n "$m" ]; then
        hit="Y"
        FOUND_SUMMARY+="$key found_in=$cf:$m\n"
        break
      fi
    done
    [ "$hit" = "N" ] && MISSING+="$key missing_policy=$desc\n"
  done <<< "$REQUIRED"
fi

# 4) 로그 파일 존재 확인(가이드 표의 주요 로그파일)
for lf in "${LOG_FILES[@]}"; do
  [ -f "$lf" ] || DETAIL_LINES+="logfile_missing=$lf\n"
done

# 5) 취약 판정
if [ "$RSYSLOG_RUNNING" != "Y" ]; then
  STATUS="FAIL"
  DETAIL_LINES+="rsyslog_service_not_running\n"
fi
[ -n "$MISSING" ] && STATUS="FAIL" && DETAIL_LINES+="$MISSING"

# 6) reason/detail 구성 (요청 문구 + 취약 시 간단 조치 안내 포함)
if [ "$STATUS" = "PASS" ]; then
  REASON_LINE="(/etc/rsyslog.conf 또는 /etc/rsyslog.d/*.conf)에 가이드 기준 로깅 규칙이 설정되어 있고(/var/log/messages, /var/log/secure, /var/log/maillog, /var/log/cron 생성 확인), 이 항목에 대한 보안 위협이 없습니다."
  DETAIL_CONTENT="$(printf "%b" "$FOUND_SUMMARY" | sed 's/[[:space:]]*$//')"
else
  REASON_LINE="(/etc/rsyslog.conf 또는 /etc/rsyslog.d/*.conf)에서 가이드 기준 로깅 규칙이 누락되었거나(rs y slog 서비스 미동작/주요 로그 파일 미생성 포함) 정책에 따라 로그가 충분히 수집되지 않아 취약합니다. 조치: rsyslog 설정에 가이드 표의 규칙을 추가/수정하고 systemctl restart rsyslog 로 재시작 후 로그 파일 생성 여부를 확인하세요."
  DETAIL_CONTENT="$(printf "%b" "$DETAIL_LINES" | sed 's/[[:space:]]*$//')"
fi

# raw_evidence (첫 줄: 평가 이유 / 다음 줄부터: 현재 설정값)
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE
$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

RAW_EVIDENCE_ESCAPED="$(json_escape "$RAW_EVIDENCE")"

echo ""
cat <<EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF