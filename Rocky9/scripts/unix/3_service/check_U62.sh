#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-07
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-62
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 하
# @Title : 로그인 시 경고 메시지 설정
# @Description : 서버 및 서비스에 로그온 시 불필요한 정보 차단 설정 및 불법적인 사용에 대한 경고 메시지 출력 여부 점검
# @Criteria_Good : 서버 및 Telnet, FTP, SMTP, DNS 서비스에 로그온 시 경고 메시지가 설정된 경우
# @Criteria_Bad : 서버 및 Telnet, FTP, SMTP, DNS 서비스에 로그온 시 경고 메시지가 설정되어 있지 않은 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-62 로그인 시 경고 메시지 설정


# 기본 변수
ID="U-62"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE="/etc/issue, /etc/issue.net, /etc/motd, /etc/ssh/sshd_config"
CHECK_COMMAND='ls -l /etc/issue /etc/issue.net /etc/motd 2>/dev/null; wc -c /etc/issue /etc/issue.net /etc/motd 2>/dev/null; grep -nEi "^[[:space:]]*Banner[[:space:]]+" /etc/ssh/sshd_config 2>/dev/null; systemctl is-active sshd 2>/dev/null'

VULNERABLE=0
DETAIL_LINES=""

append_detail() {
  local line="$1"
  [ -z "$line" ] && return 0
  if [ -z "$DETAIL_LINES" ]; then
    DETAIL_LINES="$line"
  else
    DETAIL_LINES="${DETAIL_LINES}\n$line"
  fi
}

# 파일에 "실질 내용"이 있는지(주석/공백만 있는 경우는 없음으로 간주)
file_has_effective_content() {
  local f="$1"
  [ -f "$f" ] || return 1
  # 공백만/빈 줄만이면 제외, 주석만 있는 것도 제외(경고 문구 목적상 실문구가 필요)
  local c
  c="$(grep -Ev '^[[:space:]]*$|^[[:space:]]*#' "$f" 2>/dev/null | tr -d '[:space:]')"
  [ -n "$c" ]
}

# --- 1) 로컬 로그인 배너(/etc/issue, /etc/motd) ---
ISSUE_OK=0
MOTD_OK=0
ISSUENET_OK=0
SSH_BANNER_OK=0

if [ -f "/etc/issue" ]; then
  if file_has_effective_content "/etc/issue"; then
    ISSUE_OK=1
    append_detail "[check] /etc/issue=HAS_WARNING_MESSAGE"
  else
    VULNERABLE=1
    append_detail "[check] /etc/issue=EMPTY_OR_COMMENT_ONLY"
  fi
else
  # 파일이 없어도 환경에 따라 그럴 수 있으나, 경고 메시지 목적상 확인 필요로 취약 처리
  VULNERABLE=1
  append_detail "[check] /etc/issue=NOT_FOUND"
fi

if [ -f "/etc/motd" ]; then
  if file_has_effective_content "/etc/motd"; then
    MOTD_OK=1
    append_detail "[check] /etc/motd=HAS_WARNING_MESSAGE"
  else
    VULNERABLE=1
    append_detail "[check] /etc/motd=EMPTY_OR_COMMENT_ONLY"
  fi
else
  VULNERABLE=1
  append_detail "[check] /etc/motd=NOT_FOUND"
fi

# --- 2) 원격(Telnet/SSH 등) 배너(/etc/issue.net) ---
# telnet 미사용이어도 SSH Banner에서 /etc/issue.net을 참조하는 경우가 많아 같이 점검
if [ -f "/etc/issue.net" ]; then
  if file_has_effective_content "/etc/issue.net"; then
    ISSUENET_OK=1
    append_detail "[check] /etc/issue.net=HAS_WARNING_MESSAGE"
  else
    VULNERABLE=1
    append_detail "[check] /etc/issue.net=EMPTY_OR_COMMENT_ONLY"
  fi
else
  # 시스템에 따라 없을 수 있으나, SSH Banner 연동에서 많이 쓰므로 "확인 필요"로 취약 처리
  VULNERABLE=1
  append_detail "[check] /etc/issue.net=NOT_FOUND"
fi

# --- 3) SSH Banner 설정(/etc/ssh/sshd_config Banner) ---
SSHD_ACTIVE="N"
if systemctl is-active --quiet sshd 2>/dev/null; then
  SSHD_ACTIVE="Y"
fi
append_detail "[systemd] sshd_active=$SSHD_ACTIVE"

if [ -f "/etc/ssh/sshd_config" ]; then
  # 주석 제외 Banner 라인
  BANNER_LINE="$(grep -Ev '^[[:space:]]*#|^[[:space:]]*$' /etc/ssh/sshd_config 2>/dev/null | grep -Ei '^[[:space:]]*Banner[[:space:]]+' | tail -n 1)"
  if [ -n "$BANNER_LINE" ]; then
    # Banner none이면 사실상 미설정 취급
    if echo "$BANNER_LINE" | grep -qiE '^[[:space:]]*Banner[[:space:]]+none([[:space:]]|$)'; then
      VULNERABLE=1
      append_detail "[check] sshd_config Banner=none (NOT_SET)"
    else
      SSH_BANNER_OK=1
      append_detail "[check] sshd_config $BANNER_LINE"
    fi
  else
    VULNERABLE=1
    append_detail "[check] sshd_config Banner=NOT_FOUND"
  fi
else
  VULNERABLE=1
  append_detail "[check] /etc/ssh/sshd_config=NOT_FOUND"
fi

# --- 4) 최종 판정 ---
# “로그온 경고 메시지” 핵심은 /etc/issue, /etc/motd, (원격용) /etc/issue.net, SSH Banner 중
# 최소한 로컬(/etc/issue 또는 /etc/motd) + 원격(SSH Banner 또는 /etc/issue.net) 축이 갖춰져야 의미가 있으므로 보수적으로 판단
LOCAL_OK=0
REMOTE_OK=0

[ "$ISSUE_OK" -eq 1 ] || [ "$MOTD_OK" -eq 1 ] && LOCAL_OK=1
[ "$SSH_BANNER_OK" -eq 1 ] || [ "$ISSUENET_OK" -eq 1 ] && REMOTE_OK=1

if [ "$LOCAL_OK" -eq 1 ] && [ "$REMOTE_OK" -eq 1 ] && [ "$VULNERABLE" -eq 0 ]; then
  STATUS="PASS"
  REASON_LINE="로그온 경고 메시지(/etc/issue, /etc/motd) 및 원격 접속 배너(SSH Banner 또는 /etc/issue.net)가 설정되어 있어 이 항목에 대한 보안 위협이 없습니다."
else
  STATUS="FAIL"
  REASON_LINE="로그온 경고 메시지 설정이 미흡하여 불법 접속에 대한 경고가 표시되지 않거나 일부 경로에서 경고가 누락될 수 있으므로 취약합니다. /etc/issue, /etc/motd, /etc/issue.net 내용을 설정하고 SSH Banner를 적용해야 합니다."
fi

DETAIL_CONTENT="$DETAIL_LINES"
[ -z "$DETAIL_CONTENT" ] && DETAIL_CONTENT="none"

# raw_evidence 구성 (첫 줄: 평가 이유 / 다음 줄: 상세 증적)
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

# JSON 저장을 위한 escape 처리 (따옴표, 줄바꿈)
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