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
CHECK_COMMAND='[ -d /var/log ] && (find /var/log -xdev -type f -print0 2>/dev/null | xargs -0 -I{} stat -c "%n owner=%U perm=%a" "{}" 2>/dev/null; echo "__STAT_END__") || echo "/var/log dir_not_found"'

REASON_LINE=""
DETAIL_CONTENT=""
FOUND_VULN="N"
VULN_LINES=""

# JSON escape
json_escape() {
  echo "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g'
}

if [ ! -d "$TARGET_FILE" ]; then
  STATUS="FAIL"
  FOUND_VULN="Y"
  VULN_LINES="/var/log dir_not_found"
else
  # stat 결과 수집(실패 포함)
  OUT="$(find "$TARGET_FILE" -xdev -type f -print0 2>/dev/null \
        | xargs -0 -I{} stat -c "%n owner=%U perm=%a" "{}" 2>/dev/null; echo "__STAT_END__")"

  # stat이 전부 실패해도 OUT엔 __STAT_END__만 남을 수 있음 → 그 경우 취약 처리
  if ! echo "$OUT" | grep -q "__STAT_END__"; then
    STATUS="FAIL"
    FOUND_VULN="Y"
    VULN_LINES="stat_failed_or_no_files"
  else
    # 취약 조건: owner!=root OR perm>644 OR owner/perm 확인 불가
    VULN_LINES="$(echo "$OUT" | sed '/^__STAT_END__$/d' \
      | awk '
        BEGIN{v=0}
        {
          line=$0
          owner=""; perm=""
          if (match(line, /owner=[^ ]+/)) owner=substr(line, RSTART+6, RLENGTH-6)
          if (match(line, /perm=[0-9]+/)) perm=substr(line, RSTART+5, RLENGTH-5)
          if (owner=="" || perm=="" || owner!="root" || perm+0>644) { print line; v=1 }
        }
      ')"

    if [ -n "$VULN_LINES" ]; then
      STATUS="FAIL"
      FOUND_VULN="Y"
    fi
  fi
fi

if [ "$FOUND_VULN" = "Y" ]; then
  REASON_LINE="/var/log 내 로그 파일에서 owner=root가 아니거나 perm=644 초과(또는 소유자/권한 확인 불가)로 설정되어 있어 취약합니다. 조치: 해당 파일에 chown root <파일>; chmod 644 <파일> 적용"
  DETAIL_CONTENT="$(printf "%s" "$VULN_LINES" | sed 's/[[:space:]]*$//')"
else
  REASON_LINE="/var/log 내 로그 파일이 owner=root로 설정되어 있고 perm=644 이하로 제한되어 있어 이 항목에 대한 보안 위협이 없습니다."
  # PASS에서도 “어디서 어떻게”가 보이도록 샘플/요약을 남김
  OK_SUMMARY="$(find "$TARGET_FILE" -xdev -type f 2>/dev/null | wc -l | awk '{print "checked_files=" $1 ", all owner=root perm<=644"}')"
  DETAIL_CONTENT="$OK_SUMMARY"
fi

# raw_evidence (첫 줄: REASON_LINE / 다음 줄: DETAIL_CONTENT)
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