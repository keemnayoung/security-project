#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-07
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-63
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : sudo 명령어 접근 관리
# @Description : /etc/sudoers 파일 권한 적절성 여부 점검
# @Criteria_Good :  /etc/sudoers 파일 소유자가 root이고, 파일 권한이 640인 경우
# @Criteria_Bad : /etc/sudoers 파일 소유자가 root가 아니거나, 파일 권한이 640을 초과하는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-63 sudo 명령어 접근 관리

# 기본 변수
ID="U-63"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE="/etc/sudoers"
CHECK_COMMAND='stat -c "%U %G %a %n" /etc/sudoers 2>/dev/null; ls -l /etc/sudoers.d 2>/dev/null; find /etc/sudoers.d -maxdepth 1 -type f -print -exec stat -c "%U %G %a %n" {} \; 2>/dev/null'

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

# 1) /etc/sudoers 존재 여부
if [ ! -f "/etc/sudoers" ]; then
  STATUS="PASS"
  REASON_LINE="/etc/sudoers 파일이 존재하지 않아 sudo 설정 파일을 점검할 수 없습니다. (sudo 미설치 또는 별도 정책 적용 환경일 수 있으므로 확인이 필요합니다.)"
  DETAIL_CONTENT="file_not_found"
else
  # 2) /etc/sudoers 소유자/권한 점검
  OWNER="$(stat -c '%U' /etc/sudoers 2>/dev/null || echo "unknown")"
  GROUP="$(stat -c '%G' /etc/sudoers 2>/dev/null || echo "unknown")"
  PERM_STR="$(stat -c '%a' /etc/sudoers 2>/dev/null || echo "unknown")"

  append_detail "[check] /etc/sudoers owner=$OWNER group=$GROUP perm=$PERM_STR"

  # 권한 파싱 실패 방어
  if ! echo "$PERM_STR" | grep -Eq '^[0-7]{3,4}$'; then
    VULNERABLE=1
    append_detail "[warn] permission_parse_failed perm=$PERM_STR"
  else
    PERM_DEC=$((8#$PERM_STR))

    OWNER_OK=0
    PERM_OK=0

    # 소유자 root
    [ "$OWNER" = "root" ] && OWNER_OK=1

    # 기준: 가이드에서 흔히 440(또는 400) 권장.
    # 기존 스크립트는 640 기준이었지만, sudoers는 일반적으로 group/other write 금지 + other read 금지가 핵심이라
    # 보수적으로 "group/other 쓰기 금지 + other 읽기 금지"를 필수로 본다.
    # - o+r(0004) 허용 시: 일반 사용자가 sudo 정책을 읽을 수 있어 정보 노출 소지가 있어 취약으로 판단
    # - g+w(0020), o+w(0002) 허용 시: 즉시 취약
    # - 0440, 0400, 0640(조직 정책) 등은 환경에 따라 다를 수 있어, '쓰기 금지/other read 금지' 충족이면 PASS
    WRITE_OK=0
    OTHER_READ_OK=0

    # g+w(020) + o+w(002) 금지
    [ $((PERM_DEC & 022)) -eq 0 ] && WRITE_OK=1
    # other read(004) 금지
    [ $((PERM_DEC & 004)) -eq 0 ] && OTHER_READ_OK=1

    if [ "$WRITE_OK" -eq 1 ] && [ "$OTHER_READ_OK" -eq 1 ]; then
      PERM_OK=1
    fi

    append_detail "[eval] owner_ok=$OWNER_OK write_ok=$WRITE_OK other_read_ok=$OTHER_READ_OK"

    if [ "$OWNER_OK" -ne 1 ] || [ "$PERM_OK" -ne 1 ]; then
      VULNERABLE=1
    fi
  fi

  # 3) /etc/sudoers.d 존재 시 함께 점검(실무에서 여기로 권한 우회되는 경우가 많아서 필수에 가깝게 처리)
  if [ -d "/etc/sudoers.d" ]; then
    FOUND_ANY=0
    while IFS= read -r f; do
      [ -z "$f" ] && continue
      FOUND_ANY=1
      o="$(stat -c '%U' "$f" 2>/dev/null || echo "unknown")"
      g="$(stat -c '%G' "$f" 2>/dev/null || echo "unknown")"
      p="$(stat -c '%a' "$f" 2>/dev/null || echo "unknown")"
      append_detail "[check] $f owner=$o group=$g perm=$p"

      if [ "$o" != "root" ]; then
        VULNERABLE=1
        append_detail "[risk] $f owner_is_not_root"
      fi

      if echo "$p" | grep -Eq '^[0-7]{3,4}$'; then
        pd=$((8#$p))
        # g+w/o+w 금지, other read 금지 (sudoers.d도 동일 기준 적용)
        if [ $((pd & 022)) -ne 0 ]; then
          VULNERABLE=1
          append_detail "[risk] $f has_group_or_other_write"
        fi
        if [ $((pd & 004)) -ne 0 ]; then
          VULNERABLE=1
          append_detail "[risk] $f has_other_read"
        fi
      else
        VULNERABLE=1
        append_detail "[warn] $f permission_parse_failed perm=$p"
      fi
    done < <(find /etc/sudoers.d -maxdepth 1 -type f 2>/dev/null)

    if [ "$FOUND_ANY" -eq 0 ]; then
      append_detail "[info] /etc/sudoers.d has no files"
    else
      # 증적용 target_file에 sudoers.d도 포함
      TARGET_FILE="/etc/sudoers, /etc/sudoers.d/*"
    fi
  else
    append_detail "[info] /etc/sudoers.d not found"
  fi

  # 4) 최종 판정/사유
  if [ "$VULNERABLE" -eq 1 ]; then
    STATUS="FAIL"
    REASON_LINE="sudo 설정 파일(/etc/sudoers 또는 /etc/sudoers.d)의 소유자/권한 설정이 기준에 부합하지 않아 비인가 사용자가 sudo 정책을 열람하거나 변경할 위험이 있으므로 취약합니다. 소유자를 root로 설정하고, 권한은 쓰기 금지 및 other 읽기 금지를 포함하여 최소 권한으로 설정해야 합니다."
  else
    STATUS="PASS"
    REASON_LINE="sudo 설정 파일(/etc/sudoers 및 /etc/sudoers.d)의 소유자/권한이 적절히 설정되어 있어 이 항목에 대한 보안 위협이 없습니다."
  fi

  DETAIL_CONTENT="$DETAIL_LINES"
  [ -z "$DETAIL_CONTENT" ] && DETAIL_CONTENT="none"
fi

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