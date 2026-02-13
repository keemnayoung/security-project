#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 김나영
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID : U-12
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 하
# @Title : 세션 종료 시간 설정
# @Description : 사용자 세션 방치로 인한 보안 사고 예방을 위해 TMOUT 설정 조치
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-12"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND=""
REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""

TARGET_FILE="/etc/profile"
CHECK_COMMAND="grep -nE '^[[:space:]]*TMOUT=' /etc/profile /etc/profile.d/*.sh /etc/bashrc 2>/dev/null"

MODIFIED=0
OVERRIDE_REMOVED=0

# 조치 수행(백업 없음)
if [ -f "$TARGET_FILE" ]; then
  # 1) /etc/profile.d, /etc/bashrc에 TMOUT override가 있으면 제거(필수)
  #    - 조치 후에도 override가 남으면 /etc/profile 설정이 무력화될 수 있음
  for f in /etc/profile.d/*.sh /etc/bashrc; do
    [ -e "$f" ] || continue
    if grep -qE '^[[:space:]]*TMOUT[[:space:]]*=' "$f" 2>/dev/null; then
      # TMOUT 라인만 제거(주석 여부와 무관하게 제거)
      sed -i '/^[[:space:]]*TMOUT[[:space:]]*=/Id' "$f" 2>/dev/null
      OVERRIDE_REMOVED=1
      MODIFIED=1
    fi
    # export TMOUT만 있는 파일도 의미는 있으나, 여기서는 TMOUT override 제거가 목적
    # export만 남겨도 /etc/profile에서 export를 넣으므로 문제 없음
  done

  # 2) /etc/profile: 기존 TMOUT 관련 라인 제거 후 표준 설정 추가
  if grep -qE 'TMOUT' "$TARGET_FILE" 2>/dev/null; then
    MODIFIED=1
  fi

  # TMOUT= / export TMOUT / typeset -x TMOUT 등 관련 라인 제거
  sed -i '/^[[:space:]]*TMOUT[[:space:]]*=/Id' "$TARGET_FILE" 2>/dev/null
  sed -i '/^[[:space:]]*export[[:space:]]\+TMOUT\b/Id' "$TARGET_FILE" 2>/dev/null
  sed -i '/^[[:space:]]*typeset[[:space:]]\+-x[[:space:]]\+TMOUT\b/Id' "$TARGET_FILE" 2>/dev/null

  {
    echo ""
    echo "TMOUT=600"
    echo "export TMOUT"
  } >> "$TARGET_FILE" 2>/dev/null

  # 3) 조치 후 상태 수집
  AFTER_TMOUT_LINES=$(grep -nEi '^[[:space:]]*TMOUT[[:space:]]*=' /etc/profile /etc/profile.d/*.sh /etc/bashrc 2>/dev/null | sed '/^[[:space:]]*$/d' | tail -n 10)
  AFTER_EXPORT_LINES=$(grep -nE '^[[:space:]]*(export[[:space:]]+TMOUT|typeset[[:space:]]+-x[[:space:]]+TMOUT)\b' /etc/profile /etc/profile.d/*.sh /etc/bashrc 2>/dev/null | grep -vE '^[[:space:]]*#' | tail -n 10)

  AFTER_VAL=$(grep -iE '^[[:space:]]*TMOUT[[:space:]]*=' /etc/profile /etc/profile.d/*.sh /etc/bashrc 2>/dev/null | grep -vE '^[[:space:]]*#' | tail -n 1 | sed 's/.*=[[:space:]]*//; s/[^0-9].*$//')
  [ -z "$AFTER_VAL" ] && AFTER_VAL="not_set"

  # detail에 핵심만 표시(필수 요약)
  DETAIL_CONTENT="tmout_lines=$AFTER_TMOUT_LINES"$'\n'"export_lines=$AFTER_EXPORT_LINES"

  # 4) 성공 판정: TMOUT=600 + export TMOUT 존재(필수)
  if [ "$AFTER_VAL" = "600" ] && [ -n "$AFTER_EXPORT_LINES" ]; then
    IS_SUCCESS=1
    if [ "$MODIFIED" -eq 1 ]; then
      if [ "$OVERRIDE_REMOVED" -eq 1 ]; then
        REASON_LINE="세션 종료 시간이 600초로 설정되었고(export TMOUT 포함), 기존 override 설정을 제거하여 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
      else
        REASON_LINE="세션 종료 시간이 600초로 설정되었고(export TMOUT 포함) 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
      fi
    else
      REASON_LINE="세션 종료 시간이 600초로 유지되고 있고(export TMOUT 포함) 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
    fi
  else
    IS_SUCCESS=0
    if [ "$AFTER_VAL" != "600" ]; then
      REASON_LINE="세션 종료 시간 설정을 수행했으나 TMOUT가 600초로 반영되지 않아 조치가 완료되지 않았습니다."
    else
      REASON_LINE="TMOUT 값은 600초로 설정되었으나 export TMOUT 적용이 확인되지 않아 조치가 완료되지 않았습니다."
    fi
  fi
else
  IS_SUCCESS=0
  REASON_LINE="조치 대상 파일(/etc/profile)이 존재하지 않아 조치가 완료되지 않았습니다."
  DETAIL_CONTENT=""
fi

# raw_evidence 구성
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

# DB 저장용 JSON 출력
echo ""
cat << EOF
{
    "item_code": "$ID",
    "action_date": "$ACTION_DATE",
    "is_success": $IS_SUCCESS,
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
}
EOF