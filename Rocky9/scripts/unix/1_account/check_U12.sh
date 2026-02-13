#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 김나영
# @Last Updated: 2026-02-09
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-12
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 하
# @Title : 세션 종료 시간 설정
# @Description : 사용자 셸에 대한 환경 설정 파일에서 세션 종료 시간 설정 여부 점검
# @Criteria_Good : 세션 종료 시간이 600초(10분) 이하로 설정되어 있는 경우
# @Criteria_Bad : 세션 종료 시간이 설정되지 않았거나 600초를 초과하는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================
# 기본 변수
ID="U-12"
STATUS="FAIL"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

# 점검 대상(가이드의 "사용자 쉘 환경설정 파일" 범주를 최소로 반영)
TARGET_FILES=(
  "/etc/profile"
  "/etc/profile.d/*.sh"
  "/etc/bashrc"
)

# (참고) 가이드 예시 커맨드 성격 유지용
TARGET_FILE="/etc/profile"
CHECK_COMMAND='grep -nEi "^[[:space:]]*TMOUT[[:space:]]*=" /etc/profile /etc/profile.d/*.sh /etc/bashrc 2>/dev/null | grep -nEv "^[[:space:]]*#" | head -n 5 || echo "tmout_not_found"'

REASON_LINE=""
DETAIL_CONTENT=""

TMOUT_VAL="not_set"
TMOUT_FOUND_LINE=""
EXPORT_FOUND="no"

# --------------------------------------------
# 1) TMOUT / export TMOUT 확인 (sh/ksh/bash)
#    - 여러 파일에 설정될 수 있으므로 "마지막으로 발견된 TMOUT"를 유효값으로 간주
#    - export TMOUT는 어디서든 한 번이라도 설정되면 유지되므로, 존재 여부만 확인
# --------------------------------------------

FOUND_ANY_FILE="no"
CANDIDATE_LINES=()

for pattern in "${TARGET_FILES[@]}"; do
  # glob 확장되는 파일들 순회
  for f in $pattern; do
    [ -e "$f" ] || continue
    FOUND_ANY_FILE="yes"

    # export TMOUT 존재 여부(주석 제외)
    if grep -nE '^[[:space:]]*(export[[:space:]]+TMOUT|typeset[[:space:]]+-x[[:space:]]+TMOUT)\b' "$f" 2>/dev/null | grep -qEv '^[[:space:]]*#'; then
      EXPORT_FOUND="yes"
    fi

    # TMOUT= 라인 수집(주석 제외)
    while IFS= read -r line; do
      [ -n "$line" ] && CANDIDATE_LINES+=("$f:$line")
    done < <(grep -nEi '^[[:space:]]*TMOUT[[:space:]]*=' "$f" 2>/dev/null | grep -Ev '^[[:space:]]*#')
  done
done

# 마지막 TMOUT 설정 라인(가장 마지막 발견을 유효로 간주)
if [ "${#CANDIDATE_LINES[@]}" -gt 0 ]; then
  TMOUT_FOUND_LINE="${CANDIDATE_LINES[-1]}"

  # 값만 숫자로 추출(안전하게)
  TMOUT_VAL=$(echo "$TMOUT_FOUND_LINE" \
    | sed 's/.*TMOUT[[:space:]]*=[[:space:]]*//I' \
    | sed 's/[^0-9].*$//')
  [ -z "$TMOUT_VAL" ] && TMOUT_VAL="not_set"
fi

# PASS/FAIL 판단
# - TMOUT: 1~600
# - export TMOUT: 필수(가이드 조치 예시)
if [ "$TMOUT_VAL" != "not_set" ] && echo "$TMOUT_VAL" | grep -qE '^[0-9]+$' && [ "$TMOUT_VAL" -gt 0 ] && [ "$TMOUT_VAL" -le 600 ] && [ "$EXPORT_FOUND" = "yes" ]; then
  STATUS="PASS"
  REASON_LINE="TMOUT가 1~600초 범위로 설정되어 있고(export TMOUT 포함) 유휴 세션이 자동 종료되므로 장시간 방치 세션의 탈취 위험이 낮아 이 항목에 대한 보안 위협이 없습니다."
else
  STATUS="FAIL"
  if [ "$FOUND_ANY_FILE" = "no" ]; then
    REASON_LINE="시스템 전역 쉘 환경설정 파일(/etc/profile, /etc/profile.d/*.sh, /etc/bashrc)을 확인할 수 없어 유휴 세션 종료(TMOUT) 설정을 점검할 수 없으므로 취약합니다."
  elif [ "$TMOUT_VAL" = "not_set" ]; then
    REASON_LINE="TMOUT 설정이 확인되지 않아 유휴 세션 자동 종료가 보장되지 않으므로 취약합니다. TMOUT=600 이하로 설정하고 export TMOUT를 적용해야 합니다."
  elif ! echo "$TMOUT_VAL" | grep -qE '^[0-9]+$'; then
    REASON_LINE="TMOUT 값이 숫자로 확인되지 않아 유휴 세션 자동 종료 정책이 안전하게 적용되지 않으므로 취약합니다. TMOUT=600 이하의 숫자 값으로 설정하고 export TMOUT를 적용해야 합니다."
  elif [ "$TMOUT_VAL" -le 0 ] || [ "$TMOUT_VAL" -gt 600 ]; then
    REASON_LINE="TMOUT가 ${TMOUT_VAL}초로 설정되어 권고 범위(1~600초)를 벗어나 유휴 세션 자동 종료 정책이 안전하게 적용되지 않으므로 취약합니다. TMOUT=600 이하로 설정하고 export TMOUT를 적용해야 합니다."
  elif [ "$EXPORT_FOUND" != "yes" ]; then
    REASON_LINE="TMOUT 값은 설정되어 있으나(export TMOUT 미적용) 하위 쉘/세션에 일관되게 적용되지 않을 수 있어 취약합니다. export TMOUT를 함께 적용해야 합니다."
  else
    REASON_LINE="유휴 세션 종료(TMOUT) 설정이 가이드 기준을 충족하지 않아 취약합니다. TMOUT=600 이하 및 export TMOUT를 적용해야 합니다."
  fi
fi

# detail 구성
if [ -n "$TMOUT_FOUND_LINE" ]; then
  DETAIL_CONTENT="tmout_last_line=$TMOUT_FOUND_LINE"$'\n'"tmout_value=$TMOUT_VAL"$'\n'"export_tmout=$EXPORT_FOUND"
else
  DETAIL_CONTENT="tmout_last_line=not_found"$'\n'"tmout_value=$TMOUT_VAL"$'\n'"export_tmout=$EXPORT_FOUND"
fi

# raw_evidence 구성
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "/etc/profile, /etc/profile.d/*.sh, /etc/bashrc"
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