#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.1
# @Author: 권순형
# @Last Updated: 2026-02-14
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-18
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : /etc/shadow 파일 소유자 및 권한 설정
# @Description : /etc/shadow 파일의 소유자가 root이고, 권한이 400 이하로 설정
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-18"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND=""
REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""

TARGET_FILE="/etc/shadow"
CHECK_COMMAND="stat -c '%U %G %a %n' /etc/shadow 2>/dev/null"

# 권한 판정 함수(필수 보완): 3자리(0-padding) 정규화 후 400 이하(=u:4or0, g:0, o:0)만 허용
is_perm_ok() {
  local perm_raw="$1"
  [ -z "$perm_raw" ] && return 1

  local perm3 u g o
  perm3=$(printf "%03d" "$perm_raw" 2>/dev/null) || return 1
  u="${perm3:0:1}"
  g="${perm3:1:1}"
  o="${perm3:2:1}"

  # 400 이하의 의미를 자리 기준으로 엄격히 적용(오판 방지)
  if { [ "$u" = "4" ] || [ "$u" = "0" ]; } && [ "$g" = "0" ] && [ "$o" = "0" ]; then
    return 0
  fi
  return 1
}

# 조치 프로세스
if [ -f "$TARGET_FILE" ]; then
  MODIFIED=0

  # 조치 전 상태 수집(필수: stat 실패 방어)
  OWNER=$(stat -c "%U" "$TARGET_FILE" 2>/dev/null)
  GROUP=$(stat -c "%G" "$TARGET_FILE" 2>/dev/null)
  PERM_RAW=$(stat -c "%a" "$TARGET_FILE" 2>/dev/null)

  if [ -z "$OWNER" ] || [ -z "$GROUP" ] || [ -z "$PERM_RAW" ]; then
    IS_SUCCESS=0
    REASON_LINE="조치 대상 파일(/etc/shadow)은 존재하나 소유자/권한 정보를 확인할 수 없어 조치를 완료할 수 없습니다(stat 실행 오류)."
    DETAIL_CONTENT="stat_failed"
  else
    # 권한 3자리 정규화(표시용)
    PERM=$(printf "%03d" "$PERM_RAW" 2>/dev/null)

    # 1) 소유자 조치(가이드 필수: owner=root)
    if [ "$OWNER" != "root" ]; then
      chown root "$TARGET_FILE" 2>/dev/null
      MODIFIED=1
    fi

    # 2) 권한 조치(가이드 필수: 400 이하) - 단순 -gt 400 비교 대신 엄격 판정 후 필요 시 400으로 고정
    if ! is_perm_ok "$PERM_RAW"; then
      chmod 400 "$TARGET_FILE" 2>/dev/null
      MODIFIED=1
    fi

    # 조치 후 상태 검증(조치 후 상태만 기록)
    AFTER_OWNER=$(stat -c "%U" "$TARGET_FILE" 2>/dev/null)
    AFTER_GROUP=$(stat -c "%G" "$TARGET_FILE" 2>/dev/null)
    AFTER_PERM_RAW=$(stat -c "%a" "$TARGET_FILE" 2>/dev/null)
    AFTER_PERM=$(printf "%03d" "$AFTER_PERM_RAW" 2>/dev/null)

    DETAIL_CONTENT="owner=$AFTER_OWNER
group=$AFTER_GROUP
perm=$AFTER_PERM"

    if [ "$AFTER_OWNER" = "root" ] && is_perm_ok "$AFTER_PERM_RAW"; then
      IS_SUCCESS=1
      if [ "$MODIFIED" -eq 1 ]; then
        REASON_LINE="/etc/shadow 파일의 소유자가 root로 설정되고 권한이 400 이하로 변경되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
      else
        REASON_LINE="/etc/shadow 파일의 소유자가 root이고 권한이 400 이하로 유지되어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
      fi
    else
      IS_SUCCESS=0
      REASON_LINE="조치를 수행했으나 /etc/shadow 파일의 소유자 또는 권한이 기준을 충족하지 못해 조치가 완료되지 않았습니다."
    fi
  fi
else
  IS_SUCCESS=0
  REASON_LINE="조치 대상 파일(/etc/shadow)이 존재하지 않아 조치가 완료되지 않았습니다."
  DETAIL_CONTENT=""
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