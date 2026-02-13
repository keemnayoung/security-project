#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-30
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 중
# @Title       : UMASK 설정 관리
# @Description : 시스템 UMASK 값 022 이상으로 설정
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-30"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND=""
REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""

PROFILE_OK=0
LOGIN_DEFS_OK=0

FINAL_PROFILE=""
FINAL_LOGIN_DEFS=""

TARGET_FILE="/etc/profile
/etc/login.defs"

CHECK_COMMAND="( [ -f /etc/profile ] && grep -inE '^[[:space:]]*umask[[:space:]]+[0-9]+' /etc/profile | tail -n 3 ) ; ( [ -f /etc/login.defs ] && grep -inE '^[[:space:]]*UMASK[[:space:]]+[0-9]+' /etc/login.defs | tail -n 3 )"

# /etc/profile 조치(백업 없음)
if [ -f /etc/profile ]; then
  sed -i '/^[[:space:]]*umask[[:space:]]\+[0-9]\+/Id' /etc/profile
  printf "\numask 022\nexport umask\n" >> /etc/profile

  FINAL_PROFILE=$(grep -iE '^[[:space:]]*umask[[:space:]]+[0-9]+' /etc/profile 2>/dev/null | tail -n 1 | awk '{print $2}')
  if [ -n "$FINAL_PROFILE" ] && [ "$FINAL_PROFILE" -ge 22 ]; then
    PROFILE_OK=1
  fi
fi

# /etc/login.defs 조치(백업 없음)
if [ -f /etc/login.defs ]; then
  sed -i '/^[[:space:]]*UMASK[[:space:]]\+[0-9]\+/Id' /etc/login.defs
  echo "UMASK 022" >> /etc/login.defs

  FINAL_LOGIN_DEFS=$(grep -iE '^[[:space:]]*UMASK[[:space:]]+[0-9]+' /etc/login.defs 2>/dev/null | tail -n 1 | awk '{print $2}')
  if [ -n "$FINAL_LOGIN_DEFS" ] && [ "$FINAL_LOGIN_DEFS" -ge 22 ]; then
    LOGIN_DEFS_OK=1
  fi
fi

# 조치 후 상태(조치 후 상태만 detail에 표시)
DETAIL_CONTENT=""

if [ -f /etc/profile ]; then
  PROFILE_LINE=$(grep -inE '^[[:space:]]*umask[[:space:]]+[0-9]+' /etc/profile 2>/dev/null | tail -n 1)
  [ -n "$PROFILE_LINE" ] && DETAIL_CONTENT="${DETAIL_CONTENT}${PROFILE_LINE}
"
fi

if [ -f /etc/login.defs ]; then
  LOGIN_LINE=$(grep -inE '^[[:space:]]*UMASK[[:space:]]+[0-9]+' /etc/login.defs 2>/dev/null | tail -n 1)
  [ -n "$LOGIN_LINE" ] && DETAIL_CONTENT="${DETAIL_CONTENT}${LOGIN_LINE}
"
fi

# 최종 판정
if [ "$PROFILE_OK" -eq 1 ] && [ "$LOGIN_DEFS_OK" -eq 1 ]; then
  IS_SUCCESS=1
  REASON_LINE="/etc/profile 및 /etc/login.defs에 UMASK 값이 022로 적용되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
elif [ "$PROFILE_OK" -eq 1 ] || [ "$LOGIN_DEFS_OK" -eq 1 ]; then
  IS_SUCCESS=0
  REASON_LINE="UMASK 설정이 일부 파일에만 적용되어 조치가 완료되지 않았습니다."
else
  IS_SUCCESS=0
  if [ ! -f /etc/profile ] && [ ! -f /etc/login.defs ]; then
    REASON_LINE="/etc/profile 및 /etc/login.defs 파일이 존재하지 않아 조치가 완료되지 않았습니다."
  elif [ ! -f /etc/profile ]; then
    REASON_LINE="/etc/profile 파일이 존재하지 않아 UMASK 설정 조치가 완료되지 않았습니다."
  elif [ ! -f /etc/login.defs ]; then
    REASON_LINE="/etc/login.defs 파일이 존재하지 않아 UMASK 설정 조치가 완료되지 않았습니다."
  else
    REASON_LINE="UMASK 값이 022로 적용되지 않아 조치가 완료되지 않았습니다."
  fi
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