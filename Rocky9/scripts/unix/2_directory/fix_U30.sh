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
PROFILED_OK=1   # profile.d 는 파일이 없으면 OK로 취급
BASHRC_OK=1     # bashrc 는 파일이 없으면 OK로 취급

FINAL_PROFILE=""
FINAL_LOGIN_DEFS=""

PROFILE_FILE="/etc/profile"
LOGIN_DEFS_FILE="/etc/login.defs"
BASHRC_FILE="/etc/bashrc"
PROFILED_GLOB="/etc/profile.d/*.sh"

TARGET_FILE="/etc/profile
/etc/profile.d/*.sh
/etc/bashrc
/etc/login.defs"

CHECK_COMMAND="( [ -f /etc/profile ] && grep -inE '^[[:space:]]*umask[[:space:]]+[0-9]+' /etc/profile | tail -n 3 || echo 'profile_not_found' ) ; \
( ls -1 /etc/profile.d/*.sh >/dev/null 2>&1 && grep -inE '^[[:space:]]*umask[[:space:]]+[0-9]+' /etc/profile.d/*.sh | tail -n 5 || echo 'profile_d_not_found_or_no_umask' ) ; \
( [ -f /etc/bashrc ] && grep -inE '^[[:space:]]*umask[[:space:]]+[0-9]+' /etc/bashrc | tail -n 3 || echo 'bashrc_not_found_or_no_umask' ) ; \
( [ -f /etc/login.defs ] && grep -inE '^[[:space:]]*UMASK[[:space:]]+[0-9]+' /etc/login.defs | tail -n 3 || echo 'login_defs_not_found' )"

# ------------------------------------------------------------
# 함수: "022 이상(=022 포함, 더 제한적이면 양호)" 판정
# - 8진수로 해석 후, 022의 필수 비트(그룹/기타 write 차단)가 포함되어야 양호
#   => (umask_value & 022) == 022
# ------------------------------------------------------------
is_umask_ok() {
  local raw="$1"
  local v dec required
  v=$(echo "$raw" | grep -oE '^[0-9]+' || true)
  [ -z "$v" ] && return 1

  dec=$((8#$v))
  required=$((8#022))

  if [ $(( dec & required )) -eq "$required" ]; then
    return 0
  fi
  return 1
}

# ------------------------------------------------------------
# 1) /etc/profile 조치(백업 없음)
#   - 이미 더 강한 값(예: 077)이면 유지
#   - 약하면 022로 교정
# ------------------------------------------------------------
if [ -f "$PROFILE_FILE" ]; then
  CUR_PROFILE=$(grep -iE '^[[:space:]]*umask[[:space:]]+[0-9]+' "$PROFILE_FILE" 2>/dev/null | tail -n 1 | awk '{print $2}')
  if [ -n "$CUR_PROFILE" ] && is_umask_ok "$CUR_PROFILE"; then
    PROFILE_OK=1
  else
    sed -i '/^[[:space:]]*umask[[:space:]]\+[0-9]\+/Id' "$PROFILE_FILE"
    printf "\numask 022\nexport umask\n" >> "$PROFILE_FILE"
  fi

  FINAL_PROFILE=$(grep -iE '^[[:space:]]*umask[[:space:]]+[0-9]+' "$PROFILE_FILE" 2>/dev/null | tail -n 1 | awk '{print $2}')
  if [ -n "$FINAL_PROFILE" ] && is_umask_ok "$FINAL_PROFILE"; then
    PROFILE_OK=1
  fi
fi

# ------------------------------------------------------------
# 2) /etc/profile.d/*.sh 조치(백업 없음)
#   - 존재하는 파일들에서 약한 umask 라인만 022로 교정
#   - (점검 스크립트가 profile.d의 취약 라인도 FAIL로 잡는 것을 방지)
# ------------------------------------------------------------
PROFILED_OK=1
if ls -1 $PROFILED_GLOB >/dev/null 2>&1; then
  for f in $PROFILED_GLOB; do
    [ -f "$f" ] || continue
    # 파일 내 마지막 umask 값 기준으로 취약 여부 판단
    CUR_PD=$(grep -iE '^[[:space:]]*umask[[:space:]]+[0-9]+' "$f" 2>/dev/null | tail -n 1 | awk '{print $2}')
    if [ -n "$CUR_PD" ]; then
      if is_umask_ok "$CUR_PD"; then
        : # OK면 유지
      else
        # 약한 umask 라인들만 022로 교정(간단/안전)
        sed -i -E 's/^[[:space:]]*umask[[:space:]]+[0-9]+/umask 022/I' "$f"
      fi

      # 교정 후 재검증(마지막값)
      FINAL_PD=$(grep -iE '^[[:space:]]*umask[[:space:]]+[0-9]+' "$f" 2>/dev/null | tail -n 1 | awk '{print $2}')
      if [ -n "$FINAL_PD" ] && ! is_umask_ok "$FINAL_PD"; then
        PROFILED_OK=0
      fi
    fi
  done
fi

# ------------------------------------------------------------
# 3) /etc/bashrc 조치(백업 없음)
#   - 약한 umask가 있으면 022로 교정
# ------------------------------------------------------------
BASHRC_OK=1
if [ -f "$BASHRC_FILE" ]; then
  CUR_BASHRC=$(grep -iE '^[[:space:]]*umask[[:space:]]+[0-9]+' "$BASHRC_FILE" 2>/dev/null | tail -n 1 | awk '{print $2}')
  if [ -n "$CUR_BASHRC" ]; then
    if is_umask_ok "$CUR_BASHRC"; then
      BASHRC_OK=1
    else
      sed -i -E 's/^[[:space:]]*umask[[:space:]]+[0-9]+/umask 022/I' "$BASHRC_FILE"
      FINAL_BASHRC=$(grep -iE '^[[:space:]]*umask[[:space:]]+[0-9]+' "$BASHRC_FILE" 2>/dev/null | tail -n 1 | awk '{print $2}')
      if [ -n "$FINAL_BASHRC" ] && is_umask_ok "$FINAL_BASHRC"; then
        BASHRC_OK=1
      else
        BASHRC_OK=0
      fi
    fi
  fi
fi

# ------------------------------------------------------------
# 4) /etc/login.defs 조치(백업 없음)
#   - 더 강한 값이면 유지
#   - 약하면 022로 교정
# ------------------------------------------------------------
if [ -f "$LOGIN_DEFS_FILE" ]; then
  CUR_LOGIN=$(grep -iE '^[[:space:]]*UMASK[[:space:]]+[0-9]+' "$LOGIN_DEFS_FILE" 2>/dev/null | tail -n 1 | awk '{print $2}')
  if [ -n "$CUR_LOGIN" ] && is_umask_ok "$CUR_LOGIN"; then
    LOGIN_DEFS_OK=1
  else
    sed -i '/^[[:space:]]*UMASK[[:space:]]\+[0-9]\+/Id' "$LOGIN_DEFS_FILE"
    echo "UMASK 022" >> "$LOGIN_DEFS_FILE"
  fi

  FINAL_LOGIN_DEFS=$(grep -iE '^[[:space:]]*UMASK[[:space:]]+[0-9]+' "$LOGIN_DEFS_FILE" 2>/dev/null | tail -n 1 | awk '{print $2}')
  if [ -n "$FINAL_LOGIN_DEFS" ] && is_umask_ok "$FINAL_LOGIN_DEFS"; then
    LOGIN_DEFS_OK=1
  fi
fi

# ------------------------------------------------------------
# 조치 후 상태(detail에 표시)
# ------------------------------------------------------------
DETAIL_CONTENT=""

if [ -f "$PROFILE_FILE" ]; then
  PROFILE_LINE=$(grep -inE '^[[:space:]]*umask[[:space:]]+[0-9]+' "$PROFILE_FILE" 2>/dev/null | tail -n 1)
  [ -n "$PROFILE_LINE" ] && DETAIL_CONTENT="${DETAIL_CONTENT}${PROFILE_LINE}\n"
fi

if ls -1 $PROFILED_GLOB >/dev/null 2>&1; then
  PD_LINES=$(grep -inE '^[[:space:]]*umask[[:space:]]+[0-9]+' $PROFILED_GLOB 2>/dev/null | tail -n 5)
  [ -n "$PD_LINES" ] && DETAIL_CONTENT="${DETAIL_CONTENT}${PD_LINES}\n"
fi

if [ -f "$BASHRC_FILE" ]; then
  BASHRC_LINE=$(grep -inE '^[[:space:]]*umask[[:space:]]+[0-9]+' "$BASHRC_FILE" 2>/dev/null | tail -n 1)
  [ -n "$BASHRC_LINE" ] && DETAIL_CONTENT="${DETAIL_CONTENT}${BASHRC_LINE}\n"
fi

if [ -f "$LOGIN_DEFS_FILE" ]; then
  LOGIN_LINE=$(grep -inE '^[[:space:]]*UMASK[[:space:]]+[0-9]+' "$LOGIN_DEFS_FILE" 2>/dev/null | tail -n 1)
  [ -n "$LOGIN_LINE" ] && DETAIL_CONTENT="${DETAIL_CONTENT}${LOGIN_LINE}\n"
fi

# ------------------------------------------------------------
# 최종 판정
# - 네 점검 로직 기준으로 profile.d/bashrc에서 약한 umask가 남으면 FAIL 가능 → 같이 반영
# ------------------------------------------------------------
if [ "$PROFILE_OK" -eq 1 ] && [ "$LOGIN_DEFS_OK" -eq 1 ] && [ "$PROFILED_OK" -eq 1 ] && [ "$BASHRC_OK" -eq 1 ]; then
  IS_SUCCESS=1
  REASON_LINE="주요 설정 파일에 UMASK 값이 022(또는 더 제한적으로) 적용되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
else
  IS_SUCCESS=0
  # 파일 미존재 케이스 우선 처리
  if [ ! -f "$PROFILE_FILE" ] && [ ! -f "$LOGIN_DEFS_FILE" ]; then
    REASON_LINE="/etc/profile 및 /etc/login.defs 파일이 존재하지 않아 조치가 완료되지 않았습니다."
  elif [ ! -f "$PROFILE_FILE" ]; then
    REASON_LINE="/etc/profile 파일이 존재하지 않아 UMASK 설정 조치가 완료되지 않았습니다."
  elif [ ! -f "$LOGIN_DEFS_FILE" ]; then
    REASON_LINE="/etc/login.defs 파일이 존재하지 않아 UMASK 설정 조치가 완료되지 않았습니다."
  else
    REASON_LINE="UMASK 값이 022(또는 더 제한적으로)로 모두 적용되지 않아 조치가 완료되지 않았습니다. (/etc/profile.d 또는 /etc/bashrc에 약한 UMASK가 남아있을 수 있습니다.)"
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