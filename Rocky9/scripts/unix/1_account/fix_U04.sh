#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 김나영
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID : U-04
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 비밀번호 파일 보호
# @Description : pwconv 명령어를 사용하여 쉐도우 패스워드 정책을 강제 적용
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-04"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND=""
REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""

PASSWD_FILE="/etc/passwd"
SHADOW_FILE="/etc/shadow"

TARGET_FILE="/etc/passwd
/etc/shadow"

# 점검 스크립트 기준(오탐 방지 포함):
# - $2 != "x" 이면서, '!','*' 계열(잠금/미사용)이 아닌 것만 취약 후보
CHECK_COMMAND="( command -v pwconv >/dev/null 2>&1 && echo pwconv_available=yes || echo pwconv_available=no ); \
[ -f /etc/passwd ] && awk -F: '\$2 != \"x\" && \$2 !~ /^(\\!|\\*)+\$/'\'' {print \$1\":\"\$2}'\'' /etc/passwd 2>/dev/null | head -n 50 || echo passwd_not_found; \
[ -f /etc/shadow ] && echo shadow_exists || echo shadow_not_found"

# --- 사전 체크(필수) ---
if [ "$(id -u)" -ne 0 ]; then
  IS_SUCCESS=0
  REASON_LINE="root 권한이 아니어서 조치를 수행할 수 없습니다."
  DETAIL_CONTENT="run_as_root_required"
elif [ ! -f "$PASSWD_FILE" ]; then
  IS_SUCCESS=0
  REASON_LINE="/etc/passwd 파일이 존재하지 않아 조치를 수행할 수 없습니다."
  DETAIL_CONTENT="passwd_not_found"
elif ! command -v pwconv >/dev/null 2>&1; then
  IS_SUCCESS=0
  REASON_LINE="시스템 내에 pwconv 명령이 존재하지 않아 조치가 완료되지 않았습니다."
  DETAIL_CONTENT="pwconv_not_found"
fi

# 조치 수행(백업 추가: 필수)
if [ -z "$REASON_LINE" ]; then
  TS="$(date '+%Y%m%d%H%M%S')"
  PASSWD_BAK="/var/tmp/passwd.U04.bak.${TS}"
  SHADOW_BAK="/var/tmp/shadow.U04.bak.${TS}"

  # /etc/passwd는 필수 백업
  if cp -p "$PASSWD_FILE" "$PASSWD_BAK" 2>/dev/null; then
    :
  else
    IS_SUCCESS=0
    REASON_LINE="/etc/passwd 백업에 실패하여 조치를 중단했습니다."
    DETAIL_CONTENT="backup_failed:$PASSWD_BAK"
  fi

  # /etc/shadow는 있을 때만 백업(없어도 pwconv가 생성/변환 시도 가능)
  if [ -z "$REASON_LINE" ] && [ -f "$SHADOW_FILE" ]; then
    if cp -p "$SHADOW_FILE" "$SHADOW_BAK" 2>/dev/null; then
      :
    else
      IS_SUCCESS=0
      REASON_LINE="/etc/shadow 백업에 실패하여 조치를 중단했습니다."
      DETAIL_CONTENT="backup_failed:$SHADOW_BAK"
    fi
  fi

  # pwconv 실행
  if [ -z "$REASON_LINE" ]; then
    pwconv >/dev/null 2>&1
    if [ $? -ne 0 ]; then
      IS_SUCCESS=0
      REASON_LINE="pwconv 실행에 실패하여 조치가 완료되지 않았습니다."
      DETAIL_CONTENT="pwconv_failed"
    fi
  fi
fi

# 조치 후 상태 수집(조치 후 상태만 detail에 표시)
if [ -z "$REASON_LINE" ]; then
  # 점검 스크립트와 동일 기준으로 검증(잠금/미사용 '!','*' 제외)
  NOT_X_USERS=$(awk -F: '$2 != "x" && $2 !~ /^(\!|\*)+$/ {print $1 ":" $2}' /etc/passwd 2>/dev/null | head -n 200)
  COUNT_NOT_X=$(awk -F: '$2 != "x" && $2 !~ /^(\!|\*)+$/ {c++} END{print c+0}' /etc/passwd 2>/dev/null)

  if [ "$COUNT_NOT_X" -eq 0 ]; then
    IS_SUCCESS=1
    REASON_LINE="모든 계정의 /etc/passwd 두 번째 필드가 'x'(또는 잠금/미사용 '!','*') 상태로 유지되어 비밀번호가 /etc/shadow로 분리되어 조치가 완료되었습니다."
    DETAIL_CONTENT="all_users_shadowed_or_locked"
  else
    IS_SUCCESS=0
    REASON_LINE="조치를 수행했으나 일부 계정의 /etc/passwd 두 번째 필드에 'x'가 아닌 값(잠금/미사용 '!','*' 제외)이 남아 조치가 완료되지 않았습니다."
    DETAIL_CONTENT="$NOT_X_USERS"
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