#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 김나영
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID : U-05
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : UID가 0인 일반 계정 존재
# @Description : 관리자 권한(UID 0)을 가진 일반 계정의 UID를 일반 사용자 번호로 변경
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================


# 기본 변수
ID="U-05"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND=""
REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""

PASSWD_FILE="/etc/passwd"
TARGET_FILE="$PASSWD_FILE"

# 증거용 커맨드(판정 로직과 동일하게 getent 우선 + root 제외)
CHECK_COMMAND="(command -v getent >/dev/null 2>&1 && getent passwd | awk -F: '\$3==0 && \$1!=\"root\" {print \$1\":\"\$3\":\"\$0}') || ([ -f /etc/passwd ] && awk -F: '\$3==0 && \$1!=\"root\" {print \$1\":\"\$3\":\"\$0}' /etc/passwd 2>/dev/null) || echo \"passwd_not_found\""

MODIFIED=0
FAIL_FLAG=0
DETAIL_CONTENT=""

# 2000번부터 사용 중이지 않은 UID 찾기
get_unused_uid() {
  local uid=2000
  while getent passwd "$uid" >/dev/null 2>&1; do
    uid=$((uid+1))
  done
  echo "$uid"
}

# UID 변경 후 파일 소유권(숫자 UID) 정리 (필수 보강)
fix_file_ownership_by_uid() {
  local old_uid="$1"
  local user="$2"

  # 특수 파일시스템/가상 경로는 제외, 같은 파일시스템(-xdev) 범위에서만 정리
  # old_uid 숫자로 남아있는 소유 파일을 새 사용자(user)로 변경
  find / -xdev \
    \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /var/run \) -prune -o \
    -uid "$old_uid" -exec chown -h "$user" {} + 2>/dev/null
}

# --- 조치 수행 ---

# 1) NSS 기준(getent)으로 UID=0(root 제외) 계정 수집 (필수 보강)
EXTRA_ROOT_NSS=""
if command -v getent >/dev/null 2>&1; then
  EXTRA_ROOT_NSS=$(getent passwd 2>/dev/null | awk -F: '$3 == 0 && $1 != "root" {print $1}' | sed 's/[[:space:]]*$//')
fi

# 2) 로컬(/etc/passwd)에서 조치 가능한 UID=0(root 제외) 계정 수집
EXTRA_ROOT_LOCAL=""
if [ -f "$PASSWD_FILE" ]; then
  EXTRA_ROOT_LOCAL=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' "$PASSWD_FILE" 2>/dev/null | sed 's/[[:space:]]*$//')
fi

# /etc/passwd 자체가 없으면 조치 불가
if [ ! -f "$PASSWD_FILE" ]; then
  IS_SUCCESS=0
  REASON_LINE="/etc/passwd 파일을 확인할 수 없어 조치를 수행할 수 없습니다."
  DETAIL_CONTENT="passwd_not_found"
else
  # NSS에는 있는데 로컬에는 없는 UID=0 계정은 usermod로 조치 불가 → 필수로 FAIL 처리
  NSS_ONLY_USERS=""
  if [ -n "$EXTRA_ROOT_NSS" ]; then
    for u in $EXTRA_ROOT_NSS; do
      if ! awk -F: -v UU="$u" '$1==UU {found=1} END{exit(found?0:1)}' "$PASSWD_FILE" 2>/dev/null; then
        NSS_ONLY_USERS="${NSS_ONLY_USERS}${u}"$'\n'
      fi
    done
    NSS_ONLY_USERS=$(printf "%s" "$NSS_ONLY_USERS" | sed '/^$/d')
  fi

  # 로컬에 조치할 계정이 없고, NSS-only도 없으면 성공
  if [ -z "$EXTRA_ROOT_LOCAL" ] && [ -z "$NSS_ONLY_USERS" ]; then
    IS_SUCCESS=1
    REASON_LINE="root 이외에 UID가 0인 계정이 존재하지 않아 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
    DETAIL_CONTENT=""
  else
    # 로컬(/etc/passwd)에 존재하는 UID=0 계정은 UID 변경 조치 진행
    if [ -n "$EXTRA_ROOT_LOCAL" ]; then
      for user in $EXTRA_ROOT_LOCAL; do
        OLD_UID=$(awk -F: -v U="$user" '$1==U {print $3}' "$PASSWD_FILE" 2>/dev/null)
        NEW_UID=$(get_unused_uid)

        if usermod -u "$NEW_UID" "$user" >/dev/null 2>&1; then
          MODIFIED=1
          # 필수 보강: 기존 OLD_UID 숫자로 남아있는 파일 소유권 정리
          if [ -n "$OLD_UID" ]; then
            fix_file_ownership_by_uid "$OLD_UID" "$user"
          fi
        else
          FAIL_FLAG=1
        fi
      done
    fi

    # 조치 후 상태 수집: NSS 기준 + 로컬 기준 모두 반영
    REMAIN_USERS=""
    if command -v getent >/dev/null 2>&1; then
      REMAIN_USERS=$(getent passwd 2>/dev/null | awk -F: '$3 == 0 && $1 != "root" {print $1}' | sed 's/[[:space:]]*$//')
    else
      REMAIN_USERS=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' "$PASSWD_FILE" 2>/dev/null | sed 's/[[:space:]]*$//')
    fi

    if [ -n "$REMAIN_USERS" ]; then
      DETAIL_CONTENT="$REMAIN_USERS"
    else
      DETAIL_CONTENT=""
    fi

    # NSS-only 계정이 있으면 조치 불가이므로 실패로 처리(필수)
    if [ -n "$NSS_ONLY_USERS" ]; then
      IS_SUCCESS=0
      FAIL_FLAG=1
      REASON_LINE="UID=0(root 제외) 계정이 NSS(getent)에는 존재하지만 /etc/passwd에는 없어 로컬 usermod로 조치할 수 없습니다(LDAP/NIS 등). 해당 계정 저장소에서 UID 변경/계정 제거가 필요합니다."
      # detail은 남아있는 UID=0 계정 목록을 우선 표시
      [ -z "$DETAIL_CONTENT" ] && DETAIL_CONTENT="$NSS_ONLY_USERS"
    else
      if [ -z "$REMAIN_USERS" ] && [ "$FAIL_FLAG" -eq 0 ]; then
        IS_SUCCESS=1
        if [ "$MODIFIED" -eq 1 ]; then
          REASON_LINE="root 이외의 UID 0 계정이 일반 UID로 변경되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
        else
          REASON_LINE="root 이외의 UID 0 계정이 존재하지 않아 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
        fi
      else
        IS_SUCCESS=0
        REASON_LINE="조치를 수행했으나 root 이외의 UID 0 계정이 남아 있거나 UID 변경이 정상 처리되지 않아 조치가 완료되지 않았습니다."
      fi
    fi
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