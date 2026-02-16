#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.0
# @Author: 김나영
# @Last Updated: 2026-02-13
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

# UID 변경 후 파일 소유권(숫자 UID) 정리
fix_file_ownership_by_uid() {
  local old_uid="$1"
  local user="$2"

  find / -xdev \
    \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /var/run \) -prune -o \
    -uid "$old_uid" -exec chown -h "$user" {} + 2>/dev/null
}

# 특정 사용자 프로세스 사용 여부 확인(필수 보강)
# - 프로세스가 있으면 usermod가 실패할 수 있으므로 자동 조치 중단
is_user_in_use() {
  local user="$1"
  if command -v pgrep >/dev/null 2>&1; then
    pgrep -u "$user" >/dev/null 2>&1
    return $?
  else
    # pgrep 없을 경우 ps로 대체
    ps -u "$user" >/dev/null 2>&1
    return $?
  fi
}

# PID 1이 특정 사용자로 표시되는지 확인(필수 보강)
is_pid1_mapped_to_user() {
  local user="$1"
  local u
  u=$(ps -p 1 -o user= 2>/dev/null | awk '{print $1}')
  [ "$u" = "$user" ]
}

# --- 조치 수행 ---

# /etc/passwd 자체가 없으면 조치 불가
if [ ! -f "$PASSWD_FILE" ]; then
  IS_SUCCESS=0
  REASON_LINE="/etc/passwd 파일을 확인할 수 없어 조치를 수행할 수 없습니다."
  DETAIL_CONTENT="passwd_not_found"
else
  # 로컬(/etc/passwd)에서 조치 가능한 UID=0(root 제외) 계정 수집
  EXTRA_ROOT_LOCAL=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' "$PASSWD_FILE" 2>/dev/null | sed 's/[[:space:]]*$//')

  if [ -z "$EXTRA_ROOT_LOCAL" ]; then
    IS_SUCCESS=1
    REASON_LINE="root 이외에 UID가 0인 계정이 존재하지 않아 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
    DETAIL_CONTENT=""
  else
    # 필수 보강: PID 1 매핑/사용 중 계정은 자동 조치 중단
    BLOCKED_USERS=""
    for user in $EXTRA_ROOT_LOCAL; do
      if is_pid1_mapped_to_user "$user"; then
        BLOCKED_USERS="${BLOCKED_USERS}${user}:pid1_mapped"$'\n'
      elif is_user_in_use "$user"; then
        BLOCKED_USERS="${BLOCKED_USERS}${user}:in_use"$'\n'
      fi
    done
    BLOCKED_USERS=$(printf "%s" "$BLOCKED_USERS" | sed '/^$/d')

    if [ -n "$BLOCKED_USERS" ]; then
      IS_SUCCESS=0
      FAIL_FLAG=1
      REASON_LINE="UID=0(root 제외) 계정이 현재 실행 중인 프로세스에서 사용 중이거나(PID 1 포함) 사용자 매핑에 영향이 있어 자동 조치를 중단했습니다. 먼저 해당 계정 사용 프로세스를 종료하거나(가능한 경우), /etc/passwd에서 UID 0 중복을 해소한 뒤 재실행해야 합니다."
      DETAIL_CONTENT="$BLOCKED_USERS"
    else
      # 사용 중이 아닌 경우에만 UID 변경 진행
      for user in $EXTRA_ROOT_LOCAL; do
        OLD_UID=$(awk -F: -v U="$user" '$1==U {print $3}' "$PASSWD_FILE" 2>/dev/null)
        NEW_UID=$(get_unused_uid)

        # usermod 에러를 detail에 남기기(필수 보강)
        USERMOD_ERR=""
        USERMOD_ERR=$(usermod -u "$NEW_UID" "$user" 2>&1 >/dev/null)
        RC=$?

        if [ $RC -eq 0 ]; then
          MODIFIED=1
          # 기존 숫자 UID로 남아있는 파일 소유권 정리
          if [ -n "$OLD_UID" ]; then
            fix_file_ownership_by_uid "$OLD_UID" "$user"
          fi
        else
          FAIL_FLAG=1
          DETAIL_CONTENT="${DETAIL_CONTENT}${user}:usermod_failed:${USERMOD_ERR}"$'\n'
        fi
      done

      # 조치 후 상태 수집(로컬 기준)
      REMAIN_USERS=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' "$PASSWD_FILE" 2>/dev/null | sed 's/[[:space:]]*$//')

      if [ -z "$REMAIN_USERS" ] && [ "$FAIL_FLAG" -eq 0 ]; then
        IS_SUCCESS=1
        REASON_LINE="root 이외의 UID 0 계정이 일반 UID로 변경되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
        # 성공이면 detail에는 남은 계정 없음
        DETAIL_CONTENT=""
      else
        IS_SUCCESS=0
        REASON_LINE="조치를 수행했으나 root 이외의 UID 0 계정이 남아 있거나 UID 변경이 정상 처리되지 않아 조치가 완료되지 않았습니다."
        # usermod 실패 로그가 없다면 남은 계정만 표시
        if [ -z "$(printf "%s" "$DETAIL_CONTENT" | sed '/^$/d')" ] && [ -n "$REMAIN_USERS" ]; then
          DETAIL_CONTENT="$REMAIN_USERS"
        else
          # 둘 다 있으면 이어붙임
          if [ -n "$REMAIN_USERS" ]; then
            DETAIL_CONTENT="$(printf "%s\n%s" "$(printf "%s" "$DETAIL_CONTENT" | sed '/^$/d')" "$REMAIN_USERS" | sed '/^$/d')"
          else
            DETAIL_CONTENT="$(printf "%s" "$DETAIL_CONTENT" | sed '/^$/d')"
          fi
        fi
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