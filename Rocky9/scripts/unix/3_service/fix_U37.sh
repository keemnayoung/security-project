#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-37
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : crontab 설정파일 권한 설정 미흡
# @Description : crontab 및 at 서비스 관련 파일의 권한 설정 보완
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-37 crontab 설정파일 권한 설정

# 기본 변수
ID="U-37"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

REASON_LINE=""
DETAIL_CONTENT=""
ACTION_ERR_LOG=""

# 대상(가이드 기준)
CRONTAB_CMD="/usr/bin/crontab"
AT_CMD="/usr/bin/at"

CRON_SPOOL_DIRS=("/var/spool/cron" "/var/spool/cron/crontabs")
CRON_ETC_FILES=("/etc/crontab")
CRON_ETC_DIRS=("/etc/cron.d" "/etc/cron.daily" "/etc/cron.hourly" "/etc/cron.weekly" "/etc/cron.monthly")
AT_SPOOL_DIRS=("/var/spool/at" "/var/spool/cron/atjobs")

# (추가) 접근제어 파일(가이드 취지: 일반 사용자 사용 제한)
CRON_ALLOW="/etc/cron.allow"
CRON_DENY="/etc/cron.deny"
AT_ALLOW="/etc/at.allow"
AT_DENY="/etc/at.deny"

TARGET_FILE="$CRONTAB_CMD
$AT_CMD
${CRON_SPOOL_DIRS[*]}
${CRON_ETC_FILES[*]}
${CRON_ETC_DIRS[*]}
${AT_SPOOL_DIRS[*]}
$CRON_ALLOW
$CRON_DENY
$AT_ALLOW
$AT_DENY"

CHECK_COMMAND='
for p in /usr/bin/crontab /usr/bin/at /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny; do
  [ -e "$p" ] && stat -c "%U %G %a %n" "$p" 2>/dev/null || echo "not_found:$p";
done;
for d in /var/spool/cron /var/spool/cron/crontabs /var/spool/at /var/spool/cron/atjobs; do
  [ -d "$d" ] && (stat -c "%U %G %a %n" "$d" 2>/dev/null; find "$d" -maxdepth 1 -type f -exec stat -c "%U %G %a %n" {} \; 2>/dev/null | head -n 50) || echo "dir_not_found:$d";
done;
for f in /etc/crontab; do
  [ -f "$f" ] && stat -c "%U %G %a %n" "$f" 2>/dev/null || echo "not_found:$f";
done;
for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
  [ -d "$d" ] && stat -c "%U %G %a %n" "$d" 2>/dev/null || echo "dir_not_found:$d";
done;
( [ -f /etc/cron.allow ] && echo "[cron.allow]" && grep -nEv "^[[:space:]]*#|^[[:space:]]*$" /etc/cron.allow 2>/dev/null ) || echo "cron.allow_not_found_or_empty";
( [ -f /etc/at.allow ] && echo "[at.allow]" && grep -nEv "^[[:space:]]*#|^[[:space:]]*$" /etc/at.allow 2>/dev/null ) || echo "at.allow_not_found_or_empty";
'

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
MODIFIED=0
FAIL_FLAG=0

append_err() {
  if [ -n "$ACTION_ERR_LOG" ]; then
    ACTION_ERR_LOG="${ACTION_ERR_LOG}\n$1"
  else
    ACTION_ERR_LOG="$1"
  fi
}

append_detail() {
  if [ -n "$DETAIL_CONTENT" ]; then
    DETAIL_CONTENT="${DETAIL_CONTENT}\n$1"
  else
    DETAIL_CONTENT="$1"
  fi
}

# (필수) root 권한 권장 안내(실패 원인 명확화용)
if [ "$(id -u)" -ne 0 ]; then
  ACTION_ERR_LOG="(주의) root 권한이 아니면 chown/chmod 조치가 실패할 수 있습니다."
fi

# 권한 초과 판정(정수 비교)
perm_exceeds() {
  local cur="$1"
  local max="$2"
  [ -z "$cur" ] && return 1
  [ -z "$max" ] && return 1
  echo "$cur" | grep -Eq '^[0-7]{3,4}$' || return 1
  echo "$max" | grep -Eq '^[0-7]{3,4}$' || return 1
  [ "$cur" -gt "$max" ]
}

ensure_owner_root_root() {
  local path="$1"
  [ -e "$path" ] || return 0
  chown root:root "$path" 2>/dev/null || { append_err "$path 소유자/그룹을 root:root로 변경하지 못했습니다."; FAIL_FLAG=1; }
}

ensure_mode() {
  local path="$1"
  local mode="$2"
  [ -e "$path" ] || return 0
  chmod "$mode" "$path" 2>/dev/null || { append_err "$path 권한을 ${mode}로 변경하지 못했습니다."; FAIL_FLAG=1; }
}

# (추가) SUID/SGID 제거 명시(가이드 권고 반영)
remove_suid_sgid() {
  local path="$1"
  [ -e "$path" ] || return 0
  chmod u-s,g-s "$path" 2>/dev/null || { append_err "$path SUID/SGID 제거(chmod u-s,g-s)에 실패했습니다."; FAIL_FLAG=1; }
}

# (추가) stat 수집 실패 방어 포함(조치 후 상태만 기록)
verify_file_max() {
  local path="$1"
  local max="$2"
  [ -f "$path" ] || return 0
  local owner group perm
  owner="$(stat -c '%U' "$path" 2>/dev/null)" || owner=""
  group="$(stat -c '%G' "$path" 2>/dev/null)" || group=""
  perm="$(stat -c '%a' "$path" 2>/dev/null)" || perm=""

  if [ -z "$owner" ] || [ -z "$group" ] || [ -z "$perm" ]; then
    append_detail "file(after)=$path owner=unknown group=unknown perm=unknown"
    append_err "$path 조치 후 상태(stat) 수집에 실패하여 조치가 완료되지 않았습니다."
    FAIL_FLAG=1
    return 0
  fi

  append_detail "file(after)=$path owner=$owner group=$group perm=$perm"
  [ "$owner" = "root" ] || FAIL_FLAG=1
  [ "$group" = "root" ] || FAIL_FLAG=1
  if perm_exceeds "$perm" "$max"; then
    FAIL_FLAG=1
  fi
}

verify_dir_max() {
  local path="$1"
  local max="$2"
  [ -d "$path" ] || return 0
  local owner group perm
  owner="$(stat -c '%U' "$path" 2>/dev/null)" || owner=""
  group="$(stat -c '%G' "$path" 2>/dev/null)" || group=""
  perm="$(stat -c '%a' "$path" 2>/dev/null)" || perm=""

  if [ -z "$owner" ] || [ -z "$group" ] || [ -z "$perm" ]; then
    append_detail "dir(after)=$path owner=unknown group=unknown perm=unknown"
    append_err "$path 조치 후 상태(stat) 수집에 실패하여 조치가 완료되지 않았습니다."
    FAIL_FLAG=1
    return 0
  fi

  append_detail "dir(after)=$path owner=$owner group=$group perm=$perm"
  [ "$owner" = "root" ] || FAIL_FLAG=1
  [ "$group" = "root" ] || FAIL_FLAG=1
  if perm_exceeds "$perm" "$max"; then
    FAIL_FLAG=1
  fi
}

# ---------------------------
# root 권한 아니면 조치 중단(요구 톤 유지)
# ---------------------------
if [ "$(id -u)" -ne 0 ]; then
  IS_SUCCESS=0
  REASON_LINE="root 권한이 아니어서 crontab/at 관련 파일 권한 조치를 수행할 수 없어 조치를 중단합니다."
  DETAIL_CONTENT="current_user_uid=$(id -u)"
  if [ -n "$ACTION_ERR_LOG" ]; then
    DETAIL_CONTENT="$DETAIL_CONTENT\n$ACTION_ERR_LOG"
  fi

  RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)
  RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" | sed 's/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g')

  echo ""
  cat << EOF
{
    "item_code": "$ID",
    "action_date": "$ACTION_DATE",
    "is_success": $IS_SUCCESS,
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
}
EOF
  exit 1
fi

# ---------------------------
# 조치 수행
# ---------------------------

# 1) crontab/at 명령어: root:root + 750 고정 + SUID/SGID 제거 명시
if [ -f "$CRONTAB_CMD" ]; then
  cp -a "$CRONTAB_CMD" "${CRONTAB_CMD}.bak_${TIMESTAMP}" 2>/dev/null || true
  ensure_owner_root_root "$CRONTAB_CMD"
  ensure_mode "$CRONTAB_CMD" 750
  remove_suid_sgid "$CRONTAB_CMD"
  MODIFIED=1
fi

if [ -f "$AT_CMD" ]; then
  cp -a "$AT_CMD" "${AT_CMD}.bak_${TIMESTAMP}" 2>/dev/null || true
  ensure_owner_root_root "$AT_CMD"
  ensure_mode "$AT_CMD" 750
  remove_suid_sgid "$AT_CMD"
  MODIFIED=1
fi

# 2) cron spool 디렉터리/파일: (추가) dir도 root:root + 750, 파일은 root:root + 640
for dir in "${CRON_SPOOL_DIRS[@]}"; do
  if [ -d "$dir" ]; then
    ensure_owner_root_root "$dir"
    ensure_mode "$dir" 750
    for f in "$dir"/*; do
      [ -f "$f" ] || continue
      ensure_owner_root_root "$f"
      ensure_mode "$f" 640
    done
    MODIFIED=1
  fi
done

# 3) /etc/crontab 파일: root:root + 640
for f in "${CRON_ETC_FILES[@]}"; do
  if [ -f "$f" ]; then
    cp -a "$f" "${f}.bak_${TIMESTAMP}" 2>/dev/null || true
    ensure_owner_root_root "$f"
    ensure_mode "$f" 640
    MODIFIED=1
  fi
done

# 4) /etc/cron.* 디렉토리: root:root + 750 (추가: 내부 파일도 640으로 정규화)
for d in "${CRON_ETC_DIRS[@]}"; do
  if [ -d "$d" ]; then
    ensure_owner_root_root "$d"
    ensure_mode "$d" 750
    for f in "$d"/*; do
      [ -f "$f" ] || continue
      ensure_owner_root_root "$f"
      ensure_mode "$f" 640
    done
    MODIFIED=1
  fi
done

# 5) at spool 디렉터리/파일: (추가) dir도 root:root + 750, 파일은 root:root + 640
for dir in "${AT_SPOOL_DIRS[@]}"; do
  if [ -d "$dir" ]; then
    ensure_owner_root_root "$dir"
    ensure_mode "$dir" 750
    for f in "$dir"/*; do
      [ -f "$f" ] || continue
      ensure_owner_root_root "$f"
      ensure_mode "$f" 640
    done
    MODIFIED=1
  fi
done

# 6) (추가) cron/at 접근제어 파일 조치: allow 생성(root만) + deny 제거(존재 시)
# - 파일 권한/소유자: root:root 640
# - root 외 사용 제한 목적
if [ -f "$CRON_DENY" ]; then
  cp -a "$CRON_DENY" "${CRON_DENY}.bak_${TIMESTAMP}" 2>/dev/null || true
  rm -f "$CRON_DENY" 2>/dev/null || { append_err "$CRON_DENY 삭제에 실패했습니다."; FAIL_FLAG=1; }
  MODIFIED=1
fi

if [ -f "$AT_DENY" ]; then
  cp -a "$AT_DENY" "${AT_DENY}.bak_${TIMESTAMP}" 2>/dev/null || true
  rm -f "$AT_DENY" 2>/dev/null || { append_err "$AT_DENY 삭제에 실패했습니다."; FAIL_FLAG=1; }
  MODIFIED=1
fi

# allow 파일은 "root"만 포함하도록 표준화
# (이미 존재하더라도 root만 남기도록 덮어씀)
echo "root" > "$CRON_ALLOW" 2>/dev/null || { append_err "$CRON_ALLOW 생성/수정에 실패했습니다."; FAIL_FLAG=1; }
ensure_owner_root_root "$CRON_ALLOW"
ensure_mode "$CRON_ALLOW" 640
MODIFIED=1

echo "root" > "$AT_ALLOW" 2>/dev/null || { append_err "$AT_ALLOW 생성/수정에 실패했습니다."; FAIL_FLAG=1; }
ensure_owner_root_root "$AT_ALLOW"
ensure_mode "$AT_ALLOW" 640
MODIFIED=1

# ---------------------------
# 조치 후 검증(현재/조치 후 상태만)
# ---------------------------

# 명령어(750 이하)
verify_file_max "$CRONTAB_CMD" 750
verify_file_max "$AT_CMD" 750

# spool 디렉터리(750 이하) + 내부 파일(640 이하)
for dir in "${CRON_SPOOL_DIRS[@]}"; do
  verify_dir_max "$dir" 750
  if [ -d "$dir" ]; then
    for f in "$dir"/*; do
      [ -f "$f" ] || continue
      verify_file_max "$f" 640
    done
  fi
done

for dir in "${AT_SPOOL_DIRS[@]}"; do
  verify_dir_max "$dir" 750
  if [ -d "$dir" ]; then
    for f in "$dir"/*; do
      [ -f "$f" ] || continue
      verify_file_max "$f" 640
    done
  fi
done

# /etc 파일/디렉토리
for f in "${CRON_ETC_FILES[@]}"; do
  verify_file_max "$f" 640
done

for d in "${CRON_ETC_DIRS[@]}"; do
  verify_dir_max "$d" 750
  if [ -d "$d" ]; then
    for f in "$d"/*; do
      [ -f "$f" ] || continue
      verify_file_max "$f" 640
    done
  fi
done

# allow/deny 최종 확인(allow는 640/root, deny는 없어야 함)
verify_file_max "$CRON_ALLOW" 640
verify_file_max "$AT_ALLOW" 640
if [ -f "$CRON_DENY" ]; then
  append_detail "file(after)=$CRON_DENY exists=true"
  FAIL_FLAG=1
fi
if [ -f "$AT_DENY" ]; then
  append_detail "file(after)=$AT_DENY exists=true"
  FAIL_FLAG=1
fi

# allow 내용 확인(조치 후 설정만)
CRON_ALLOW_USERS="$(grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$CRON_ALLOW" 2>/dev/null | tr -d '\r' | paste -sd ',' -)"
AT_ALLOW_USERS="$(grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$AT_ALLOW" 2>/dev/null | tr -d '\r' | paste -sd ',' -)"
append_detail "allow(after)=$CRON_ALLOW users=${CRON_ALLOW_USERS:-empty}"
append_detail "allow(after)=$AT_ALLOW users=${AT_ALLOW_USERS:-empty}"
if [ "$CRON_ALLOW_USERS" != "root" ]; then
  FAIL_FLAG=1
fi
if [ "$AT_ALLOW_USERS" != "root" ]; then
  FAIL_FLAG=1
fi

# ---------------------------
# 최종 판정
# ---------------------------
if [ "$FAIL_FLAG" -eq 0 ]; then
  IS_SUCCESS=1
  if [ "$MODIFIED" -eq 1 ]; then
    REASON_LINE="crontab 및 at 관련 파일(명령/설정/스풀/접근제어)의 소유자/권한이 기준에 맞게 설정되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
  else
    REASON_LINE="crontab 및 at 관련 파일(명령/설정/스풀/접근제어)의 소유자/권한이 이미 기준에 맞게 유지되어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
  fi
else
  IS_SUCCESS=0
  REASON_LINE="조치를 수행했으나 crontab 및 at 관련 파일(명령/설정/스풀/접근제어)의 소유자 또는 권한이 기준을 충족하지 못해 조치가 완료되지 않았습니다."
fi

if [ -n "$ACTION_ERR_LOG" ]; then
  DETAIL_CONTENT="$DETAIL_CONTENT\n$ACTION_ERR_LOG"
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