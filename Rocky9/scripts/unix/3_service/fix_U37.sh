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

R_SERVICES_UNUSED=""

# 대상(가이드 기준)
CRONTAB_CMD="/usr/bin/crontab"
AT_CMD="/usr/bin/at"

CRON_SPOOL_DIRS=("/var/spool/cron" "/var/spool/cron/crontabs")
CRON_ETC_FILES=("/etc/crontab")
CRON_ETC_DIRS=("/etc/cron.d" "/etc/cron.daily" "/etc/cron.hourly" "/etc/cron.weekly" "/etc/cron.monthly")
AT_SPOOL_DIRS=("/var/spool/at" "/var/spool/cron/atjobs")

TARGET_FILE="$CRONTAB_CMD
$AT_CMD
${CRON_SPOOL_DIRS[*]}
${CRON_ETC_FILES[*]}
${CRON_ETC_DIRS[*]}
${AT_SPOOL_DIRS[*]}"

CHECK_COMMAND='
for p in /usr/bin/crontab /usr/bin/at; do
  [ -e "$p" ] && stat -c "%U %G %a %n" "$p" 2>/dev/null || echo "not_found:$p";
done;
for d in /var/spool/cron /var/spool/cron/crontabs /var/spool/at /var/spool/cron/atjobs; do
  [ -d "$d" ] && find "$d" -maxdepth 1 -type f -exec stat -c "%U %G %a %n" {} \; 2>/dev/null | head -n 50 || echo "dir_not_found:$d";
done;
for f in /etc/crontab; do
  [ -f "$f" ] && stat -c "%U %G %a %n" "$f" 2>/dev/null || echo "not_found:$f";
done;
for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
  [ -d "$d" ] && stat -c "%U %G %a %n" "$d" 2>/dev/null || echo "dir_not_found:$d";
done
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
  # 숫자 형식 검증
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

# 검증(현재/조치 후 상태만 기록)
verify_file_max() {
  local path="$1"
  local max="$2"
  [ -f "$path" ] || return 0
  local owner group perm
  owner="$(stat -c '%U' "$path" 2>/dev/null)"
  group="$(stat -c '%G' "$path" 2>/dev/null)"
  perm="$(stat -c '%a' "$path" 2>/dev/null)"
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
  owner="$(stat -c '%U' "$path" 2>/dev/null)"
  group="$(stat -c '%G' "$path" 2>/dev/null)"
  perm="$(stat -c '%a' "$path" 2>/dev/null)"
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

# 1) crontab/at 명령어: root:root + 750 고정(특수권한도 제거됨)
if [ -f "$CRONTAB_CMD" ]; then
  cp -a "$CRONTAB_CMD" "${CRONTAB_CMD}.bak_${TIMESTAMP}" 2>/dev/null || true
  ensure_owner_root_root "$CRONTAB_CMD"
  ensure_mode "$CRONTAB_CMD" 750
  MODIFIED=1
fi

if [ -f "$AT_CMD" ]; then
  cp -a "$AT_CMD" "${AT_CMD}.bak_${TIMESTAMP}" 2>/dev/null || true
  ensure_owner_root_root "$AT_CMD"
  ensure_mode "$AT_CMD" 750
  MODIFIED=1
fi

# 2) cron spool 파일: root:root + 640
for dir in "${CRON_SPOOL_DIRS[@]}"; do
  if [ -d "$dir" ]; then
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

# 4) /etc/cron.* 디렉토리: root:root + 750
for d in "${CRON_ETC_DIRS[@]}"; do
  if [ -d "$d" ]; then
    ensure_owner_root_root "$d"
    ensure_mode "$d" 750
    MODIFIED=1
  fi
done

# 5) at spool 파일: root:root + 640
for dir in "${AT_SPOOL_DIRS[@]}"; do
  if [ -d "$dir" ]; then
    for f in "$dir"/*; do
      [ -f "$f" ] || continue
      ensure_owner_root_root "$f"
      ensure_mode "$f" 640
    done
    MODIFIED=1
  fi
done

# ---------------------------
# 조치 후 검증(현재/조치 후 상태만)
# ---------------------------
# 명령어
verify_file_max "$CRONTAB_CMD" 750
verify_file_max "$AT_CMD" 750

# spool 파일들
for dir in "${CRON_SPOOL_DIRS[@]}"; do
  if [ -d "$dir" ]; then
    # dir 자체 권한은 가이드에 명시가 없어서 here는 기록만 하고 파일만 강제(필요시 dir도 750으로 바꿀 수 있음)
    for f in "$dir"/*; do
      [ -f "$f" ] || continue
      verify_file_max "$f" 640
    done
  fi
done

for dir in "${AT_SPOOL_DIRS[@]}"; do
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
done

# ---------------------------
# 최종 판정
# ---------------------------
if [ "$FAIL_FLAG" -eq 0 ]; then
  IS_SUCCESS=1
  if [ "$MODIFIED" -eq 1 ]; then
    REASON_LINE="crontab 및 at 관련 파일의 소유자/권한이 기준에 맞게 설정되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
  else
    REASON_LINE="crontab 및 at 관련 파일의 소유자/권한이 이미 기준에 맞게 유지되어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
  fi
else
  IS_SUCCESS=0
  REASON_LINE="조치를 수행했으나 crontab 및 at 관련 파일의 소유자 또는 권한이 기준을 충족하지 못해 조치가 완료되지 않았습니다."
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
