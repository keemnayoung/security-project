#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-37
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : crontab 설정파일 권한 설정 미흡
# @Description : crontab 및 at 서비스 관련 파일의 권한 적절성 여부 점검
# @Criteria_Good : crontab 및 at 명령어에 일반 사용자 실행 권한이 제거되어 있으며, cron 및 at 관련 파일 권한이 640 이하인 경우
# @Criteria_Bad :  crontab 및 at 명령어에 일반 사용자 실행 권한이 부여되어 있으며, cron 및 at 관련 파일 권한이 640 이상인 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-37 crontab 설정파일 권한 설정 미흡


# 기본 변수
ID="U-37"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/usr/bin/crontab /usr/bin/at /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /var/spool/cron /var/spool/cron/crontabs /var/spool/at /var/spool/cron/atjobs /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny"

CHECK_COMMAND='
stat -c "%U %a %A %n" /usr/bin/crontab /usr/bin/at /etc/crontab /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny 2>/dev/null;
for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /var/spool/cron /var/spool/cron/crontabs /var/spool/at /var/spool/cron/atjobs; do
  [ -d "$d" ] && stat -c "%U %a %A %n" "$d" 2>/dev/null;
  [ -e "$d" ] && find "$d" -maxdepth 1 -type f -print -exec stat -c "%U %a %A %n" {} \; 2>/dev/null;
done;
( [ -f /etc/cron.allow ] && echo "[cron.allow]" && grep -nEv "^[[:space:]]*#|^[[:space:]]*$" /etc/cron.allow 2>/dev/null ) || echo "cron.allow_not_found_or_empty";
( [ -f /etc/at.allow ] && echo "[at.allow]" && grep -nEv "^[[:space:]]*#|^[[:space:]]*$" /etc/at.allow 2>/dev/null ) || echo "at.allow_not_found_or_empty";
'

DETAIL_CONTENT=""
REASON_LINE=""

VULN_LIST=()
INFO_LIST=()

# 권한 비교(정수 비교)
perm_exceeds() {
  local cur="$1"
  local max="$2"
  [ -n "$cur" ] && [ "$cur" -gt "$max" ]
}

add_vuln() {
  local path="$1"
  local owner="$2"
  local perm="$3"
  local why="$4"
  VULN_LIST+=("${path} (owner=${owner}, perm=${perm}) - ${why}")
}

add_info() {
  local msg="$1"
  INFO_LIST+=("$msg")
}

# SUID/SGID 체크: stat -c '%a' 결과가 4자리면 첫 자리가 4/5/6/7 => suid/sgid/sticky 중 하나 이상
has_suid_sgid_bits() {
  local mode="$1"
  if [[ "$mode" =~ ^[0-7]{4}$ ]]; then
    local high="${mode:0:1}"
    # 4(suid),2(sgid),1(sticky) 포함 가능 => 4~7은 뭔가 특수비트가 켜진 것
    [ "$high" -ge 1 ] && return 0
  fi
  return 1
}

# 접근제어(allow/deny) 유효성 체크
# - allow가 있으면: allow에 있는 사용자만 사용 가능 => 최소 root만 있어야 "일반 사용자 사용 제한" 충족
# - allow가 없고 deny만 있으면: deny에 없는 사용자는 사용 가능 => 기본적으로 광범위 허용이 될 수 있어 취약 판단(가이드 취지)
check_access_control() {
  local allow_file="$1"   # /etc/cron.allow or /etc/at.allow
  local deny_file="$2"    # /etc/cron.deny or /etc/at.deny
  local svc_name="$3"     # cron or at

  local allow_ok=0

  if [ -f "$allow_file" ]; then
    # 소유자/권한(<=640) 기본 체크
    local ao ap
    ao=$(stat -c '%U' "$allow_file" 2>/dev/null)
    ap=$(stat -c '%a' "$allow_file" 2>/dev/null)
    add_info "${allow_file}: owner=${ao}, perm=${ap}"
    [ "$ao" != "root" ] && { STATUS="FAIL"; add_vuln "$allow_file" "$ao" "$ap" "소유자가 root가 아님"; }
    perm_exceeds "$ap" 640 && { STATUS="FAIL"; add_vuln "$allow_file" "$ao" "$ap" "권한이 640 초과"; }

    # allow 내용 점검(주석/공백 제외)
    local users
    users=$(grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$allow_file" 2>/dev/null | tr -d '\r')
    if [ -z "$users" ]; then
      STATUS="FAIL"
      add_vuln "$allow_file" "${ao:-unknown}" "${ap:-unknown}" "허용 사용자 목록이 비어있음(제한 정책 불명확)"
    else
      # root 외 사용자가 있으면 "일반 사용자 사용 제한" 관점에서 취약
      local non_root
      non_root=$(echo "$users" | awk 'tolower($0)!="root"{print}' | head -n 1)
      if [ -n "$non_root" ]; then
        STATUS="FAIL"
        add_vuln "$allow_file" "${ao:-unknown}" "${ap:-unknown}" "root 외 사용자(${non_root})가 허용되어 일반 사용자 사용 제한 미흡"
      else
        allow_ok=1
      fi
    fi
  fi

  # allow가 없으면 deny 존재/미존재 모두 “일반 사용자 제한 미흡”으로 취약 처리(가이드 취지에 맞춤)
  if [ "$allow_ok" -eq 0 ]; then
    if [ -f "$deny_file" ]; then
      local doo dp
      doo=$(stat -c '%U' "$deny_file" 2>/dev/null)
      dp=$(stat -c '%a' "$deny_file" 2>/dev/null)
      add_info "${deny_file}: owner=${doo}, perm=${dp}"
      # 파일 권한/소유자 자체도 점검(<=640, root)
      [ "$doo" != "root" ] && { STATUS="FAIL"; add_vuln "$deny_file" "$doo" "$dp" "소유자가 root가 아님"; }
      perm_exceeds "$dp" 640 && { STATUS="FAIL"; add_vuln "$deny_file" "$doo" "$dp" "권한이 640 초과"; }

      STATUS="FAIL"
      add_vuln "$deny_file" "${doo:-unknown}" "${dp:-unknown}" "${svc_name}.allow 미존재 상태에서 ${svc_name}.deny만으로는 일반 사용자 사용 제한이 충분하지 않을 수 있음(allow 기반 제한 권고)"
    else
      STATUS="FAIL"
      add_vuln "${allow_file}/${deny_file}" "N/A" "N/A" "${svc_name}.allow/${svc_name}.deny 모두 미존재로 일반 사용자 사용 제한 미적용 가능"
    fi
  fi
}

# 1) /usr/bin/crontab : owner root, perm <= 750 + SUID/SGID 제거 확인
CRONTAB_CMD="/usr/bin/crontab"
if [ -f "$CRONTAB_CMD" ]; then
  O=$(stat -c '%U' "$CRONTAB_CMD" 2>/dev/null)
  P=$(stat -c '%a' "$CRONTAB_CMD" 2>/dev/null)
  add_info "${CRONTAB_CMD}: owner=${O}, perm=${P}"
  [ "$O" != "root" ] && { STATUS="FAIL"; add_vuln "$CRONTAB_CMD" "$O" "$P" "소유자가 root가 아님"; }
  perm_exceeds "$P" 750 && { STATUS="FAIL"; add_vuln "$CRONTAB_CMD" "$O" "$P" "권한이 750 초과"; }
  if has_suid_sgid_bits "$P"; then
    STATUS="FAIL"
    add_vuln "$CRONTAB_CMD" "$O" "$P" "SUID/SGID/특수비트가 설정되어 있음(가이드 권고: 제거 필요)"
  fi
else
  add_info "${CRONTAB_CMD}: not_found"
fi

# 2) crontab 스풀(사용자 crontab 파일) : owner root, perm <= 640
CRON_SPOOL_DIRS=("/var/spool/cron" "/var/spool/cron/crontabs")
for d in "${CRON_SPOOL_DIRS[@]}"; do
  if [ -d "$d" ]; then
    Od=$(stat -c '%U' "$d" 2>/dev/null)
    Pd=$(stat -c '%a' "$d" 2>/dev/null)
    add_info "${d}: owner=${Od}, perm=${Pd}"
    [ "$Od" != "root" ] && { STATUS="FAIL"; add_vuln "$d" "$Od" "$Pd" "소유자가 root가 아님"; }
    perm_exceeds "$Pd" 750 && { STATUS="FAIL"; add_vuln "$d" "$Od" "$Pd" "디렉터리 권한이 750 초과"; }

    while IFS= read -r f; do
      O=$(stat -c '%U' "$f" 2>/dev/null)
      P=$(stat -c '%a' "$f" 2>/dev/null)
      [ "$O" != "root" ] && { STATUS="FAIL"; add_vuln "$f" "$O" "$P" "소유자가 root가 아님"; }
      perm_exceeds "$P" 640 && { STATUS="FAIL"; add_vuln "$f" "$O" "$P" "권한이 640 초과"; }
    done < <(find "$d" -maxdepth 1 -type f 2>/dev/null)
  else
    add_info "${d}: not_found_or_not_dir"
  fi
done

# 3) /etc/cron* : 파일은 640 이하, 디렉터리는 750 이하, owner root
CRON_ETC_ITEMS=("/etc/crontab" "/etc/cron.d" "/etc/cron.daily" "/etc/cron.hourly" "/etc/cron.weekly" "/etc/cron.monthly")
for it in "${CRON_ETC_ITEMS[@]}"; do
  if [ -e "$it" ]; then
    O=$(stat -c '%U' "$it" 2>/dev/null)
    P=$(stat -c '%a' "$it" 2>/dev/null)
    add_info "${it}: owner=${O}, perm=${P}"
    [ "$O" != "root" ] && { STATUS="FAIL"; add_vuln "$it" "$O" "$P" "소유자가 root가 아님"; }

    if [ -d "$it" ]; then
      perm_exceeds "$P" 750 && { STATUS="FAIL"; add_vuln "$it" "$O" "$P" "디렉터리 권한이 750 초과"; }
      while IFS= read -r f; do
        O2=$(stat -c '%U' "$f" 2>/dev/null)
        P2=$(stat -c '%a' "$f" 2>/dev/null)
        [ "$O2" != "root" ] && { STATUS="FAIL"; add_vuln "$f" "$O2" "$P2" "소유자가 root가 아님"; }
        perm_exceeds "$P2" 640 && { STATUS="FAIL"; add_vuln "$f" "$O2" "$P2" "권한이 640 초과"; }
      done < <(find "$it" -maxdepth 1 -type f 2>/dev/null)
    else
      perm_exceeds "$P" 640 && { STATUS="FAIL"; add_vuln "$it" "$O" "$P" "파일 권한이 640 초과"; }
    fi
  else
    add_info "${it}: not_found"
  fi
done

# 4) /usr/bin/at : owner root, perm <= 750 + SUID/SGID 제거 확인
AT_CMD="/usr/bin/at"
if [ -f "$AT_CMD" ]; then
  O=$(stat -c '%U' "$AT_CMD" 2>/dev/null)
  P=$(stat -c '%a' "$AT_CMD" 2>/dev/null)
  add_info "${AT_CMD}: owner=${O}, perm=${P}"
  [ "$O" != "root" ] && { STATUS="FAIL"; add_vuln "$AT_CMD" "$O" "$P" "소유자가 root가 아님"; }
  perm_exceeds "$P" 750 && { STATUS="FAIL"; add_vuln "$AT_CMD" "$O" "$P" "권한이 750 초과"; }
  if has_suid_sgid_bits "$P"; then
    STATUS="FAIL"
    add_vuln "$AT_CMD" "$O" "$P" "SUID/SGID/특수비트가 설정되어 있음(가이드 권고: 제거 필요)"
  fi
else
  add_info "${AT_CMD}: not_found"
fi

# 5) at 스풀 : owner root, perm <= 640 (dir 750 이하)
AT_SPOOL_DIRS=("/var/spool/at" "/var/spool/cron/atjobs")
for d in "${AT_SPOOL_DIRS[@]}"; do
  if [ -d "$d" ]; then
    Od=$(stat -c '%U' "$d" 2>/dev/null)
    Pd=$(stat -c '%a' "$d" 2>/dev/null)
    add_info "${d}: owner=${Od}, perm=${Pd}"
    [ "$Od" != "root" ] && { STATUS="FAIL"; add_vuln "$d" "$Od" "$Pd" "소유자가 root가 아님"; }
    perm_exceeds "$Pd" 750 && { STATUS="FAIL"; add_vuln "$d" "$Od" "$Pd" "디렉터리 권한이 750 초과"; }

    while IFS= read -r f; do
      O=$(stat -c '%U' "$f" 2>/dev/null)
      P=$(stat -c '%a' "$f" 2>/dev/null)
      [ "$O" != "root" ] && { STATUS="FAIL"; add_vuln "$f" "$O" "$P" "소유자가 root가 아님"; }
      perm_exceeds "$P" 640 && { STATUS="FAIL"; add_vuln "$f" "$O" "$P" "권한이 640 초과"; }
    done < <(find "$d" -maxdepth 1 -type f 2>/dev/null)
  else
    add_info "${d}: not_found_or_not_dir"
  fi
done

# 6) cron/at 접근제어 파일 점검(필수 추가)
check_access_control "/etc/cron.allow" "/etc/cron.deny" "cron"
check_access_control "/etc/at.allow"   "/etc/at.deny"   "at"

# 결과 정리 (요구 문구 반영)
if [ "$STATUS" = "PASS" ]; then
  REASON_LINE="cron/at 관련 명령(/usr/bin/crontab, /usr/bin/at)의 소유자가 root이고 권한이 750 이하이며 SUID/SGID가 제거되어 있고, cron/at 접근제어 파일(allow)이 root만 허용하도록 설정되어 있으며, cron/at 관련 파일 권한이 640 이하로 관리되고 있어 이 항목에 대한 보안 위협이 없습니다."
  DETAIL_CONTENT=$(printf "%s\n" "${INFO_LIST[@]}")
else
  REASON_LINE="cron/at 관련 명령 또는 cron/at 접근제어(allow/deny) 설정이 미흡하거나 관련 파일 권한/소유자 또는 SUID/SGID 설정이 기준에 부합하지 않아 취약합니다. 조치 방법: (1) /usr/bin/crontab, /usr/bin/at 소유자 root 및 권한 750 이하로 조정, SUID/SGID 제거 (chmod u-s,g-s), (2) /etc/cron.allow 및 /etc/at.allow를 생성하여 root만 등록하고 권한 640 이하/소유자 root로 설정, (3) cron/at 관련 스풀/설정 파일은 소유자 root 및 권한 640 이하(디렉터리 750 이하)로 재설정."
  DETAIL_CONTENT=$(printf "%s\n" "${VULN_LIST[@]}")
fi

# raw_evidence 구성 (첫 줄: 평가 이유 / 다음 줄: 현재 설정값)
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE
$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
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