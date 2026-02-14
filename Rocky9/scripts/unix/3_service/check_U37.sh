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

TARGET_FILE="/usr/bin/crontab /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /var/spool/cron /var/spool/cron/crontabs /usr/bin/at /var/spool/at /var/spool/cron/atjobs"
CHECK_COMMAND='stat -c "%U %a %n" /usr/bin/crontab /usr/bin/at /etc/crontab 2>/dev/null; for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /var/spool/cron /var/spool/cron/crontabs /var/spool/at /var/spool/cron/atjobs; do [ -e "$d" ] && find "$d" -maxdepth 1 -type f -print -exec stat -c "%U %a %n" {} \; 2>/dev/null; [ -d "$d" ] && stat -c "%U %a %n" "$d" 2>/dev/null; done'

DETAIL_CONTENT=""
REASON_LINE=""

VULN_LIST=()

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

# 1) /usr/bin/crontab : owner root, perm <= 750
CRONTAB_CMD="/usr/bin/crontab"
if [ -f "$CRONTAB_CMD" ]; then
  O=$(stat -c '%U' "$CRONTAB_CMD" 2>/dev/null)
  P=$(stat -c '%a' "$CRONTAB_CMD" 2>/dev/null)
  [ "$O" != "root" ] && { STATUS="FAIL"; add_vuln "$CRONTAB_CMD" "$O" "$P" "소유자가 root가 아님"; }
  perm_exceeds "$P" 750 && { STATUS="FAIL"; add_vuln "$CRONTAB_CMD" "$O" "$P" "권한이 750 초과"; }
fi

# 2) crontab 스풀(사용자 crontab 파일) : owner root, perm <= 640
CRON_SPOOL_DIRS=("/var/spool/cron" "/var/spool/cron/crontabs")
for d in "${CRON_SPOOL_DIRS[@]}"; do
  if [ -d "$d" ]; then
    while IFS= read -r f; do
      O=$(stat -c '%U' "$f" 2>/dev/null)
      P=$(stat -c '%a' "$f" 2>/dev/null)
      [ "$O" != "root" ] && { STATUS="FAIL"; add_vuln "$f" "$O" "$P" "소유자가 root가 아님"; }
      perm_exceeds "$P" 640 && { STATUS="FAIL"; add_vuln "$f" "$O" "$P" "권한이 640 초과"; }
    done < <(find "$d" -maxdepth 1 -type f 2>/dev/null)
  fi
done

# 3) /etc/cron* : 파일은 640 이하, 디렉터리는 750 이하, owner root
CRON_ETC_ITEMS=("/etc/crontab" "/etc/cron.d" "/etc/cron.daily" "/etc/cron.hourly" "/etc/cron.weekly" "/etc/cron.monthly")
for it in "${CRON_ETC_ITEMS[@]}"; do
  if [ -e "$it" ]; then
    O=$(stat -c '%U' "$it" 2>/dev/null)
    P=$(stat -c '%a' "$it" 2>/dev/null)
    [ "$O" != "root" ] && { STATUS="FAIL"; add_vuln "$it" "$O" "$P" "소유자가 root가 아님"; }

    if [ -d "$it" ]; then
      perm_exceeds "$P" 750 && { STATUS="FAIL"; add_vuln "$it" "$O" "$P" "디렉터리 권한이 750 초과"; }
      # 디렉터리 내 파일도 640 이하(최상위만)
      while IFS= read -r f; do
        O2=$(stat -c '%U' "$f" 2>/dev/null)
        P2=$(stat -c '%a' "$f" 2>/dev/null)
        [ "$O2" != "root" ] && { STATUS="FAIL"; add_vuln "$f" "$O2" "$P2" "소유자가 root가 아님"; }
        perm_exceeds "$P2" 640 && { STATUS="FAIL"; add_vuln "$f" "$O2" "$P2" "권한이 640 초과"; }
      done < <(find "$it" -maxdepth 1 -type f 2>/dev/null)
    else
      perm_exceeds "$P" 640 && { STATUS="FAIL"; add_vuln "$it" "$O" "$P" "파일 권한이 640 초과"; }
    fi
  fi
done

# 4) /usr/bin/at : owner root, perm <= 750
AT_CMD="/usr/bin/at"
if [ -f "$AT_CMD" ]; then
  O=$(stat -c '%U' "$AT_CMD" 2>/dev/null)
  P=$(stat -c '%a' "$AT_CMD" 2>/dev/null)
  [ "$O" != "root" ] && { STATUS="FAIL"; add_vuln "$AT_CMD" "$O" "$P" "소유자가 root가 아님"; }
  perm_exceeds "$P" 750 && { STATUS="FAIL"; add_vuln "$AT_CMD" "$O" "$P" "권한이 750 초과"; }
fi

# 5) at 스풀 : owner root, perm <= 640
AT_SPOOL_DIRS=("/var/spool/at" "/var/spool/cron/atjobs")
for d in "${AT_SPOOL_DIRS[@]}"; do
  if [ -d "$d" ]; then
    while IFS= read -r f; do
      O=$(stat -c '%U' "$f" 2>/dev/null)
      P=$(stat -c '%a' "$f" 2>/dev/null)
      [ "$O" != "root" ] && { STATUS="FAIL"; add_vuln "$f" "$O" "$P" "소유자가 root가 아님"; }
      perm_exceeds "$P" 640 && { STATUS="FAIL"; add_vuln "$f" "$O" "$P" "권한이 640 초과"; }
    done < <(find "$d" -maxdepth 1 -type f 2>/dev/null)
  fi
done

# 결과 정리
if [ "$STATUS" = "PASS" ]; then
  REASON_LINE="cron/at 관련 명령 및 설정/스풀 파일의 소유자(root)와 권한(명령 750 이하, 파일 640 이하, 디렉터리 750 이하)이 적절하게 설정되어 비인가 사용자가 예약 작업을 조작할 위험이 없으므로 이 항목에 대한 보안 위협이 없습니다."
  DETAIL_CONTENT="none"
else
  REASON_LINE="cron/at 관련 명령 또는 설정/스풀 파일의 소유자/권한이 과도하게 설정되어 비인가 사용자가 예약 작업을 조작할 위험이 있으므로 취약합니다. 아래 항목의 소유자(root) 및 권한을 기준(명령 750 이하, 파일 640 이하, 디렉터리 750 이하)에 맞게 재설정해야 합니다."
  DETAIL_CONTENT=$(printf "%s\n" "${VULN_LIST[@]}")
fi

# raw_evidence 구성 (첫 줄: 평가 이유 / 다음 줄: 현재 설정값)
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