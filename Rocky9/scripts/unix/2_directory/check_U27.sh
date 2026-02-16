#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.1
# @Author: 권순형
# @Last Updated: 2026-02-15
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-27
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : $HOME/.rhosts, hosts.equiv 사용 금지
# @Description : $HOME/.rhosts 및 /etc/hosts.equiv 파일에 대해 적절한 소유자 및 접근 권한 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-27"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/hosts.equiv /home/*/.rhosts"

CHECK_COMMAND='
# service check
(ps -ef | grep -E "rlogin|rsh|rexec|in\.rlogind|in\.rshd|in\.rexecd" | grep -v grep 2>/dev/null);
(command -v systemctl >/dev/null 2>&1 && (systemctl is-active --quiet rlogin.socket || systemctl is-enabled --quiet rlogin.socket) 2>/dev/null && echo "rlogin.socket=active_or_enabled");
(command -v systemctl >/dev/null 2>&1 && (systemctl is-active --quiet rsh.socket || systemctl is-enabled --quiet rsh.socket) 2>/dev/null && echo "rsh.socket=active_or_enabled");
(command -v systemctl >/dev/null 2>&1 && (systemctl is-active --quiet rexec.socket || systemctl is-enabled --quiet rexec.socket) 2>/dev/null && echo "rexec.socket=active_or_enabled");
(command -v ss >/dev/null 2>&1 && ss -ltnp 2>/dev/null | grep -E ":(512|513|514)\b");
# file check
( [ -f /etc/hosts.equiv ] && stat -c "%n owner=%U perm=%a" /etc/hosts.equiv );
find /home -name ".rhosts" -type f -print0 2>/dev/null | xargs -0 -I{} stat -c "%n owner=%U perm=%a" "{}" 2>/dev/null;
grep -nE "^[[:space:]]*\+" /etc/hosts.equiv 2>/dev/null;
find /home -name ".rhosts" -type f -exec grep -nE "^[[:space:]]*\+" {} \; 2>/dev/null
'

DETAIL_CONTENT=""
REASON_LINE=""

VULN_LINES=""
FOUND_VULN="N"

# -----------------------------
# 1) rlogin/rsh/rexec "서비스 사용 여부" 판정 (필수 보강)
#  - ps만 보면 socket-activation을 놓칠 수 있으므로:
#    ps + systemctl(socket/service) + ss(포트)로 종합 판단
# -----------------------------
SERVICE_USED="NO"
SERVICE_EVIDENCE=""

# 1-1) 프로세스 기반
PS_USED=$(ps -ef | grep -E 'rlogin|rsh|rexec|in\.rlogind|in\.rshd|in\.rexecd' | grep -v grep 2>/dev/null)
if [ -n "$PS_USED" ]; then
  SERVICE_USED="YES"
  SERVICE_EVIDENCE+="ps_match,"
fi

# 1-2) systemctl socket/service 활성/enable 여부
if command -v systemctl >/dev/null 2>&1; then
  for u in rlogin.socket rsh.socket rexec.socket rlogin.service rsh.service rexec.service; do
    if systemctl is-active --quiet "$u" 2>/dev/null || systemctl is-enabled --quiet "$u" 2>/dev/null; then
      SERVICE_USED="YES"
      SERVICE_EVIDENCE+="systemctl_${u},"
    fi
  done
fi

# 1-3) 포트 리슨 여부(512/513/514)
if command -v ss >/dev/null 2>&1; then
  if ss -ltnp 2>/dev/null | grep -Eq ':(512|513|514)\b'; then
    SERVICE_USED="YES"
    SERVICE_EVIDENCE+="ports_512_513_514_listen,"
  fi
fi

SERVICE_EVIDENCE=${SERVICE_EVIDENCE%,}
SERVICE_LINE="service_used=${SERVICE_USED}"
if [ -n "$SERVICE_EVIDENCE" ]; then
  SERVICE_LINE="${SERVICE_LINE}(by:${SERVICE_EVIDENCE})"
fi

# -----------------------------
# 2) 점검 대상 파일 수집
# -----------------------------
RHOSTS_FILES=$(find /home -name ".rhosts" -type f 2>/dev/null)

# -----------------------------
# 3) 파일 소유자/권한/'+' 설정 점검
#   - 가이드 기준:
#     (서비스 사용 시) 소유자(root 또는 해당 계정), 권한 600 이하, '+' 없음
# -----------------------------
for file in /etc/hosts.equiv $RHOSTS_FILES; do
  [ -f "$file" ] || continue

  OWNER=$(stat -c %U "$file" 2>/dev/null)
  PERM=$(stat -c %a "$file" 2>/dev/null)

  # stat 실패/비정상 값 방어
  if ! [[ "$PERM" =~ ^[0-9]+$ ]]; then
    FOUND_VULN="Y"
    VULN_LINES+="$file perm_read_fail,"
    continue
  fi

  PLUS_EXIST=$(grep -nE '^[[:space:]]*\+' "$file" 2>/dev/null)

  # /etc/hosts.equiv 소유자 점검 (root만 허용)
  if [[ "$file" == "/etc/hosts.equiv" && "$OWNER" != "root" ]]; then
    FOUND_VULN="Y"
    VULN_LINES+="$file owner=$OWNER perm=$PERM(owner_must_be_root),"
  fi

  # .rhosts 소유자 점검 (해당 사용자 또는 root 허용)
  if [[ "$file" != "/etc/hosts.equiv" ]]; then
    FILE_USER=$(basename "$(dirname "$file")")
    if [[ "$OWNER" != "$FILE_USER" && "$OWNER" != "root" ]]; then
      FOUND_VULN="Y"
      VULN_LINES+="$file owner=$OWNER perm=$PERM(owner_must_be_${FILE_USER}_or_root),"
    fi
  fi

  # 권한 점검 (600 이하)
  if [ "$PERM" -gt 600 ]; then
    FOUND_VULN="Y"
    VULN_LINES+="$file owner=$OWNER perm=$PERM(perm_must_be_600_or_less),"
  fi

  # '+' 포함 여부 점검 (라인 시작 '+' 허용 금지)
  if [ -n "$PLUS_EXIST" ]; then
    FOUND_VULN="Y"
    FIRST_LINE=$(echo "$PLUS_EXIST" | head -n 1 | cut -d: -f1)
    VULN_LINES+="$file has_plus_entry(line:${FIRST_LINE}),"
  fi
done

# 끝 쉼표 제거
VULN_LINES=${VULN_LINES%,}

# -----------------------------
# 4) 최종 판단
#   - 가이드: 서비스 미사용이면 양호(단, 정책상 파일은 점검 가능)
#   - 서비스 사용 + 기준 미충족이면 취약
# -----------------------------
if [ "$SERVICE_USED" = "YES" ] && [ "$FOUND_VULN" = "Y" ]; then
  STATUS="FAIL"
  REASON_LINE="rlogin/rsh/rexec 서비스를 사용 중이며 /etc/hosts.equiv 또는 .rhosts에서 소유자/권한 설정이 부적절하거나 '+' 허용 설정이 존재하여 인증 우회 및 무단 원격 접속 위험이 있습니다. 소유자를 root/해당 계정으로 설정하고 권한을 600 이하로 제한하며 '+' 설정을 제거해야 합니다."
  DETAIL_CONTENT="${SERVICE_LINE},${VULN_LINES}"
else
  STATUS="PASS"
  if [ "$SERVICE_USED" = "NO" ]; then
    REASON_LINE="rlogin/rsh/rexec 서비스를 사용하지 않아 해당 위험이 낮으며, 점검 대상 파일에서도 가이드 위반(소유자/권한/+)이 확인되지 않았습니다."
  else
    REASON_LINE="rlogin/rsh/rexec 서비스를 사용 중이더라도 /etc/hosts.equiv 및 .rhosts의 소유자/권한이 안전하고 '+' 허용 설정이 없어 인증 우회 위험이 없습니다."
  fi

  if [ -n "$VULN_LINES" ]; then
    # 서비스는 미사용이지만 파일 정책 위반이 있으면 참고로 남김(가이드의 '서비스 미사용이면 양호' 취지 유지)
    DETAIL_CONTENT="${SERVICE_LINE},policy_notes:${VULN_LINES}"
  else
    DETAIL_CONTENT="${SERVICE_LINE},all_files_ok"
  fi
fi

# raw_evidence 구성 (detail은 쉼표 구분 문자열로 유지)
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE, $DETAIL_CONTENT",
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