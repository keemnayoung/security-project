#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-40
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : NFS 접근 통제
# @Description : NFS(Network File System)의 접근 통제 설정 적용 여부 점검
# @Criteria_Good : 접근 통제가 설정되어 있으며 NFS 설정 파일 접근 권한이 644 이하인 경우
# @Criteria_Bad : 접근 통제가 설정되어 있지 않고 NFS 설정 파일 접근 권한이 644를 초과하는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-40 NFS 접근 통제

# 기본 변수
ID="U-40"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/exports"
CHECK_COMMAND='[ -f /etc/exports ] && (stat -c "%U %a %n" /etc/exports; grep -nEv "^[[:space:]]*#|^[[:space:]]*$" /etc/exports || echo "exports_empty") || echo "exports_not_found"'

DETAIL_CONTENT=""
REASON_LINE=""

# 점검 결과 누적
VULN_FLAGS=()
add_vuln() { [ -n "$1" ] && VULN_FLAGS+=("$1"); }

# 1) /etc/exports 존재 여부
if [ ! -f "$TARGET_FILE" ]; then
  STATUS="PASS"
  REASON_LINE="NFS exports 파일(/etc/exports)이 존재하지 않아 NFS 공유 설정이 적용되지 않으므로 이 항목에 대한 보안 위협이 없습니다."
  DETAIL_CONTENT="exports_not_found"
else
  OWNER=$(stat -c '%U' "$TARGET_FILE" 2>/dev/null | tr -d '[:space:]')
  PERM=$(stat -c '%a' "$TARGET_FILE" 2>/dev/null | tr -d '[:space:]')

  # 2) 파일 소유자/권한 점검 (가이드: root, 644 이하)
  if [ "$OWNER" != "root" ]; then
    add_vuln "파일 소유자 부적절(owner=${OWNER})"
  fi
  if [ -n "$PERM" ] && [ "$PERM" -gt 644 ]; then
    add_vuln "파일 권한 과대(perm=${PERM})"
  fi

  # 3) 접근 통제 설정 점검
  # - 주석/공백 제외 후 라인 기준
  # - everyone(*) 허용, no_root_squash 사용 여부를 핵심 위험으로 판단
  EXPORT_LINES=$(grep -nEv "^[[:space:]]*#|^[[:space:]]*$" "$TARGET_FILE" 2>/dev/null || true)

  if [ -z "$EXPORT_LINES" ]; then
    # exports 파일은 있으나 설정이 비어있으면 "NFS 미사용"에 가까움
    STATUS="PASS"
    REASON_LINE="/etc/exports 파일은 존재하지만 유효한 export 설정이 없어 NFS 공유가 적용되지 않으므로 이 항목에 대한 보안 위협이 없습니다."
    DETAIL_CONTENT="exports_empty (owner=${OWNER}, perm=${PERM})"
  else
    # everyone(*) 공유 탐지: 호스트 필드에 단독 '*' 또는 '*(' 형태를 단순 탐지
    if echo "$EXPORT_LINES" | grep -qE "([[:space:]]|^)\*([[:space:]]|$|\()"; then
      add_vuln "모든 호스트(*)에 공유 허용"
    fi

    # no_root_squash 탐지
    if echo "$EXPORT_LINES" | grep -qiE "no_root_squash"; then
      add_vuln "no_root_squash 옵션 사용"
    fi

    if [ "${#VULN_FLAGS[@]}" -gt 0 ]; then
      STATUS="FAIL"
      REASON_LINE="NFS 공유 설정(/etc/exports)에서 접근 통제가 미흡하거나 설정 파일 권한이 과대하여, 비인가 호스트 접근 또는 root 권한 상승 위험이 있으므로 취약합니다. 운영 중인 공유 범위를 점검하고 허용 호스트를 제한해야 합니다."
      DETAIL_CONTENT=$(
        printf "owner=%s perm=%s\n" "${OWNER:-unknown}" "${PERM:-unknown}"
        printf "findings:\n"
        printf "%s\n" "${VULN_FLAGS[@]}"
        printf "exports(sample top5):\n"
        echo "$EXPORT_LINES" | head -n 5
      )
    else
      STATUS="PASS"
      REASON_LINE="NFS exports 파일의 소유자/권한이 적절하며, everyone(*) 공유 또는 no_root_squash와 같은 위험 설정이 확인되지 않아 이 항목에 대한 보안 위협이 없습니다."
      DETAIL_CONTENT=$(
        printf "owner=%s perm=%s\n" "${OWNER:-unknown}" "${PERM:-unknown}"
        printf "exports(sample top5):\n"
        echo "$EXPORT_LINES" | head -n 5
      )
    fi
  fi
fi

# raw_evidence 구성 (첫 줄: 평가 이유 / 다음 줄부터: 현재 설정값)
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