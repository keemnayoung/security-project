#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.1
# @Author: 이가영
# @Last Updated: 2026-02-15
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
CHECK_COMMAND='
( command -v systemctl >/dev/null 2>&1 && (
    systemctl is-active nfs-server 2>/dev/null || true;
    systemctl is-enabled nfs-server 2>/dev/null || true;
    systemctl is-active rpcbind 2>/dev/null || true;
    systemctl is-enabled rpcbind 2>/dev/null || true;
  ) ) || echo "systemctl_not_found";
[ -f /etc/exports ] && (stat -c "%U %a %n" /etc/exports; grep -nEv "^[[:space:]]*#|^[[:space:]]*$" /etc/exports || echo "exports_empty") || echo "exports_not_found"
'
CHECK_COMMAND="$(echo "$CHECK_COMMAND" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g')"

DETAIL_CONTENT=""
REASON_LINE=""

# 점검 결과 누적
VULN_FLAGS=()
add_vuln() { [ -n "$1" ] && VULN_FLAGS+=("$1"); }

# NFS 서비스 상태 점검 (Rocky Linux 9/10 기준: nfs-server, rpcbind)
NFS_ACTIVE="unknown"
NFS_ENABLED="unknown"
RPCBIND_ACTIVE="unknown"
RPCBIND_ENABLED="unknown"

if command -v systemctl >/dev/null 2>&1; then
  NFS_ACTIVE="$(systemctl is-active nfs-server 2>/dev/null | tr -d '[:space:]')"
  NFS_ENABLED="$(systemctl is-enabled nfs-server 2>/dev/null | tr -d '[:space:]')"
  RPCBIND_ACTIVE="$(systemctl is-active rpcbind 2>/dev/null | tr -d '[:space:]')"
  RPCBIND_ENABLED="$(systemctl is-enabled rpcbind 2>/dev/null | tr -d '[:space:]')"
else
  add_vuln "systemctl 미존재로 서비스 상태 확인 불가"
fi

# exports 파일 점검
EXPORT_LINES=""
OWNER=""
PERM=""

if [ ! -f "$TARGET_FILE" ]; then
  # /etc/exports 미존재: NFS 미사용으로 간주 가능하나, 서비스가 켜져 있으면 취약으로 처리(가이드: 미사용 시 중지/비활성)
  if [ "$NFS_ACTIVE" = "active" ] || [ "$NFS_ENABLED" = "enabled" ] || [ "$RPCBIND_ACTIVE" = "active" ] || [ "$RPCBIND_ENABLED" = "enabled" ]; then
    STATUS="FAIL"
    REASON_LINE="nfs-server/rpcbind 서비스가 활성화(또는 enable)되어 있으나 /etc/exports가 존재하지 않아 접근 통제 설정이 적용되지 않은 상태이므로 취약합니다. 조치: NFS 미사용 시 nfs-server 및 rpcbind 서비스를 중지/비활성화하고, 사용 시 /etc/exports를 생성하여 허용 호스트만 지정 후 exports -ra로 적용하세요."
    DETAIL_CONTENT=$(
      printf "services: nfs-server(active=%s enabled=%s), rpcbind(active=%s enabled=%s)\n" \
        "${NFS_ACTIVE:-unknown}" "${NFS_ENABLED:-unknown}" "${RPCBIND_ACTIVE:-unknown}" "${RPCBIND_ENABLED:-unknown}"
      printf "exports: not_found\n"
    )
  else
    STATUS="PASS"
    REASON_LINE="NFS 관련 서비스(nfs-server/rpcbind)가 비활성 상태이며 /etc/exports 파일이 존재하지 않아 NFS 공유 설정이 적용되지 않은 상태이므로 이 항목에 대한 보안 위협이 없습니다."
    DETAIL_CONTENT=$(
      printf "services: nfs-server(active=%s enabled=%s), rpcbind(active=%s enabled=%s)\n" \
        "${NFS_ACTIVE:-unknown}" "${NFS_ENABLED:-unknown}" "${RPCBIND_ACTIVE:-unknown}" "${RPCBIND_ENABLED:-unknown}"
      printf "exports: not_found\n"
    )
  fi
else
  # stat 수집(실패 방어)
  OWNER=$(stat -c '%U' "$TARGET_FILE" 2>/dev/null | tr -d '[:space:]')
  PERM=$(stat -c '%a' "$TARGET_FILE" 2>/dev/null | tr -d '[:space:]')

  if [ -z "$OWNER" ] || [ -z "$PERM" ]; then
    add_vuln "/etc/exports 소유자/권한 수집 실패"
  else
    # 파일 소유자/권한 점검 (가이드: root, 644 이하)
    if [ "$OWNER" != "root" ]; then
      add_vuln "파일 소유자 부적절(owner=${OWNER})"
    fi
    if [ "$PERM" -gt 644 ] 2>/dev/null; then
      add_vuln "파일 권한 과대(perm=${PERM})"
    fi
  fi

  # 유효 export 라인 수집
  EXPORT_LINES=$(grep -nEv "^[[:space:]]*#|^[[:space:]]*$" "$TARGET_FILE" 2>/dev/null || true)

  if [ -z "$EXPORT_LINES" ]; then
    # exports 파일은 있으나 설정이 비어있음
    if [ "$NFS_ACTIVE" = "active" ] || [ "$NFS_ENABLED" = "enabled" ] || [ "$RPCBIND_ACTIVE" = "active" ] || [ "$RPCBIND_ENABLED" = "enabled" ]; then
      STATUS="FAIL"
      REASON_LINE="/etc/exports 파일은 존재하지만 유효한 export 설정이 없고, NFS 관련 서비스가 활성화(또는 enable)되어 있어 불필요한 서비스 노출 상태이므로 취약합니다. 조치: NFS 미사용 시 nfs-server/rpcbind 서비스를 중지/비활성화하거나, 사용 시 /etc/exports에 허용 호스트만 지정하고 exports -ra로 적용하세요."
      DETAIL_CONTENT=$(
        printf "services: nfs-server(active=%s enabled=%s), rpcbind(active=%s enabled=%s)\n" \
          "${NFS_ACTIVE:-unknown}" "${NFS_ENABLED:-unknown}" "${RPCBIND_ACTIVE:-unknown}" "${RPCBIND_ENABLED:-unknown}"
        printf "exports: empty (owner=%s perm=%s)\n" "${OWNER:-unknown}" "${PERM:-unknown}"
      )
    else
      # 서비스도 꺼져 있고 export도 없음 → 미사용
      if [ "${#VULN_FLAGS[@]}" -gt 0 ]; then
        STATUS="FAIL"
        REASON_LINE="/etc/exports 파일의 소유자/권한이 가이드 기준에 맞지 않거나 정보 수집이 불가하여 취약합니다. 조치: /etc/exports 소유자를 root로, 권한을 644로 설정하세요."
        DETAIL_CONTENT=$(
          printf "services: nfs-server(active=%s enabled=%s), rpcbind(active=%s enabled=%s)\n" \
            "${NFS_ACTIVE:-unknown}" "${NFS_ENABLED:-unknown}" "${RPCBIND_ACTIVE:-unknown}" "${RPCBIND_ENABLED:-unknown}"
          printf "exports: empty (owner=%s perm=%s)\n" "${OWNER:-unknown}" "${PERM:-unknown}"
          printf "findings:\n"
          printf "%s\n" "${VULN_FLAGS[@]}"
        )
      else
        STATUS="PASS"
        REASON_LINE="/etc/exports에 유효한 공유 설정이 없고 NFS 관련 서비스도 비활성 상태라 NFS 공유가 적용되지 않은 상태이므로 이 항목에 대한 보안 위협이 없습니다."
        DETAIL_CONTENT=$(
          printf "services: nfs-server(active=%s enabled=%s), rpcbind(active=%s enabled=%s)\n" \
            "${NFS_ACTIVE:-unknown}" "${NFS_ENABLED:-unknown}" "${RPCBIND_ACTIVE:-unknown}" "${RPCBIND_ENABLED:-unknown}"
          printf "exports: empty (owner=%s perm=%s)\n" "${OWNER:-unknown}" "${PERM:-unknown}"
        )
      fi
    fi
  else
    # export 설정이 존재하면 "사용 중"으로 보고 접근통제 핵심 점검
    # 1) 모든 호스트(*) 허용 탐지
    if echo "$EXPORT_LINES" | grep -qE "([[:space:]]|^)\*([[:space:]]|$|\()"; then
      add_vuln "모든 호스트(*)에 공유 허용"
    fi

    # 2) no_root_squash 탐지
    if echo "$EXPORT_LINES" | grep -qiE "no_root_squash"; then
      add_vuln "no_root_squash 옵션 사용"
    fi

    # 3) 호스트/옵션 미지정(경로만 있는 라인) 탐지: 주석 제거 후 첫 토큰만 존재
    ONLY_PATH_LINE=$(echo "$EXPORT_LINES" | awk '
      {
        line=$0;
        sub(/^[0-9]+:/,"",line);
        gsub(/^[ \t]+|[ \t]+$/,"",line);
        n=split(line,a,/[ \t]+/);
        if (n==1) print $0;
      }' | head -n 1)
    if [ -n "$ONLY_PATH_LINE" ]; then
      add_vuln "export 항목에 허용 호스트/옵션 미지정 라인 존재"
    fi

    if [ "${#VULN_FLAGS[@]}" -gt 0 ]; then
      STATUS="FAIL"
      REASON_LINE="/etc/exports에서 접근 통제(허용 호스트 제한/안전 옵션)가 미흡하거나 설정 파일 권한이 과대하여 비인가 호스트 접근 또는 권한 상승 위험이 있으므로 취약합니다. 조치: /etc/exports 소유자 root 및 권한 644 적용, 공유 대상은 허용 호스트(또는 네트워크)만 지정, no_root_squash 제거 후 exports -ra로 반영하세요."
      DETAIL_CONTENT=$(
        printf "services: nfs-server(active=%s enabled=%s), rpcbind(active=%s enabled=%s)\n" \
          "${NFS_ACTIVE:-unknown}" "${NFS_ENABLED:-unknown}" "${RPCBIND_ACTIVE:-unknown}" "${RPCBIND_ENABLED:-unknown}"
        printf "exports_file: owner=%s perm=%s\n" "${OWNER:-unknown}" "${PERM:-unknown}"
        printf "findings:\n"
        printf "%s\n" "${VULN_FLAGS[@]}"
        printf "exports(sample top5):\n"
        echo "$EXPORT_LINES" | head -n 5
      )
    else
      STATUS="PASS"
      REASON_LINE="/etc/exports에서 허용 호스트가 명시되어 있고(*, no_root_squash 등 위험 설정 미사용), /etc/exports 소유자(root) 및 권한(644 이하)이 적절하게 설정되어 있어 이 항목에 대한 보안 위협이 없습니다."
      DETAIL_CONTENT=$(
        printf "services: nfs-server(active=%s enabled=%s), rpcbind(active=%s enabled=%s)\n" \
          "${NFS_ACTIVE:-unknown}" "${NFS_ENABLED:-unknown}" "${RPCBIND_ACTIVE:-unknown}" "${RPCBIND_ENABLED:-unknown}"
        printf "exports_file: owner=%s perm=%s\n" "${OWNER:-unknown}" "${PERM:-unknown}"
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