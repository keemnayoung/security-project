#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [보완 항목 상세]
# @Check_ID : U-40
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : NFS 접근 통제
# @Description : NFS(Network File System)의 접근 통제 설정 적용 여부 점검
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [보완] U-40 NFS 접근 통제

# 기본 변수
ID="U-40"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

TARGET_FILE="/etc/exports"
CHECK_COMMAND="stat -c '%U %G %a %n' /etc/exports 2>/dev/null; grep -nEv '^[[:space:]]*#|^[[:space:]]*$' /etc/exports 2>/dev/null | head -n 50"

REASON_LINE=""
DETAIL_CONTENT=""
ACTION_ERR_LOG=""
MODIFIED=0
FAIL_FLAG=0

# (필수) root 권한 권장 안내(실패 원인 명확화용)
if [ "$(id -u)" -ne 0 ]; then
  ACTION_ERR_LOG="(주의) root 권한이 아니면 chown/chmod/exportfs 조치가 실패할 수 있습니다."
fi

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

# exports 내 와일드카드(*) 허용 여부(활성 라인 기준)
has_wildcard_share() {
  [ -f "$TARGET_FILE" ] || return 1
  # 예: /path *(rw,...) 또는 /path  *(...) 등 다양한 공백 케이스 방어
  grep -nEv '^[[:space:]]*#|^[[:space:]]*$' "$TARGET_FILE" 2>/dev/null | grep -qE '(^|[[:space:]])\*([[:space:]]|\(|$)'
}

# ---------------------------
# 조치 프로세스
# ---------------------------
if [ ! -f "$TARGET_FILE" ]; then
  IS_SUCCESS=1
  REASON_LINE="NFS exports 파일(/etc/exports)이 존재하지 않아 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
  DETAIL_CONTENT="exports_file=not_found"
else
  # stat 수집 실패 방어(필수)
  OWNER=$(stat -c "%U" "$TARGET_FILE" 2>/dev/null)
  GROUP=$(stat -c "%G" "$TARGET_FILE" 2>/dev/null)
  PERM=$(stat -c "%a" "$TARGET_FILE" 2>/dev/null)

  if [ -z "$OWNER" ] || [ -z "$GROUP" ] || [ -z "$PERM" ]; then
    IS_SUCCESS=0
    REASON_LINE="/etc/exports 파일의 소유자/그룹/권한 정보를 수집하지 못해 조치 수행 및 검증이 불가능하므로 조치가 완료되지 않았습니다."
    DETAIL_CONTENT="owner=${OWNER:-unknown}\ngroup=${GROUP:-unknown}\nperm=${PERM:-unknown}"
  else
    # 1) 소유자/그룹 root:root 표준화
    if [ "$OWNER" != "root" ] || [ "$GROUP" != "root" ]; then
      chown root:root "$TARGET_FILE" 2>/dev/null || append_err "chown root:root 실패"
      MODIFIED=1
    fi

    # 2) 권한 644 표준화
    if [ "$PERM" != "644" ]; then
      chmod 644 "$TARGET_FILE" 2>/dev/null || append_err "chmod 644 실패"
      MODIFIED=1
    fi

    # 3) everyone(*) 공유는 자동 변경 대신 FAIL + 수동 조치 권고(안전)
    if has_wildcard_share; then
      FAIL_FLAG=1
      append_err "exports 파일에서 everyone(*) 공유 설정이 확인되었습니다."
    fi

    # 4) 설정 반영(exportfs -ra) (명령 있을 때만)
    if command -v exportfs >/dev/null 2>&1; then
      exportfs -ra 2>/dev/null || append_err "exportfs -ra 실행 실패"
    else
      append_err "exportfs 명령을 사용할 수 없어 설정 반영을 수행하지 못했습니다."
    fi

    # 조치 후/현재 상태 수집(현재 설정만 evidence에 포함)
    AFTER_OWNER=$(stat -c "%U" "$TARGET_FILE" 2>/dev/null)
    AFTER_GROUP=$(stat -c "%G" "$TARGET_FILE" 2>/dev/null)
    AFTER_PERM=$(stat -c "%a" "$TARGET_FILE" 2>/dev/null)

    # 현재 exports 주요 라인(요약)
    ACTIVE_LINES="$(grep -nEv '^[[:space:]]*#|^[[:space:]]*$' "$TARGET_FILE" 2>/dev/null | head -n 10)"
    [ -z "$ACTIVE_LINES" ] && ACTIVE_LINES="no_active_exports_lines"

    WILDCARD_STATUS="not_found"
    if has_wildcard_share; then
      WILDCARD_STATUS="wildcard_share_exists"
    else
      WILDCARD_STATUS="no_wildcard_share"
    fi

    append_detail "exports(after) owner=$AFTER_OWNER group=$AFTER_GROUP perm=$AFTER_PERM"
    append_detail "wildcard_share_check(after)=$WILDCARD_STATUS"
    append_detail "exports_active_lines(after)=$ACTIVE_LINES"

    # 최종 검증
    if [ "$AFTER_OWNER" = "root" ] && [ "$AFTER_GROUP" = "root" ] && [ "$AFTER_PERM" = "644" ] && [ "$FAIL_FLAG" -eq 0 ]; then
      IS_SUCCESS=1
      if [ "$MODIFIED" -eq 1 ]; then
        REASON_LINE="/etc/exports 파일의 소유자/그룹이 root로 설정되고 권한이 644로 변경되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
      else
        REASON_LINE="/etc/exports 파일의 소유자/그룹이 root이고 권한이 644로 유지되어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
      fi
    else
      IS_SUCCESS=0
      if [ "$FAIL_FLAG" -eq 1 ]; then
        REASON_LINE="조치를 수행했으나 /etc/exports 파일에 everyone(*) 공유 설정이 남아 있어 수동으로 허용 IP 또는 네트워크 대역(예: 192.168.1.0/24)으로 제한해야 조치가 완료됩니다."
      else
        REASON_LINE="조치를 수행했으나 /etc/exports 파일의 소유자 또는 권한이 기준을 충족하지 못해 조치가 완료되지 않았습니다."
      fi
    fi
  fi
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