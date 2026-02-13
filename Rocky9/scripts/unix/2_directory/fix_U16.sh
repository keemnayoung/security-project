#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-16
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : /etc/passwd 파일 소유자 및 권한 설정
# @Description : /etc/passwd 파일의 소유자를 root로 설정하고 권한을 644 이하로 변경
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-16"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND="stat -c '%U %G %a %n' /etc/passwd 2>/dev/null"
REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE="/etc/passwd"

if [ -f "$TARGET_FILE" ]; then
  MODIFIED=0

  BEFORE_OWNER=$(stat -c "%U" "$TARGET_FILE" 2>/dev/null)
  BEFORE_GROUP=$(stat -c "%G" "$TARGET_FILE" 2>/dev/null)
  BEFORE_PERM=$(stat -c "%a" "$TARGET_FILE" 2>/dev/null)

  if [ "$BEFORE_OWNER" != "root" ] || [ "$BEFORE_GROUP" != "root" ]; then
    chown root:root "$TARGET_FILE" 2>/dev/null
    MODIFIED=1
  fi

  if [ -n "$BEFORE_PERM" ] && [ "$BEFORE_PERM" -gt 644 ]; then
    chmod 644 "$TARGET_FILE" 2>/dev/null
    MODIFIED=1
  fi

  AFTER_OWNER=$(stat -c "%U" "$TARGET_FILE" 2>/dev/null)
  AFTER_GROUP=$(stat -c "%G" "$TARGET_FILE" 2>/dev/null)
  AFTER_PERM=$(stat -c "%a" "$TARGET_FILE" 2>/dev/null)

  DETAIL_CONTENT="owner=$AFTER_OWNER
group=$AFTER_GROUP
perm=$AFTER_PERM"

  if [ "$AFTER_OWNER" = "root" ] && [ "$AFTER_GROUP" = "root" ] && [ -n "$AFTER_PERM" ] && [ "$AFTER_PERM" -le 644 ]; then
    IS_SUCCESS=1
    if [ "$MODIFIED" -eq 1 ]; then
      REASON_LINE="/etc/passwd 파일의 소유자/그룹이 root로 설정되고 권한이 644 이하로 변경되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
    else
      REASON_LINE="/etc/passwd 파일의 소유자/그룹이 root이고 권한이 644 이하로 유지되어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
    fi
  else
    IS_SUCCESS=0
    REASON_LINE="조치를 수행했으나 /etc/passwd 파일의 소유자 또는 권한이 기준을 충족하지 못해 조치가 완료되지 않았습니다."
  fi
else
  IS_SUCCESS=0
  REASON_LINE="조치 대상 파일(/etc/passwd)이 존재하지 않아 조치가 완료되지 않았습니다."
  DETAIL_CONTENT=""
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