#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.1
# @Author: 권순형
# @Last Updated: 2026-02-15
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-29
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 하
# @Title       : hosts.lpd 파일 소유자 및 권한 설정
# @Description : /etc/hosts.lpd 파일이 존재하지 않거나, 불가피하게 사용 시 /etc/hosts.lpd 파일의 소유자가 root이고, 권한이 600 이하로 설정
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-29"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND=""
REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""

TARGET_FILE="/etc/hosts.lpd"
CHECK_COMMAND="stat -c '%F %U %G %a %n' /etc/hosts.lpd 2>/dev/null"

# 조치 프로세스
if [ ! -e "$TARGET_FILE" ]; then
  IS_SUCCESS=1
  REASON_LINE="/etc/hosts.lpd 파일이 존재하지 않아 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
  DETAIL_CONTENT=""
else
  # [추가] 파일 타입 확인: 일반 파일이 아니면 자동 조치 대상에서 제외(수동 조치 필요)
  FILE_TYPE=$(stat -c "%F" "$TARGET_FILE" 2>/dev/null)
  if [ -z "$FILE_TYPE" ]; then
    IS_SUCCESS=0
    REASON_LINE="/etc/hosts.lpd 파일은 존재하나 파일 정보 조회(stat) 실패로 조치를 수행할 수 없습니다. 수동 확인이 필요합니다."
    DETAIL_CONTENT="stat_failed"
  elif [ "$FILE_TYPE" != "regular file" ]; then
    IS_SUCCESS=0
    REASON_LINE="/etc/hosts.lpd 경로가 일반 파일이 아닌 형태($FILE_TYPE)로 존재하여 자동으로 소유자/권한 조치를 수행할 수 없습니다. 비정상 타입(링크/디렉터리 등) 제거 후 재시도하거나 수동 조치가 필요합니다."
    DETAIL_CONTENT="type=$FILE_TYPE"
  else
    MODIFIED=0

    OWNER=$(stat -c "%U" "$TARGET_FILE" 2>/dev/null)
    GROUP=$(stat -c "%G" "$TARGET_FILE" 2>/dev/null)
    PERM=$(stat -c "%a" "$TARGET_FILE" 2>/dev/null)

    # [추가] 조회 값 유효성 검사
    if [ -z "$OWNER" ] || [ -z "$GROUP" ] || [ -z "$PERM" ] || ! [[ "$PERM" =~ ^[0-9]+$ ]]; then
      IS_SUCCESS=0
      REASON_LINE="/etc/hosts.lpd 파일은 존재하나 소유자/그룹/권한 값 조회에 실패하여 자동 조치를 수행할 수 없습니다. 수동 확인이 필요합니다."
      DETAIL_CONTENT="owner=$OWNER group=$GROUP perm=$PERM"
    else
      if [ "$OWNER" != "root" ] || [ "$GROUP" != "root" ]; then
        chown root:root "$TARGET_FILE" 2>/dev/null
        MODIFIED=1
      fi

      if [ "$PERM" -gt 600 ]; then
        chmod 600 "$TARGET_FILE" 2>/dev/null
        MODIFIED=1
      fi

      AFTER_OWNER=$(stat -c "%U" "$TARGET_FILE" 2>/dev/null)
      AFTER_GROUP=$(stat -c "%G" "$TARGET_FILE" 2>/dev/null)
      AFTER_PERM=$(stat -c "%a" "$TARGET_FILE" 2>/dev/null)

      DETAIL_CONTENT="type=$FILE_TYPE
owner=$AFTER_OWNER
group=$AFTER_GROUP
perm=$AFTER_PERM"

      # [추가] 조치 후 값 유효성 검사
      if [ -z "$AFTER_OWNER" ] || [ -z "$AFTER_GROUP" ] || [ -z "$AFTER_PERM" ] || ! [[ "$AFTER_PERM" =~ ^[0-9]+$ ]]; then
        IS_SUCCESS=0
        REASON_LINE="조치를 수행했으나 조치 후 소유자/그룹/권한 값 확인에 실패하여 완료 여부를 판단할 수 없습니다. 수동 확인이 필요합니다."
      elif [ "$AFTER_OWNER" = "root" ] && [ "$AFTER_GROUP" = "root" ] && [ "$AFTER_PERM" -le 600 ]; then
        IS_SUCCESS=1
        if [ "$MODIFIED" -eq 1 ]; then
          REASON_LINE="/etc/hosts.lpd 파일의 소유자/그룹이 root로 설정되고 권한이 600 이하로 변경되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
        else
          REASON_LINE="/etc/hosts.lpd 파일의 소유자/그룹이 root이고 권한이 600 이하로 유지되어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
        fi
      else
        IS_SUCCESS=0
        REASON_LINE="조치를 수행했으나 /etc/hosts.lpd 파일의 소유자 또는 권한이 기준을 충족하지 못해 조치가 완료되지 않았습니다."
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