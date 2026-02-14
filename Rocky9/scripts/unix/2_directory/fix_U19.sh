#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-19
# @Category    : 파일 및 디렉토리 관리
# @Platform    : RHEL
# @Importance  : 상
# @Title       : /etc/hosts 파일 소유자 및 권한 설정
# @Description : /etc/hosts 파일의 소유자가 root이고, 권한이 644 이하로 설정
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-19"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND=""
REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""

TARGET_FILE="/etc/hosts"
CHECK_COMMAND="stat -c '%U %G %a %n' /etc/hosts 2>/dev/null"

# 조치 프로세스
if [ -f "$TARGET_FILE" ]; then
  MODIFIED=0

  # 조치 전 상태 수집
  BEFORE_OWNER=$(stat -c "%U" "$TARGET_FILE" 2>/dev/null)
  BEFORE_GROUP=$(stat -c "%G" "$TARGET_FILE" 2>/dev/null)
  BEFORE_PERM=$(stat -c "%a" "$TARGET_FILE" 2>/dev/null)

  # stat 결과 수집 실패 처리(필수)
  if [ -z "$BEFORE_OWNER" ] || [ -z "$BEFORE_GROUP" ] || [ -z "$BEFORE_PERM" ]; then
    IS_SUCCESS=0
    REASON_LINE="/etc/hosts 파일의 소유자/그룹/권한 정보를 수집하지 못해 조치 수행 및 검증이 불가능하므로 조치가 완료되지 않았습니다."
    DETAIL_CONTENT="before_owner=${BEFORE_OWNER:-unknown}
before_group=${BEFORE_GROUP:-unknown}
before_perm=${BEFORE_PERM:-unknown}"
  else
    # 1) 소유자/그룹 조치 (그룹은 기준에는 없지만 root:root로 통일)
    if [ "$BEFORE_OWNER" != "root" ] || [ "$BEFORE_GROUP" != "root" ]; then
      chown root:root "$TARGET_FILE" 2>/dev/null
      MODIFIED=1
    fi

    # 2) 권한 조치 (기준은 644 이하이지만, 조치 방식은 644로 표준화)
    if [ "$BEFORE_PERM" != "644" ]; then
      chmod 644 "$TARGET_FILE" 2>/dev/null
      MODIFIED=1
    fi

    # 조치 후 상태 수집
    AFTER_OWNER=$(stat -c "%U" "$TARGET_FILE" 2>/dev/null)
    AFTER_GROUP=$(stat -c "%G" "$TARGET_FILE" 2>/dev/null)
    AFTER_PERM=$(stat -c "%a" "$TARGET_FILE" 2>/dev/null)

    DETAIL_CONTENT="before_owner=$BEFORE_OWNER
before_group=$BEFORE_GROUP
before_perm=$BEFORE_PERM
after_owner=$AFTER_OWNER
after_group=$AFTER_GROUP
after_perm=$AFTER_PERM"

    # 최종 검증
    if [ "$AFTER_OWNER" = "root" ] && [ "$AFTER_GROUP" = "root" ] && [ -n "$AFTER_PERM" ] && [ "$AFTER_PERM" -eq 644 ]; then
      IS_SUCCESS=1
      if [ "$MODIFIED" -eq 1 ]; then
        REASON_LINE="/etc/hosts 파일의 소유자/그룹이 root로 설정되고 권한이 644로 변경되어 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
      else
        REASON_LINE="/etc/hosts 파일의 소유자/그룹이 root이고 권한이 644로 유지되어 변경 없이도 조치가 완료되어 이 항목에 대한 보안 위협이 없습니다."
      fi
    else
      IS_SUCCESS=0
      REASON_LINE="조치를 수행했으나 /etc/hosts 파일의 소유자 또는 권한이 기준을 충족하지 못해 조치가 완료되지 않았습니다."
    fi
  fi
else
  IS_SUCCESS=0
  REASON_LINE="조치 대상 파일(/etc/hosts)이 존재하지 않아 조치가 완료되지 않았습니다."
  DETAIL_CONTENT="file_not_found"
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