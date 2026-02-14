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

ACTION_ERR_LOG=""

# (필수) root 권한 권장 안내(실패 원인 명확화용)
if [ "$(id -u)" -ne 0 ]; then
  ACTION_ERR_LOG="(주의) root 권한이 아니면 chown/chmod가 실패할 수 있습니다."
fi

if [ -f "$TARGET_FILE" ]; then
  MODIFIED=0

  BEFORE_OWNER=$(stat -c "%U" "$TARGET_FILE" 2>/dev/null)
  BEFORE_GROUP=$(stat -c "%G" "$TARGET_FILE" 2>/dev/null)
  BEFORE_PERM=$(stat -c "%a" "$TARGET_FILE" 2>/dev/null)

  # (필수) 권한값 형식 검증 (예: 644 또는 0644 또는 1644 등)
  if ! echo "$BEFORE_PERM" | grep -Eq '^[0-7]{3,4}$'; then
    IS_SUCCESS=0
    REASON_LINE="조치 전 /etc/passwd 권한 값을 정상적으로 확인할 수 없어 조치를 중단합니다."
    DETAIL_CONTENT="before_owner=$BEFORE_OWNER\nbefore_group=$BEFORE_GROUP\nbefore_perm=$BEFORE_PERM\n$ACTION_ERR_LOG"
  else
    # (필수) 8진수 권한을 정수로 변환해 정확 판정 (특수권한/쓰기비트)
    BEFORE_PERM_DEC=$((8#$BEFORE_PERM))

    # 조치 1) 소유자/그룹 root로 변경
    if [ "$BEFORE_OWNER" != "root" ] || [ "$BEFORE_GROUP" != "root" ]; then
      if chown root:root "$TARGET_FILE" 2>/dev/null; then
        MODIFIED=1
      else
        ACTION_ERR_LOG="${ACTION_ERR_LOG}\nchown 실패"
      fi
    fi

    # 조치 2) 권한이 기준에 어긋나면 644로 고정
    # - 그룹/기타 쓰기(022) 존재 또는 특수권한(07000) 존재 또는 단순히 644 초과면 조치
    NEED_CHMOD=0
    [ $((BEFORE_PERM_DEC & 022)) -ne 0 ] && NEED_CHMOD=1
    [ $((BEFORE_PERM_DEC & 07000)) -ne 0 ] && NEED_CHMOD=1
    [ "$BEFORE_PERM" -gt 644 ] && NEED_CHMOD=1

    if [ "$NEED_CHMOD" -eq 1 ]; then
      if chmod 644 "$TARGET_FILE" 2>/dev/null; then
        MODIFIED=1
      else
        ACTION_ERR_LOG="${ACTION_ERR_LOG}\nchmod 실패"
      fi
    fi

    AFTER_OWNER=$(stat -c "%U" "$TARGET_FILE" 2>/dev/null)
    AFTER_GROUP=$(stat -c "%G" "$TARGET_FILE" 2>/dev/null)
    AFTER_PERM=$(stat -c "%a" "$TARGET_FILE" 2>/dev/null)

    # AFTER 권한도 형식 검증
    if ! echo "$AFTER_PERM" | grep -Eq '^[0-7]{3,4}$'; then
      IS_SUCCESS=0
      REASON_LINE="조치 후 /etc/passwd 권한 값을 정상적으로 확인할 수 없어 조치 결과 검증에 실패했습니다."
    else
      AFTER_PERM_DEC=$((8#$AFTER_PERM))
      # 최종 기준: owner=root, group=root, 그룹/기타 쓰기 없음, 특수권한 없음, 그리고 644 이하
      OWNER_OK=0; GROUP_OK=0; WRITE_OK=0; SPECIAL_OK=0; LE_OK=0
      [ "$AFTER_OWNER" = "root" ] && OWNER_OK=1
      [ "$AFTER_GROUP" = "root" ] && GROUP_OK=1
      [ $((AFTER_PERM_DEC & 022)) -eq 0 ] && WRITE_OK=1
      [ $((AFTER_PERM_DEC & 07000)) -eq 0 ] && SPECIAL_OK=1
      [ "$AFTER_PERM" -le 644 ] && LE_OK=1

      if [ "$OWNER_OK" -eq 1 ] && [ "$GROUP_OK" -eq 1 ] && [ "$WRITE_OK" -eq 1 ] && [ "$SPECIAL_OK" -eq 1 ] && [ "$LE_OK" -eq 1 ]; then
        IS_SUCCESS=1
        if [ "$MODIFIED" -eq 1 ]; then
          REASON_LINE="/etc/passwd 파일의 소유자/그룹이 root로 설정되고 권한이 644 이하로 변경되어 조치가 완료되었습니다."
        else
          REASON_LINE="/etc/passwd 파일의 소유자/그룹이 root이고 권한이 644 이하로 유지되어 변경 없이도 조치가 완료되었습니다."
        fi
      else
        IS_SUCCESS=0
        REASON_LINE="조치를 수행했으나 /etc/passwd 파일의 소유자 또는 권한이 기준을 충족하지 못해 조치가 완료되지 않았습니다."
      fi
    fi

    # (필수) BEFORE/AFTER 근거 모두 기록
    DETAIL_CONTENT="before_owner=$BEFORE_OWNER\nbefore_group=$BEFORE_GROUP\nbefore_perm=$BEFORE_PERM\nafter_owner=$AFTER_OWNER\nafter_group=$AFTER_GROUP\nafter_perm=$AFTER_PERM"
    if [ -n "$ACTION_ERR_LOG" ]; then
      DETAIL_CONTENT="$DETAIL_CONTENT\n$ACTION_ERR_LOG"
    fi
  fi
else
  IS_SUCCESS=0
  REASON_LINE="조치 대상 파일(/etc/passwd)이 존재하지 않아 조치가 완료되지 않았습니다."
  DETAIL_CONTENT="$ACTION_ERR_LOG"
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