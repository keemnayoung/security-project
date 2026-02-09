#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 권순형
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-24
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Debian
# @Importance  : 상
# @Title       : 사용자, 시스템 환경변수 파일 소유자 및 권한 설정
# @Description : 홈 디렉터리 환경변수 파일 소유자가 root 또는 해당 계정으로 지정되어 있고, 홈 디렉터리 환경변수 파일에 root 계정과 소유자만 쓰기 권한 부여
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 1. 기본 변수 정의 (고정 템플릿)
ID="U-24"
TARGET_FILE=""
ACTION_RESULT="SUCCESS"
ACTION_LOG=""
BEFORE_SETTING=""
AFTER_SETTING=""
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

ENV_FILES=(
  ".profile"
  ".kshrc"
  ".cshrc"
  ".bashrc"
  ".bash_profile"
  ".login"
  ".exrc"
  ".netrc"
)

# 2. 조치 로직
while IFS=: read -r USER _ UID _ _ HOME_DIR _; do
  # 일반 사용자만 대상
  if [ "$UID" -lt 1000 ] || [ ! -d "$HOME_DIR" ]; then
    continue
  fi

  for ENV_FILE in "${ENV_FILES[@]}"; do
    FILE_PATH="$HOME_DIR/$ENV_FILE"

    if [ -f "$FILE_PATH" ]; then
      PERM_BEFORE="$(stat -c %A "$FILE_PATH")"

      # 기타 사용자 쓰기 권한이 있는 경우만 조치
      if [[ "${PERM_BEFORE:8:1}" == "w" ]]; then
        chmod o-w "$FILE_PATH" 2>/dev/null

        PERM_AFTER="$(stat -c %A "$FILE_PATH")"

        TARGET_FILE+="$FILE_PATH "

        if [ -z "$BEFORE_SETTING" ]; then
          BEFORE_SETTING="$FILE_PATH:$PERM_BEFORE"
          AFTER_SETTING="$FILE_PATH:$PERM_AFTER"
          ACTION_LOG="기타 사용자 쓰기 권한 제거"
        else
          BEFORE_SETTING+=", $FILE_PATH:$PERM_BEFORE"
          AFTER_SETTING+=", $FILE_PATH:$PERM_AFTER"
          ACTION_LOG+=", 기타 사용자 쓰기 권한 제거"
        fi

        if [ "$PERM_BEFORE" = "$PERM_AFTER" ]; then
          ACTION_RESULT="FAIL"
          ACTION_LOG+=", 조치 실패"
        fi
      fi
    fi
  done
done < /etc/passwd

if [ -z "$TARGET_FILE" ]; then
  ACTION_LOG="조치 대상 파일 없음"
  BEFORE_SETTING="N/A"
  AFTER_SETTING="N/A"
fi


# 3. JSON 결과 출력 (echo 공백 필수)
echo ""

cat <<EOF
{
  "check_id": "$ID",
  "action_result": "$ACTION_RESULT",
  "before_setting": "$BEFORE_SETTING",
  "after_setting": "$AFTER_SETTING",
  "action_log": "$ACTION_LOG",
  "action_date": "$ACTION_DATE"
}
EOF