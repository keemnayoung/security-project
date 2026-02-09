#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-24
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : 사용자, 시스템 환경변수 파일 소유자 및 권한 설정
# @Description : 홈 디렉터리 환경변수 파일 소유자가 root 또는 해당 계정으로 지정되어 있고, 홈 디렉터리 환경변수 파일에 root 계정과 소유자만 쓰기 권한 부여
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-24"
CATEGORY="파일 및 디렉토리 관리"
TITLE="사용자, 시스템 환경변수 파일 소유자 및 권한 설정"
IMPORTANCE="상"

STATUS="PASS"
ACTION_RESULT="SUCCESS"
ACTION_LOG=""
EVIDENCE=""
GUIDE="KISA 가이드라인에 따른 홈 디렉터리 환경변수 파일 권한 설정을 수행하였습니다."

ENV_FILES=(
  ".profile"
  ".bashrc"
  ".bash_profile"
  ".kshrc"
  ".cshrc"
  ".login"
  ".exrc"
  ".netrc"
)

ACTION_TARGET_FOUND=false


# 1. 실제 조치 프로세스
while IFS=: read -r USER _ _ _ _ HOME_DIR _; do

  [ ! -d "$HOME_DIR" ] && continue

  for ENV_FILE in "${ENV_FILES[@]}"; do
    FILE_PATH="$HOME_DIR/$ENV_FILE"

    [ ! -f "$FILE_PATH" ] && continue

    ACTION_TARGET_FOUND=true

    OWNER_BEFORE="$(stat -c %U "$FILE_PATH")"

    # 1) 소유자 조치
    if [[ "$OWNER_BEFORE" != "root" && "$OWNER_BEFORE" != "$USER" ]]; then
      chown "$USER" "$FILE_PATH" 2>/dev/null
    fi

    # 2) 권한 조치 (group / other write 제거)
    chmod go-w "$FILE_PATH" 2>/dev/null

    OWNER_AFTER="$(stat -c %U "$FILE_PATH")"
    PERM_AFTER="$(stat -c %A "$FILE_PATH")"

    # 검증
    if [[ "$OWNER_AFTER" != "root" && "$OWNER_AFTER" != "$USER" ]] \
       || [[ "${PERM_AFTER:5:1}" == "w" || "${PERM_AFTER:8:1}" == "w" ]]; then
        STATUS="FAIL"
        ACTION_RESULT="PARTIAL_SUCCESS"
        [ -n "$ACTION_LOG" ] && ACTION_LOG+=", "
        ACTION_LOG+="조치 실패: $FILE_PATH"
        [ -n "$EVIDENCE" ] && EVIDENCE+=", "
        EVIDENCE+="조치 후에도 기준 미충족 ($FILE_PATH)"
    else
        [ -n "$ACTION_LOG" ] && ACTION_LOG+=", "
        ACTION_LOG+="조치 완료: $FILE_PATH"
    fi

  done
done < /etc/passwd


# 2. 결과 정리
if [ "$ACTION_TARGET_FOUND" = false ]; then
  STATUS="PASS"
  ACTION_RESULT="SUCCESS"
  ACTION_LOG="조치 대상 환경변수 파일이 존재하지 않음"
  EVIDENCE="점검 대상 파일 없음"
fi


# 3. JSON 표준 출력
echo ""
cat << EOF
{
  "check_id": "$ID",
  "category": "$CATEGORY",
  "title": "$TITLE",
  "importance": "$IMPORTANCE",
  "status": "$STATUS",
  "evidence": "$EVIDENCE",
  "guide": "$GUIDE",
  "action_result": "$ACTION_RESULT",
  "action_log": "$ACTION_LOG",
  "action_date": "$(date '+%Y-%m-%d %H:%M:%S')",
  "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF