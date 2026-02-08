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
# @Description : 홈 디렉터리 내의 환경변수 파일에 대한 소유자 및 접근 권한이 관리자 또는 해당 계정으로 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 1. 점검 항목 정보 정의
CHECK_ID="U-24"
CATEGORY="계정 관리"
TITLE="사용자, 시스템 환경변수 파일 소유자 및 권한 설정"
IMPORTANCE="상"
STATUS="PASS"
EVIDENCE=""
TARGET_FILE=""
CHECK_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

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

# 2. 진단 로직
while IFS=: read -r USER _ UID _ _ HOME_DIR _; do
  # 시스템 계정 제외 (UID 1000 미만)
  if [ "$UID" -lt 1000 ] || [ ! -d "$HOME_DIR" ]; then
    continue
  fi

  for ENV_FILE in "${ENV_FILES[@]}"; do
    FILE_PATH="$HOME_DIR/$ENV_FILE"

    if [ -f "$FILE_PATH" ]; then
      OWNER="$(stat -c %U "$FILE_PATH")"
      PERM="$(stat -c %A "$FILE_PATH")"

      # 소유자 점검 (root 또는 해당 계정)
        if [[ "$OWNER" != "root" && "$OWNER" != "$USER" ]]; then
            STATUS="FAIL"
            if [ -z "$EVIDENCE" ]; then
            EVIDENCE="[소유자 오류] $FILE_PATH (owner=$OWNER)"
            else
            EVIDENCE+=", [소유자 오류] $FILE_PATH (owner=$OWNER)"
            fi
            TARGET_FILE+="$FILE_PATH "
            continue
        fi

      # 기타 사용자 쓰기 권한 점검

        if [[ "${PERM:8:1}" == "w" ]]; then
            STATUS="FAIL"
            if [ -z "$EVIDENCE" ]; then
            EVIDENCE="[권한 오류] $FILE_PATH (perm=$PERM)"
            else
            EVIDENCE+=", [권한 오류] $FILE_PATH (perm=$PERM)"
            fi
            TARGET_FILE+="$FILE_PATH "
        fi
    fi
  done
done < /etc/passwd

if [ "$STATUS" = "PASS" ]; then
  EVIDENCE="모든 홈 디렉터리 환경변수 파일의 소유자 및 권한이 적절하게 설정되어 있음"
fi


# 3. JSON 결과 출력
echo ""

cat <<EOF
{
  "check_id": "$CHECK_ID",
  "category": "$CATEGORY",
  "title": "$TITLE",
  "importance": "$IMPORTANCE",
  "status": "$STATUS",
  "evidence": "$EVIDENCE",
  "target_file": "$TARGET_FILE",
  "check_date": "$CHECK_DATE"
}
EOF