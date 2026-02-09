#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-24
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : 사용자, 시스템 환경변수 파일 소유자 및 권한 설정
# @Description : 홈 디렉터리 내의 환경변수 파일에 대한 소유자 및 접근 권한이 관리자 또는 해당 계정으로 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 1. 점검 항목 정보 정의
CHECK_ID="U-24"
CATEGORY="파일 및 디렉토리 관리"
TITLE="사용자, 시스템 환경변수 파일 소유자 및 권한 설정"
IMPORTANCE="상"
STATUS="PASS"
EVIDENCE=""
TARGET_FILE=""
IMPACT_LEVEL="LOW" 
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없으나, 일부 사용자 환경변수 파일에 대한 수정이 제한되어 사용자별 쉘 초기화 스크립트 변경이나 커스텀 설정이 일시적으로 적용되지 않을 수 있습니다."
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
while IFS=: read -r USER _ _ _ _ HOME_DIR _; do

  # 홈 디렉터리가 실제로 존재하는 계정만 대상
  if [ ! -d "$HOME_DIR" ]; then
    continue
  fi

  for ENV_FILE in "${ENV_FILES[@]}"; do
    FILE_PATH="$HOME_DIR/$ENV_FILE"

    if [ -f "$FILE_PATH" ]; then
      OWNER="$(stat -c %U "$FILE_PATH")"
      PERM="$(stat -c %A "$FILE_PATH")"

      # 1) 소유자 점검 (root 또는 해당 계정만 허용)
      if [[ "$OWNER" != "root" && "$OWNER" != "$USER" ]]; then
        STATUS="FAIL"
        [ -n "$EVIDENCE" ] && EVIDENCE+=", "
        EVIDENCE+="[소유자 오류] $FILE_PATH (owner=$OWNER, user=$USER)"
        TARGET_FILE+="$FILE_PATH "
        continue
      fi

      # 2) group / other 쓰기 권한 점검
      if [[ "${PERM:5:1}" == "w" || "${PERM:8:1}" == "w" ]]; then
        STATUS="FAIL"
        [ -n "$EVIDENCE" ] && EVIDENCE+=", "
        EVIDENCE+="[권한 오류] $FILE_PATH (perm=$PERM)"
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
  "guide": "환경변수 파일의 일반 사용자 쓰기 권한을 제거해주세요.",
  "target_file": "$TARGET_FILE",
  "file_hash": "N/A",
  "action_impact": "$ACTION_IMPACT",
  "impact_level": "$IMPACT_LEVEL",  
  "check_date": "$CHECK_DATE"
}
EOF