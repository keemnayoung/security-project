#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.2
# @Author: 권순형
# @Last Updated: 2026-02-10
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
ID="U-24"
CATEGORY="파일 및 디렉토리 관리"
TITLE="사용자, 시스템 환경변수 파일 소유자 및 권한 설정"
IMPORTANCE="상"
STATUS="PASS"
EVIDENCE=""
GUIDE="해당 항목은 자동 조치 시 시스템 장애 위험이 커서 자동 조치 기능을 제공하지 않습니다. 관리자가 직접 환경변수 파일(.profile, .kshrc, .cshrc, .bashrc, .bash_profile, .login, .exrc, .netrc 등)의 소유자를 root 또는 해당 계정으로 변경하고, 일반 사용자 쓰기 권한을 제거해주세요."
ACTION_RESULT="N/A"
IMPACT_LEVEL="LOW" 
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없으나, 일부 사용자 환경변수 파일에 대한 수정이 제한되어 사용자별 쉘 초기화 스크립트 변경이나 커스텀 설정이 일시적으로 적용되지 않을 수 있습니다."
TARGET_FILE=""
FILE_HASH="N/A"
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

VUL_OWNER_LIST=()
VUL_PERM_LIST=()


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
        ACTION_RESULT="PARTIAL_SUCCESS"
        VUL_OWNER_LIST+=("$FILE_PATH(owner=$OWNER,user=$USER); ")
        TARGET_FILE+="$FILE_PATH "
        continue
      fi

      # 2) group / other 쓰기 권한 점검
      if [[ "${PERM:5:1}" == "w" || "${PERM:8:1}" == "w" ]]; then
        STATUS="FAIL"
        ACTION_RESULT="PARTIAL_SUCCESS"
        VUL_PERM_LIST+=("$FILE_PATH(perm=$PERM); ")
        TARGET_FILE+="$FILE_PATH "
      fi
    fi
  done

done < /etc/passwd

# 3. EVIDENCE 구성
if [ "$STATUS" = "FAIL" ]; then
  EVIDENCE="사용자, 시스템 환경변수 파일 소유자 또는 권한 설정이 부적절하여 보안을 위한 수동 재설정이 필요합니다."
  if [ "${#VUL_OWNER_LIST[@]}" -gt 0 ]; then
    EVIDENCE+="[소유자 점검] ${VUL_OWNER_LIST[*]}"
  fi

  if [ "${#VUL_PERM_LIST[@]}" -gt 0 ]; then
    [ -n "$EVIDENCE" ] && EVIDENCE+=", "
    EVIDENCE+="[권한 점검] ${VUL_PERM_LIST[*]}"
  fi
else
  STATUS="PASS"
  ACTION_RESULT="SUCCESS"
  EVIDENCE="사용자, 시스템 환경변수 파일 소유자 또는 권한 설정이 적절하게 설정되어 있어 이 항목에서 보안 위협이 없습니다."
  GUIDE="KISA 보안 가이드라인을 준수하고 있습니다."
fi


# 3. 마스터 템플릿 표준 출력
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
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$CHECK_DATE"
}
EOF