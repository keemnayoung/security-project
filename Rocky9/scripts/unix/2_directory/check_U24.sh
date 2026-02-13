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

# 기본 변수
ID="U-24"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

CHECK_COMMAND='for u in /etc/passwd; do 홈디렉터리 내 (.profile .kshrc .cshrc .bashrc .bash_profile .login .exrc .netrc) 파일에 대해 소유자(root 또는 계정) 및 group/other 쓰기 권한 여부(stat) 점검'
TARGET_FILE=""

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

DETAIL_CONTENT=""
REASON_LINE=""
FOUND_VULN="N"
VULN_LINES=""

# /etc/passwd를 순회하며 홈 디렉터리 내 환경변수 파일 점검
while IFS=: read -r USER _ _ _ _ HOME_DIR _; do
  [ -d "$HOME_DIR" ] || continue

  for ENV_FILE in "${ENV_FILES[@]}"; do
    FILE_PATH="$HOME_DIR/$ENV_FILE"
    [ -f "$FILE_PATH" ] || continue

    OWNER="$(stat -c %U "$FILE_PATH" 2>/dev/null)"
    PERM="$(stat -c %A "$FILE_PATH" 2>/dev/null)"

    # 소유자(root 또는 해당 계정) 조건 위반
    if [[ "$OWNER" != "root" && "$OWNER" != "$USER" ]]; then
      STATUS="FAIL"
      FOUND_VULN="Y"
      VULN_LINES+="$FILE_PATH owner=$OWNER user=$USER perm=$PERM"$'\n'
      TARGET_FILE+="$FILE_PATH "
      continue
    fi

    # group/other 쓰기 권한 존재 여부 점검
    if [[ "${PERM:5:1}" == "w" || "${PERM:8:1}" == "w" ]]; then
      STATUS="FAIL"
      FOUND_VULN="Y"
      VULN_LINES+="$FILE_PATH owner=$OWNER user=$USER perm=$PERM"$'\n'
      TARGET_FILE+="$FILE_PATH "
    fi
  done
done < /etc/passwd

# 결과에 따른 평가 이유 및 detail 구성
if [ "$FOUND_VULN" = "Y" ]; then
  REASON_LINE="사용자 환경변수 파일의 소유자가 root 또는 해당 계정이 아니거나, group/other 쓰기 권한이 허용되어 있어 환경 초기화 스크립트가 임의로 변조될 위험이 있으므로 취약합니다. 각 파일의 소유자를 root 또는 해당 사용자로 변경하고 group/other 쓰기 권한(o-w, g-w)을 제거해야 합니다."
  DETAIL_CONTENT="$(printf "%s" "$VULN_LINES" | sed 's/[[:space:]]*$//')"
  TARGET_FILE="$(echo "$TARGET_FILE" | tr -s ' ' | sed 's/[[:space:]]*$//')"
else
  STATUS="PASS"
  REASON_LINE="사용자 환경변수 파일의 소유자가 root 또는 해당 계정으로 설정되어 있고 group/other 쓰기 권한이 제거되어 있어 초기화 스크립트 변조 위험이 없으므로 이 항목에 대한 보안 위협이 없습니다."
  DETAIL_CONTENT="all_files_ok"
  TARGET_FILE="user_home_env_files"
fi

# raw_evidence 구성 (첫 줄: 평가 이유 / 다음 줄부터: 현재 설정값)
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

# scan_history 저장용 JSON 출력
echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF