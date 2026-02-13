#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.2
# @Author: 권순형
# @Last Updated: 2026-02-10
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-14
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : root 홈, 패스 디렉터리 권한 및 패스 설정
# @Description : root 계정의 PATH 환경변수에 “.”(마침표)이 포함 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

# 기본 변수
ID="U-14"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

CHECK_COMMAND="su - root -c 'echo \$PATH'"

# 1) root 로그인 쉘 확인 + 쉘별 환경설정 파일 목록 구성
#    (가이드: /etc/profile -> root 환경설정 파일 순차 확인)
ROOT_SHELL=$(getent passwd root | cut -d: -f7)
SHELL_NAME=$(basename "$ROOT_SHELL")

TARGET_FILES=()

case "$SHELL_NAME" in
  sh)
    TARGET_FILES=(/etc/profile /root/.profile)
    ;;
  csh)
    TARGET_FILES=(/etc/csh.cshrc /etc/csh.login /root/.cshrc /root/.login)
    ;;
  ksh)
    TARGET_FILES=(/etc/profile /root/.profile /root/.kshrc)
    ;;
  bash)
    TARGET_FILES=(/etc/profile /etc/bash.bashrc /root/.bash_profile /root/.bashrc)
    ;;
  *)
    # 쉘이 예상 밖이어도 최소로 /etc/profile, /root/.profile는 확인
    TARGET_FILES=(/etc/profile /root/.profile)
    ;;
esac

# TARGET_FILE 문자열(증적용)
TARGET_FILE="$(printf "%s, " "${TARGET_FILES[@]}")"
TARGET_FILE="${TARGET_FILE%, }"

# 2) root 최종 PATH 수집 및 '.' 위치 판정 (판단 기준)
#    - 양호: '.'이 맨 앞/중간에 없음(없거나, 맨 마지막만 존재)
#    - 취약: '.'이 맨 앞 또는 중간에 존재
ROOT_PATH=$(su - root -c 'echo $PATH' 2>/dev/null)

IFS=':' read -ra PATH_ITEMS <<< "$ROOT_PATH"

INDEX=0
DOT_FOUND="N"
DOT_AT_START="N"
DOT_IN_MIDDLE="N"
DOT_AT_END="N"

for ITEM in "${PATH_ITEMS[@]}"; do
  if [ "$ITEM" = "." ]; then
    DOT_FOUND="Y"
    if [ "$INDEX" -eq 0 ]; then
      DOT_AT_START="Y"
    elif [ "$INDEX" -lt $((${#PATH_ITEMS[@]} - 1)) ]; then
      DOT_IN_MIDDLE="Y"
    else
      DOT_AT_END="Y"
    fi
  fi
  INDEX=$((INDEX + 1))
done

if [ "$DOT_FOUND" = "N" ]; then
  STATUS="PASS"
  REASON_LINE="root PATH에 '.'이 포함되어 있지 않습니다. (양호)"
elif [ "$DOT_AT_END" = "Y" ] && [ "$DOT_AT_START" = "N" ] && [ "$DOT_IN_MIDDLE" = "N" ]; then
  STATUS="PASS"
  REASON_LINE="root PATH에서 '.'이 맨 마지막에만 존재합니다. (양호)"
else
  STATUS="FAIL"
  if [ "$DOT_AT_START" = "Y" ]; then
    REASON_LINE="root PATH에서 '.'이 맨 앞에 존재합니다. (취약)"
  else
    REASON_LINE="root PATH에서 '.'이 중간에 존재합니다. (취약)"
  fi
fi


# 3) 원인(설정 파일) 추적 증적 추가
#    - /etc/profile -> root 환경설정 파일 순차적으로 PATH 정의 라인 확인
#    - 주석 제외 PATH= / export PATH= 라인 수집
FILE_TRACE=""

classify_path_dot_position() {
  # 입력: PATH 문자열(예: .:/usr/bin:/bin or /usr/bin:/bin:.)
  local p="$1"
  IFS=':' read -ra parts <<< "$p"
  local n=${#parts[@]}
  local i=0
  local start="N" mid="N" end="N" found="N"

  for ((i=0; i<n; i++)); do
    if [ "${parts[$i]}" = "." ]; then
      found="Y"
      if [ "$i" -eq 0 ]; then
        start="Y"
      elif [ "$i" -eq $((n-1)) ]; then
        end="Y"
      else
        mid="Y"
      fi
    fi
  done

  if [ "$found" = "N" ]; then
    echo "DOT=NONE"
  elif [ "$start" = "Y" ] || [ "$mid" = "Y" ]; then
    echo "DOT=VULNERABLE(start=$start,mid=$mid,end=$end)"
  else
    echo "DOT=SAFE(end_only=Y)"
  fi
}

for F in "${TARGET_FILES[@]}"; do
  if [ ! -f "$F" ]; then
    FILE_TRACE+="[INFO] $F (not found)\n"
    continue
  fi

  # 주석 제외 PATH 정의 라인들
  LINES=$(grep -E '^[[:space:]]*(export[[:space:]]+)?PATH=' "$F" 2>/dev/null | grep -v '^[[:space:]]*#')
  if [ -z "$LINES" ]; then
    FILE_TRACE+="[INFO] $F (no PATH definition)\n"
    continue
  fi

  # 각 라인에 대해 PATH 값 부분만 뽑아서 '.' 위치 분류
  while IFS= read -r line; do
    val=$(echo "$line" | sed -E 's/^[[:space:]]*(export[[:space:]]+)?PATH=//')
    val=$(echo "$val" | sed 's/"//g')
    pos=$(classify_path_dot_position "$val")
    FILE_TRACE+="[CHECK] $F | $line | $pos\n"
  done <<< "$LINES"
done

DETAIL_CONTENT="root_shell=$SHELL_NAME, root_path=$ROOT_PATH"

# raw_evidence 구성 (평가 이유 + 현재 값 + 파일 추적)
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT\n\n[config_file_trace]\n$FILE_TRACE",
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