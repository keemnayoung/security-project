#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.1.0
# @Author: 권순형
# @Last Updated: 2026-02-15
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-33
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 하
# @Title       : 숨겨진 파일 및 디렉토리 검색 및 제거
# @Description : 숨겨진 파일 및 디렉토리 내 의심스러운 파일 존재 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-33"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_DIRS=("/root" "/home" "/etc" "/tmp" "/var/tmp")
TARGET_FILE="$(printf "%s " "${TARGET_DIRS[@]}" | sed 's/[[:space:]]*$//')"

CHECK_COMMAND='for d in /root /home /etc /tmp /var/tmp; do [ -d "$d" ] && ls -al "$d"; done; for d in /root /home /etc /tmp /var/tmp; do [ -d "$d" ] && find "$d" -xdev -type f -name ".*" 2>/dev/null; [ -d "$d" ] && find "$d" -xdev -type d -name ".*" 2>/dev/null; done'

DETAIL_CONTENT=""
REASON_LINE=""
GUIDE_LINE="정상 동작에 필요한 숨김 설정 파일까지 삭제되어 서비스 또는 사용자 환경에 장애가 발생할 위험이 존재하여 수동 조치가 필요합니다.
관리자가 직접 확인 후 불필요하거나 의심스러운 숨김 파일/디렉터리를 rm 또는 rm -r로 제거해 주시기 바랍니다."

# JSON escape 유틸 (백슬래시/따옴표/줄바꿈)
json_escape() {
  echo "$1" \
    | sed 's/\\/\\\\/g' \
    | sed 's/"/\\"/g' \
    | sed ':a;N;$!ba;s/\n/\\n/g'
}

# 숨겨진 파일/디렉터리 수집
HIDDEN_FILES_RAW=""
HIDDEN_DIRS_RAW=""
HIDDEN_FILES_FLAT=""
HIDDEN_DIRS_FLAT=""

for d in "${TARGET_DIRS[@]}"; do
  [ -d "$d" ] || continue

  f=$(find "$d" -xdev -type f -name ".*" 2>/dev/null | head -n 50)
  if [ -n "$f" ]; then
    HIDDEN_FILES_RAW+="$d:"$'\n'"$f"$'\n'
    HIDDEN_FILES_FLAT+="$f"$'\n'
  fi

  dd=$(find "$d" -xdev -type d -name ".*" 2>/dev/null | head -n 50)
  if [ -n "$dd" ]; then
    HIDDEN_DIRS_RAW+="$d:"$'\n'"$dd"$'\n'
    HIDDEN_DIRS_FLAT+="$dd"$'\n'
  fi
done

# Step1: 특정 디렉토리 ls -al 결과 수집
LS_AL_RAW=""
for d in "${TARGET_DIRS[@]}"; do
  [ -d "$d" ] || continue
  LS_AL_RAW+="[ls -al $d]"$'\n'
  LS_AL_RAW+=$(ls -al "$d" 2>/dev/null | head -n 60)
  LS_AL_RAW+=$'\n\n'
done

# DETAIL_CONTENT는 양호/취약과 관계 없이 "현재 설정값"만 표기
DETAIL_CONTENT="Target_dirs: $TARGET_FILE"$'\n\n'
DETAIL_CONTENT+="[Step1: ls -al 결과(일부)]"$'\n'
DETAIL_CONTENT+="$LS_AL_RAW"$'\n'
DETAIL_CONTENT+="[Step2: find 결과]"$'\n'

DETAIL_CONTENT+="Hidden_files:"$'\n'
if [ -n "$HIDDEN_FILES_RAW" ]; then
  DETAIL_CONTENT+="$HIDDEN_FILES_RAW"$'\n'
else
  DETAIL_CONTENT+="none"$'\n'
fi

DETAIL_CONTENT+="Hidden_directories:"$'\n'
if [ -n "$HIDDEN_DIRS_RAW" ]; then
  DETAIL_CONTENT+="$HIDDEN_DIRS_RAW"
else
  DETAIL_CONTENT+="none"
fi

# PASS/FAIL 분기: reason 문장은 1문장, "어떠한 이유(설정 값)"만 포함
if [[ -n "$HIDDEN_FILES_RAW" || -n "$HIDDEN_DIRS_RAW" ]]; then
  STATUS="FAIL"

  # 취약한 부분(발견된 항목)만 reason에 포함 (너무 길어지지 않게 상위 일부만)
  HF_REASON="$(echo "$HIDDEN_FILES_FLAT" | sed '/^[[:space:]]*$/d' | head -n 10 | paste -sd ', ' -)"
  HD_REASON="$(echo "$HIDDEN_DIRS_FLAT"  | sed '/^[[:space:]]*$/d' | head -n 10 | paste -sd ', ' -)"

  # 둘 중 하나만 있을 수도 있으니 자연스럽게 구성
  if [ -n "$HF_REASON" ] && [ -n "$HD_REASON" ]; then
    REASON_LINE="Hidden_files: $HF_REASON, Hidden_directories: $HD_REASON 가 존재하여 이 항목에 대해 취약합니다."
  elif [ -n "$HF_REASON" ]; then
    REASON_LINE="Hidden_files: $HF_REASON 가 존재하여 이 항목에 대해 취약합니다."
  else
    REASON_LINE="Hidden_directories: $HD_REASON 가 존재하여 이 항목에 대해 취약합니다."
  fi
else
  STATUS="PASS"
  REASON_LINE="Hidden_files: none, Hidden_directories: none 로 확인되어 이 항목에 대해 양호합니다."
fi

# RAW_EVIDENCE 구성: 각 값은 문장/블록을 줄바꿈으로 구분 (파이썬/DB 복원용 \n 이스케이프)
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE
$DETAIL_CONTENT",
  "guide": "$GUIDE_LINE",
  "target_file": "$TARGET_FILE"
}
EOF
)

RAW_EVIDENCE_ESCAPED="$(json_escape "$RAW_EVIDENCE")"

echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF
