#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.1
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

# 가이드 Step1(특정 디렉토리 ls -al) + Step2(find) 취지 반영:
# 전역(/)이 아니라 관리자가 확인해야 하는 핵심 디렉토리만 점검
TARGET_DIRS=("/root" "/home" "/etc" "/tmp" "/var/tmp")
TARGET_FILE="$(printf "%s " "${TARGET_DIRS[@]}" | sed 's/[[:space:]]*$//')"

CHECK_COMMAND='for d in /root /home /etc /tmp /var/tmp; do [ -d "$d" ] && ls -al "$d"; done; for d in /root /home /etc /tmp /var/tmp; do [ -d "$d" ] && find "$d" -xdev -type f -name ".*" 2>/dev/null; [ -d "$d" ] && find "$d" -xdev -type d -name ".*" 2>/dev/null; done'

DETAIL_CONTENT=""
REASON_LINE=""

# --------------------------------------------------------------------
# 숨겨진 파일/디렉터리 수집 (핵심 디렉토리 기준, 동일 파일시스템(-xdev))
# --------------------------------------------------------------------
HIDDEN_FILES_RAW=""
HIDDEN_DIRS_RAW=""

for d in "${TARGET_DIRS[@]}"; do
  [ -d "$d" ] || continue

  # 파일
  f=$(find "$d" -xdev -type f -name ".*" 2>/dev/null | head -n 50)
  if [ -n "$f" ]; then
    HIDDEN_FILES_RAW+="$d:"$'\n'"$f"$'\n'
  fi

  # 디렉터리
  dd=$(find "$d" -xdev -type d -name ".*" 2>/dev/null | head -n 50)
  if [ -n "$dd" ]; then
    HIDDEN_DIRS_RAW+="$d:"$'\n'"$dd"$'\n'
  fi
done

# --------------------------------------------------------------------
# 가이드 Step1: 특정 디렉토리 ls -al 결과도 evidence에 포함(필수 보완)
# --------------------------------------------------------------------
LS_AL_RAW=""
for d in "${TARGET_DIRS[@]}"; do
  [ -d "$d" ] || continue
  # 너무 길어지지 않게 각 디렉토리별 상위 일부만 포함
  LS_AL_RAW+="[ls -al $d]"$'\n'
  LS_AL_RAW+=$(ls -al "$d" 2>/dev/null | head -n 60)
  LS_AL_RAW+=$'\n\n'
done

# 결과 유무에 따른 PASS/FAIL 결정
if [[ -n "$HIDDEN_FILES_RAW" || -n "$HIDDEN_DIRS_RAW" ]]; then
    STATUS="FAIL"
    REASON_LINE="점검 대상 핵심 디렉토리에서 숨겨진 파일 또는 숨겨진 디렉터리가 발견되었습니다. 정상 설정 파일일 수도 있으므로 용도를 확인하고, 불필요하거나 의심스러운 항목만 제거해야 합니다."

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
else
    STATUS="PASS"
    REASON_LINE="점검 대상 핵심 디렉토리에서 숨겨진 파일이나 숨겨진 디렉터리가 발견되지 않았습니다."
    DETAIL_CONTENT="Target_dirs: $TARGET_FILE\nnone"
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