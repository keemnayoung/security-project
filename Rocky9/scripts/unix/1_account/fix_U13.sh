#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 김나영
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID : U-13
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 중
# @Title : 안전한 비밀번호 암호화 알고리즘 사용
# @Description : 비밀번호 암호화 알고리즘을 강력한 SHA512로 설정하여 보안 강화
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-13"
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
IS_SUCCESS=0

CHECK_COMMAND=""     
REASON_LINE=""
DETAIL_CONTENT=""
TARGET_FILE=""

DEFS_FILE="/etc/login.defs"
PAM_SYSTEM_AUTH="/etc/pam.d/system-auth"
PAM_PASSWORD_AUTH="/etc/pam.d/password-auth"

TARGET_FILE="$DEFS_FILE $PAM_SYSTEM_AUTH $PAM_PASSWORD_AUTH"
CHECK_COMMAND='
grep -nE "^[[:space:]]*ENCRYPT_METHOD[[:space:]]+" /etc/login.defs 2>/dev/null;
grep -nE "^[[:space:]]*password[[:space:]]+.*pam_unix\.so" /etc/pam.d/system-auth 2>/dev/null;
grep -nE "^[[:space:]]*password[[:space:]]+.*pam_unix\.so" /etc/pam.d/password-auth 2>/dev/null
' | tr '\n' '; ' | sed 's/[[:space:]]\+/ /g'

MODIFIED=0
ERR_FLAG=0

# --- 함수: PAM 파일에서 pam_unix.so password 라인에 sha512 옵션이 없으면 추가 ---
ensure_pam_sha512() {
  local file="$1"

  [ -f "$file" ] || return 2  # not found (optional for password-auth)
  # pam_unix.so 포함 password 라인이 없으면 오류 취급(가이드 Step3 기준)
  if ! grep -Eqi '^[[:space:]]*password[[:space:]]+.*pam_unix\.so' "$file" 2>/dev/null; then
    return 3
  fi

  # 이미 sha512/sha256/yescrypt 중 하나라도 있으면 그대로 둠(최소 변경)
  if grep -Ei '^[[:space:]]*password[[:space:]]+.*pam_unix\.so' "$file" 2>/dev/null | grep -Eqi '(^|[[:space:]])(sha512|sha256|yescrypt)($|[[:space:]])'; then
    return 0
  fi

  # 없으면 pam_unix.so 라인 끝에 sha512 추가
  # (동일 라인이 여러 개일 수 있어 password.*pam_unix.so 매칭되는 줄 모두에 적용)
  sed -i -E '/^[[:space:]]*password[[:space:]]+.*pam_unix\.so/ s/[[:space:]]*$/ sha512/' "$file" 2>/dev/null
  return 1
}

# 조치 수행(백업 없음)
if [ -f "$DEFS_FILE" ]; then
  # 1) /etc/login.defs ENCRYPT_METHOD 설정
  CURRENT_VAL=$(grep -E '^[[:space:]]*ENCRYPT_METHOD[[:space:]]+' "$DEFS_FILE" 2>/dev/null | tail -n 1 | awk '{print $2}' | tr -d '[:space:]')

  if [ "$CURRENT_VAL" != "SHA512" ]; then
    MODIFIED=1
  fi

  if grep -qE '^[[:space:]]*ENCRYPT_METHOD[[:space:]]+' "$DEFS_FILE" 2>/dev/null; then
    sed -i 's/^[[:space:]]*ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/g' "$DEFS_FILE" 2>/dev/null
  else
    echo "ENCRYPT_METHOD SHA512" >> "$DEFS_FILE" 2>/dev/null
    MODIFIED=1
  fi

  # 2) PAM 설정(system-auth 필수)
  PAM_MOD_MSGS=""

  ensure_pam_sha512 "$PAM_SYSTEM_AUTH"
  PAM_RES=$?
  if [ $PAM_RES -eq 1 ]; then
    MODIFIED=1
    PAM_MOD_MSGS="${PAM_MOD_MSGS}system-auth: sha512 옵션 추가"$'\n'
  elif [ $PAM_RES -eq 3 ]; then
    ERR_FLAG=1
    PAM_MOD_MSGS="${PAM_MOD_MSGS}system-auth: pam_unix.so password 라인 없음(조치 실패 가능)"$'\n'
  elif [ $PAM_RES -eq 2 ]; then
    ERR_FLAG=1
    PAM_MOD_MSGS="${PAM_MOD_MSGS}system-auth: 파일 없음(필수 파일 누락)"$'\n'
  fi

  # password-auth는 존재하면 함께 처리(없으면 skip)
  if [ -f "$PAM_PASSWORD_AUTH" ]; then
    ensure_pam_sha512 "$PAM_PASSWORD_AUTH"
    PAM_RES2=$?
    if [ $PAM_RES2 -eq 1 ]; then
      MODIFIED=1
      PAM_MOD_MSGS="${PAM_MOD_MSGS}password-auth: sha512 옵션 추가"$'\n'
    elif [ $PAM_RES2 -eq 3 ]; then
      ERR_FLAG=1
      PAM_MOD_MSGS="${PAM_MOD_MSGS}password-auth: pam_unix.so password 라인 없음(조치 실패 가능)"$'\n'
    fi
  else
    PAM_MOD_MSGS="${PAM_MOD_MSGS}password-auth: 파일 없음(skip)"$'\n'
  fi

  # 조치 후 상태 수집(조치 후 상태만 detail에 표시)
  AFTER_LINE_DEFS=$(grep -nE '^[[:space:]]*ENCRYPT_METHOD[[:space:]]+' "$DEFS_FILE" 2>/dev/null | tail -n 1 | sed '/^[[:space:]]*$/d')
  RESULT_VAL=$(grep -E '^[[:space:]]*ENCRYPT_METHOD[[:space:]]+' "$DEFS_FILE" 2>/dev/null | tail -n 1 | awk '{print $2}' | tr -d '[:space:]')

  AFTER_LINE_SYS=$(grep -nE '^[[:space:]]*password[[:space:]]+.*pam_unix\.so' "$PAM_SYSTEM_AUTH" 2>/dev/null | sed '/^[[:space:]]*$/d' | tail -n 3)
  AFTER_LINE_PW=""
  if [ -f "$PAM_PASSWORD_AUTH" ]; then
    AFTER_LINE_PW=$(grep -nE '^[[:space:]]*password[[:space:]]+.*pam_unix\.so' "$PAM_PASSWORD_AUTH" 2>/dev/null | sed '/^[[:space:]]*$/d' | tail -n 3)
  fi

  DETAIL_CONTENT="$AFTER_LINE_DEFS"
  DETAIL_CONTENT="${DETAIL_CONTENT}"$'\n'"----- system-auth(pam_unix.so lines) -----"$'\n'"$AFTER_LINE_SYS"
  if [ -f "$PAM_PASSWORD_AUTH" ]; then
    DETAIL_CONTENT="${DETAIL_CONTENT}"$'\n'"----- password-auth(pam_unix.so lines) -----"$'\n'"$AFTER_LINE_PW"
  else
    DETAIL_CONTENT="${DETAIL_CONTENT}"$'\n'"----- password-auth -----"$'\n'"not_found(skip)"
  fi

  # 성공 판정: ENCRYPT_METHOD=SHA512 반영 + system-auth에 sha256/sha512/yescrypt 중 하나 존재
  SYS_HAS_SAFE=$(grep -Ei '^[[:space:]]*password[[:space:]]+.*pam_unix\.so' "$PAM_SYSTEM_AUTH" 2>/dev/null | grep -Eqi '(^|[[:space:]])(sha512|sha256|yescrypt)($|[[:space:]])'; echo $?)
  if [ "$RESULT_VAL" = "SHA512" ] && [ $SYS_HAS_SAFE -eq 0 ] && [ $ERR_FLAG -eq 0 ]; then
    IS_SUCCESS=1
    if [ "$MODIFIED" -eq 1 ]; then
      REASON_LINE="비밀번호 암호화 알고리즘이 SHA512로 설정되고, PAM(system-auth${PAM_PASSWORD_AUTH:+/password-auth})에도 안전한 알고리즘 옵션이 적용되어 조치가 완료되었습니다. (기존 계정 해시 갱신은 비밀번호 재설정이 필요할 수 있습니다.)"
    else
      REASON_LINE="비밀번호 암호화 알고리즘(SHA512)과 PAM 설정이 이미 안전 기준을 충족하여 변경 없이도 조치가 완료되었습니다. (기존 계정 해시 갱신은 비밀번호 재설정이 필요할 수 있습니다.)"
    fi
  else
    IS_SUCCESS=0
    REASON_LINE="비밀번호 암호화 알고리즘/인증 모듈 설정 조치를 수행했으나 일부 반영되지 않아 조치가 완료되지 않았습니다."
    if [ -n "$PAM_MOD_MSGS" ]; then
      DETAIL_CONTENT="${DETAIL_CONTENT}"$'\n'"----- action_note -----"$'\n'"$(printf "%s" "$PAM_MOD_MSGS" | sed '/^$/d')"
    fi
  fi
else
  IS_SUCCESS=0
  REASON_LINE="조치 대상 파일(/etc/login.defs)이 존재하지 않아 조치가 완료되지 않았습니다."
  DETAIL_CONTENT=""
fi

# raw_evidence 구성
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

# DB 저장용 JSON 출력
echo ""
cat << EOF
{
    "item_code": "$ID",
    "action_date": "$ACTION_DATE",
    "is_success": $IS_SUCCESS,
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED"
}
EOF