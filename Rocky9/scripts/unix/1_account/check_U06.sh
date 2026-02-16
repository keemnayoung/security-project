#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.0
# @Author: 김나영
# @Last Updated: 2026-02-13
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-06
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : su 명령 사용 제한
# @Description : 특정 그룹(wheel)만 su 명령을 사용할 수 있도록 제한 설정 여부 점검
# @Criteria_Good : su 명령 사용 권한이 특정 그룹에만 부여되어 있는 경우
# @Criteria_Bad : su 명령 사용 권한이 모든 사용자에게 개방되어 있는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-06"
STATUS="FAIL"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/pam.d/su"
SU_BIN="$(command -v su 2>/dev/null)"
[ -z "$SU_BIN" ] && SU_BIN="/usr/bin/su"

# 가이드 반영:
# 1) PAM 사용 중: /etc/pam.d/su 에 pam_wheel.so 활성 + (use_uid 또는 group=wheel) 권장/필수 체크
# 2) PAM 미사용/대체 통제: su 바이너리 wheel 그룹 소유 + 4750 권한이면 제한으로 인정

CHECK_COMMAND='(
  if [ -f /etc/pam.d/su ]; then
    grep -nEv "^[[:space:]]*#" /etc/pam.d/su | grep -nE "^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\.so" || echo "su_pam_rule_missing"
  else
    echo "su_pam_file_not_found"
  fi
  SU_PATH="$(command -v su 2>/dev/null)"; [ -z "$SU_PATH" ] && SU_PATH="/usr/bin/su";
  if [ -e "$SU_PATH" ]; then
    ls -l "$SU_PATH"
    stat -c "perm=%a group=%G path=%n" "$SU_PATH"
  else
    echo "su_binary_not_found"
  fi
)'

REASON_LINE=""
DETAIL_CONTENT=""

# 내부 점검 값들
PAM_ACTIVE_LINE=""
PAM_RULE_OK="no"
PAM_RULE_REASON=""

WHEEL_GROUP_LINE="$(getent group wheel 2>/dev/null)"
WHEEL_EXISTS="no"
WHEEL_MEMBERS=""
if [ -n "$WHEEL_GROUP_LINE" ]; then
  WHEEL_EXISTS="yes"
  WHEEL_MEMBERS="$(echo "$WHEEL_GROUP_LINE" | awk -F: '{print $4}')"
  [ -z "$WHEEL_MEMBERS" ] && WHEEL_MEMBERS="(none)"
else
  WHEEL_MEMBERS="(wheel group not found)"
fi

SU_EXISTS="no"
SU_PERM_OCT="N/A"
SU_GROUP="N/A"
SU_ALT_OK="no"
if [ -e "$SU_BIN" ]; then
  SU_EXISTS="yes"
  SU_PERM_OCT="$(stat -c '%a' "$SU_BIN" 2>/dev/null)"
  SU_GROUP="$(stat -c '%G' "$SU_BIN" 2>/dev/null)"
  if [ "$WHEEL_EXISTS" = "yes" ] && [ "$SU_PERM_OCT" = "4750" ] && [ "$SU_GROUP" = "wheel" ]; then
    SU_ALT_OK="yes"
  fi
fi

# 파일 존재 여부에 따른 분기 (기본 구조 유지)
if [ -f "$TARGET_FILE" ]; then
    # pam_wheel.so(auth required) 설정이 활성화되어 있는지 확인(주석 제외)
    PAM_ACTIVE_LINE="$(grep -Ev '^[[:space:]]*#' "$TARGET_FILE" 2>/dev/null \
        | grep -E '^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\.so' \
        | head -n 1)"

    if [ -n "$PAM_ACTIVE_LINE" ]; then
        # 가이드 예시 반영: use_uid 또는 group=wheel 옵션 확인
        if echo "$PAM_ACTIVE_LINE" | grep -qE '(^|[[:space:]])use_uid([[:space:]]|$)'; then
            PAM_RULE_OK="yes"
            PAM_RULE_REASON="pam_wheel.so에 use_uid 옵션 존재"
        elif echo "$PAM_ACTIVE_LINE" | grep -qE '(^|[[:space:]])group=wheel([[:space:]]|$)'; then
            PAM_RULE_OK="yes"
            PAM_RULE_REASON="pam_wheel.so에 group=wheel 옵션 존재"
        else
            PAM_RULE_OK="no"
            PAM_RULE_REASON="pam_wheel.so 라인은 있으나 use_uid 또는 group=wheel 옵션이 없음(가이드 예시 기준 미흡)"
        fi

        if [ "$PAM_RULE_OK" = "yes" ] && [ "$WHEEL_EXISTS" = "yes" ]; then
            STATUS="PASS"
            REASON_LINE="/etc/pam.d/su에 pam_wheel.so가 auth required로 설정되어 있고($PAM_RULE_REASON), wheel 그룹을 기반으로 su 사용이 제한되므로 권한 오남용 위험이 낮아 이 항목에 대한 보안 위협이 없습니다."
        else
            STATUS="FAIL"
            if [ "$WHEEL_EXISTS" != "yes" ]; then
              REASON_LINE="/etc/pam.d/su에 pam_wheel.so(auth required) 설정은 있으나($PAM_RULE_REASON), wheel 그룹이 존재하지 않아 su 접근 통제가 유효하지 않을 수 있으므로 취약합니다. wheel 그룹 생성 및 su 제한 설정을 점검해야 합니다."
            else
              REASON_LINE="/etc/pam.d/su에 pam_wheel.so(auth required) 설정은 있으나($PAM_RULE_REASON), 가이드 예시 기준의 제한 설정이 미흡하여 취약합니다. use_uid 또는 group=wheel 옵션을 포함해 su 사용자를 wheel 그룹으로 제한하도록 설정해야 합니다."
            fi
        fi

        # DETAIL_CONTENT: 대시보드 가독성(한 줄 단위) + 추가 증거 포함
        DETAIL_CONTENT="$(cat <<EOF
pam_active_line=$(echo "$PAM_ACTIVE_LINE" | sed 's/[[:space:]]*$//')
wheel_exists=$WHEEL_EXISTS
wheel_members=$WHEEL_MEMBERS
su_bin=$SU_BIN
su_perm_octal=$SU_PERM_OCT
su_group=$SU_GROUP
EOF
)"
    else
        # PAM 규칙이 없으면 대체 통제(su 바이너리 4750 + wheel)까지 확인
        if [ "$SU_ALT_OK" = "yes" ]; then
            STATUS="PASS"
            REASON_LINE="/etc/pam.d/su에 pam_wheel.so(auth required) 설정은 없으나, su 바이너리가 wheel 그룹 소유이며 권한이 4750으로 설정되어(대체 통제) wheel 그룹 사용자만 실행 가능하므로 권한 오남용 위험이 낮아 이 항목에 대한 보안 위협이 없습니다."
            DETAIL_CONTENT="$(cat <<EOF
pam_wheel_rule=missing
wheel_exists=$WHEEL_EXISTS
wheel_members=$WHEEL_MEMBERS
su_bin=$SU_BIN
su_perm_octal=$SU_PERM_OCT
su_group=$SU_GROUP
EOF
)"
        else
            STATUS="FAIL"
            REASON_LINE="/etc/pam.d/su에 pam_wheel.so(auth required) 설정이 없어 모든 사용자가 su 명령을 사용할 수 있어 권한 오남용 및 관리자 권한 상승 위험이 있으므로 취약합니다. pam_wheel.so 설정을 적용하거나, su 바이너리를 wheel 그룹 소유 및 4750 권한으로 제한해야 합니다."
            DETAIL_CONTENT="$(cat <<EOF
pam_wheel_rule=missing
wheel_exists=$WHEEL_EXISTS
wheel_members=$WHEEL_MEMBERS
su_bin=$SU_BIN
su_perm_octal=$SU_PERM_OCT
su_group=$SU_GROUP
EOF
)"
        fi
    fi
else
    # PAM 파일이 없으면 대체 통제(su 바이너리 4750 + wheel)까지 확인
    if [ "$SU_ALT_OK" = "yes" ]; then
        STATUS="PASS"
        REASON_LINE="시스템 인증 설정 파일(/etc/pam.d/su)은 존재하지 않으나, su 바이너리가 wheel 그룹 소유이며 권한이 4750으로 설정되어(대체 통제) wheel 그룹 사용자만 실행 가능하므로 권한 오남용 위험이 낮아 이 항목에 대한 보안 위협이 없습니다."
        DETAIL_CONTENT="$(cat <<EOF
pam_su_file_not_found
wheel_exists=$WHEEL_EXISTS
wheel_members=$WHEEL_MEMBERS
su_bin=$SU_BIN
su_perm_octal=$SU_PERM_OCT
su_group=$SU_GROUP
EOF
)"
    else
        STATUS="FAIL"
        REASON_LINE="시스템 인증 설정 파일(/etc/pam.d/su)이 존재하지 않아 PAM 기반 su 접근 통제를 확인할 수 없고, su 바이너리 권한/그룹 기반의 대체 통제(4750+wheel)도 확인되지 않아 취약합니다. 환경에 맞는 PAM 설정 또는 su 바이너리 권한 제한을 적용해야 합니다."
        DETAIL_CONTENT="$(cat <<EOF
pam_su_file_not_found
wheel_exists=$WHEEL_EXISTS
wheel_members=$WHEEL_MEMBERS
su_bin=$SU_BIN
su_perm_octal=$SU_PERM_OCT
su_group=$SU_GROUP
EOF
)"
    fi
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

# scan_history 저장용 JSON 출력 (형태 유지)
echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF