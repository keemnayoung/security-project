#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 2.0.1
# @Author: 권순형
# @Last Updated: 2026-02-15
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-31
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 중
# @Title       : 홈디렉토리 소유자 및 권한 설정
# @Description : 홈 디렉토리의 소유자 외 타 사용자가 해당 홈 디렉토리를 수정할 수 없도록 제한 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================


# 기본 변수
ID="U-31"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/passwd"
CHECK_COMMAND='while IFS=: read -r u _ _ _ _ h _; do [ -d "$h" ] && stat -c "%n owner=%U perm=%a" "$h"; done < /etc/passwd; for b in /home /export/home; do [ -d "$b" ] && find "$b" -mindepth 1 -maxdepth 1 -type d -print 2>/dev/null; done'

DETAIL_CONTENT=""
REASON_LINE=""
VULN_LINES=""
FOUND_VULN="N"

# -------------------------------------------------------------------
# 1) /etc/passwd에 등록된 홈 디렉터리 소유자/권한 점검
# -------------------------------------------------------------------
HOME_LIST=""   # 홈 디렉터리 목록(추가 사용자 디렉터리 탐지용)

while IFS=: read -r USER _ _ _ _ HOME _; do
    [ -d "$HOME" ] || continue

    HOME_LIST+="$HOME"$'\n'

    OWNER=$(stat -c %U "$HOME" 2>/dev/null | tr -d '[:space:]')
    PERM=$(stat -c %a "$HOME" 2>/dev/null | tr -d '[:space:]')

    # other write 여부 확인 (마지막 자리)
    OTHER_DIGIT=$((PERM % 10))

    # 조건 위반 시 취약 목록에 추가 (소유자 불일치 또는 other write 존재)
    if [[ "$OWNER" != "$USER" || "$OTHER_DIGIT" -ge 2 ]]; then
        STATUS="FAIL"
        FOUND_VULN="Y"
        VULN_LINES+="${USER}:${HOME} owner=${OWNER} perm=${PERM}"$'\n'
    fi
done < /etc/passwd

# -------------------------------------------------------------------
# 2) (가이드 필수) 사용자 홈 디렉터리 외 개별 사용자 디렉터리 존재 여부 확인
#    - /home/*, /export/home/* 중 /etc/passwd HOME 목록에 없는 디렉터리 탐지
#    - other write(o+w)가 있으면 취약으로 포함
#    - other write가 없으면 "추가 확인 필요"로 detail에만 표시
# -------------------------------------------------------------------
EXTRA_LINES=""
EXTRA_VULN_LINES=""

is_in_home_list() {
    local p="$1"
    # HOME_LIST에 정확히 동일 경로가 있는지 확인(라인 단위)
    printf "%s" "$HOME_LIST" | grep -Fxq "$p"
}

for BASE in /home /export/home; do
    [ -d "$BASE" ] || continue

    while IFS= read -r D; do
        [ -d "$D" ] || continue

        # /etc/passwd의 HOME으로 등록된 경로면 제외
        if is_in_home_list "$D"; then
            continue
        fi

        D_OWNER=$(stat -c %U "$D" 2>/dev/null | tr -d '[:space:]')
        D_PERM=$(stat -c %a "$D" 2>/dev/null | tr -d '[:space:]')
        D_OTHER_DIGIT=$((D_PERM % 10))

        # other write가 있으면 "취약"으로 포함
        if [[ "$D_OTHER_DIGIT" -ge 2 ]]; then
            STATUS="FAIL"
            FOUND_VULN="Y"
            EXTRA_VULN_LINES+="extra_dir:${D} owner=${D_OWNER} perm=${D_PERM}"$'\n'
        else
            # 취약 판정까지는 하지 않되, 가이드상 존재 여부는 표시(추가 확인 필요)
            EXTRA_LINES+="extra_dir:${D} owner=${D_OWNER} perm=${D_PERM} (추가 확인 필요)"$'\n'
        fi
    done < <(find "$BASE" -mindepth 1 -maxdepth 1 -type d -print 2>/dev/null)
done

# 취약 라인 합치기
if [ -n "$EXTRA_VULN_LINES" ]; then
    VULN_LINES+="$EXTRA_VULN_LINES"
fi

# 결과에 따른 평가 이유 및 detail 구성
if [ "$FOUND_VULN" = "Y" ]; then
    REASON_LINE="사용자 홈 디렉터리의 소유자가 해당 계정과 다르거나 타 사용자(other) 쓰기 권한이 허용(또는 홈 외 사용자 디렉터리에 other 쓰기 권한 존재)되어 변조 위험이 있으므로 취약합니다. 각 디렉터리의 소유자를 해당 사용자로 변경하고 타 사용자 쓰기 권한을 제거해야 합니다."
    DETAIL_CONTENT="$(printf "%s" "$VULN_LINES" | sed 's/[[:space:]]*$//')"
    # 취약이더라도 추가 디렉터리(취약 아님) 정보는 뒤에 붙여 제공
    if [ -n "$EXTRA_LINES" ]; then
        DETAIL_CONTENT+=$'\n'"---- extra_user_dirs_found (not vuln but review needed) ----"$'\n'
        DETAIL_CONTENT+="$(printf "%s" "$EXTRA_LINES" | sed 's/[[:space:]]*$//')"
    fi
else
    STATUS="PASS"
    REASON_LINE="사용자 홈 디렉터리의 소유자가 해당 계정으로 설정되어 있고 타 사용자(other) 쓰기 권한이 제거되어 있어 변조 위험이 없으므로 이 항목에 대한 보안 위협이 없습니다."
    if [ -n "$EXTRA_LINES" ]; then
        # 양호이지만 가이드상 '추가 사용자 디렉터리 존재 여부'는 표시
        DETAIL_CONTENT="all_homes_ok"$'\n'"---- extra_user_dirs_found (review needed) ----"$'\n'
        DETAIL_CONTENT+="$(printf "%s" "$EXTRA_LINES" | sed 's/[[:space:]]*$//')"
    else
        DETAIL_CONTENT="all_homes_ok"
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