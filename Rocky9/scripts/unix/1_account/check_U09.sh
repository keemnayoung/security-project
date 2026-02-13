#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 김나영
# @Last Updated: 2026-02-09
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-09
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 하
# @Title : 계정이 존재하지 않는 GID 금지
# @Description : /etc/group 파일에 설정된 그룹 중 소속된 계정이 없는 불필요한 그룹 점검
# @Criteria_Good : 소속 계정이 없는 불필요한 그룹이 존재하지 않는 경우
# @Criteria_Bad : 소속 계정이 없는 불필요한 그룹이 존재하는 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-09"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

GROUP_FILE="/etc/group"
PASSWD_FILE="/etc/passwd"
GSHADOW_FILE="/etc/gshadow"
TARGET_FILE="$GROUP_FILE $PASSWD_FILE $GSHADOW_FILE"

CHECK_COMMAND='[ -f /etc/group ] && [ -f /etc/passwd ] && [ -f /etc/gshadow ] && awk -F: '\''{print $1 ":" $3 ":" $4}'\'' /etc/group || echo "group_or_passwd_or_gshadow_not_found"'

REASON_LINE=""
DETAIL_CONTENT=""

UNUSED_GROUPS=()
GID_MIN=1000

# 추가 점검용 배열
MISMATCH_GROUPS=()        # group에는 있는데 gshadow에는 없음 / 반대 케이스
GHOST_MEMBERS=()          # group 멤버(GMEM)에 존재하지 않는 계정이 포함된 케이스

# 파일 존재 여부에 따른 분기 (필수: /etc/gshadow 포함)
if [ -f "$GROUP_FILE" ] && [ -f "$PASSWD_FILE" ] && [ -f "$GSHADOW_FILE" ]; then

    # ---------------------------
    # (필수 추가 1) /etc/group <-> /etc/gshadow 정합성 점검
    # ---------------------------

    # group에는 있는데 gshadow에는 없는 그룹
    while IFS=: read -r GNAME _; do
        [ -z "$GNAME" ] && continue
        if ! grep -qE "^${GNAME}:" "$GSHADOW_FILE" 2>/dev/null; then
            MISMATCH_GROUPS+=("group_only:$GNAME")
        fi
    done < "$GROUP_FILE"

    # gshadow에는 있는데 group에는 없는 그룹
    while IFS=: read -r GNAME _; do
        [ -z "$GNAME" ] && continue
        if ! grep -qE "^${GNAME}:" "$GROUP_FILE" 2>/dev/null; then
            MISMATCH_GROUPS+=("gshadow_only:$GNAME")
        fi
    done < "$GSHADOW_FILE"

    # ---------------------------
    # 기존 점검: 유휴 그룹 (GID 1000 이상, 어떤 계정도 사용 안 함)
    # ---------------------------
    while IFS=: read -r GNAME GPASS GID GMEM; do
        if [ -n "$GID" ] && [ "$GID" -ge "$GID_MIN" ]; then
            # 해당 GID를 기본 그룹으로 쓰는 유저 확인
            USER_EXISTS=$(awk -F: -v gid="$GID" '$4 == gid {print $1}' "$PASSWD_FILE" 2>/dev/null | head -n 1)

            # (필수 추가 2) GMEM에 적힌 멤버가 /etc/passwd에 실제 존재하는지 확인
            if [ -n "$GMEM" ]; then
                IFS=',' read -r -a MEMBERS <<< "$GMEM"
                for m in "${MEMBERS[@]}"; do
                    m_trim="$(echo "$m" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
                    [ -z "$m_trim" ] && continue
                    if ! awk -F: -v u="$m_trim" '$1==u{found=1} END{exit(found?0:1)}' "$PASSWD_FILE" 2>/dev/null; then
                        GHOST_MEMBERS+=("$GNAME:$m_trim")
                    fi
                done
            fi

            # 유저도 없고, 그룹 멤버 리스트도 비어있으면 유휴 그룹
            if [ -z "$USER_EXISTS" ] && [ -z "$GMEM" ]; then
                UNUSED_GROUPS+=("$GNAME($GID)")
            fi
        fi
    done < "$GROUP_FILE"

    # ---------------------------
    # 최종 판정: 필수 추가 항목(정합성/유령멤버) 우선 반영 + 기존 유휴그룹 반영
    # ---------------------------
    if [ ${#MISMATCH_GROUPS[@]} -gt 0 ] || [ ${#GHOST_MEMBERS[@]} -gt 0 ] || [ ${#UNUSED_GROUPS[@]} -gt 0 ]; then
        STATUS="FAIL"
        REASON_LINE="불필요/비정상 그룹 관리 상태가 확인되었습니다. (/etc/group, /etc/gshadow, /etc/passwd 정합성 불일치 또는 존재하지 않는 계정의 그룹 멤버 등록, 또는 유휴 그룹 존재) 불필요한 권한/리소스 관리 대상이 늘어나고 운영 정책 관리가 어려워질 수 있으므로 취약합니다. 사용 계획이 없다면 해당 그룹/등록 정보를 정리해야 합니다."

        DETAIL_CONTENT=""
        if [ ${#MISMATCH_GROUPS[@]} -gt 0 ]; then
            DETAIL_CONTENT="${DETAIL_CONTENT}mismatch_group_vs_gshadow:\n$(printf "%s\n" "${MISMATCH_GROUPS[@]}")\n"
        else
            DETAIL_CONTENT="${DETAIL_CONTENT}mismatch_group_vs_gshadow:\nnone\n"
        fi

        if [ ${#GHOST_MEMBERS[@]} -gt 0 ]; then
            DETAIL_CONTENT="${DETAIL_CONTENT}ghost_members_in_group:\n$(printf "%s\n" "${GHOST_MEMBERS[@]}")\n"
        else
            DETAIL_CONTENT="${DETAIL_CONTENT}ghost_members_in_group:\nnone\n"
        fi

        if [ ${#UNUSED_GROUPS[@]} -gt 0 ]; then
            DETAIL_CONTENT="${DETAIL_CONTENT}unused_groups_gid_1000_plus:\n$(printf "%s\n" "${UNUSED_GROUPS[@]}")"
        else
            DETAIL_CONTENT="${DETAIL_CONTENT}unused_groups_gid_1000_plus:\nnone"
        fi
    else
        STATUS="PASS"
        REASON_LINE="(/etc/group, /etc/gshadow, /etc/passwd) 간 그룹 정합성이 유지되고, 존재하지 않는 계정의 그룹 멤버 등록 및 유휴 그룹이 확인되지 않아 이 항목에 대한 보안 위협이 없습니다."
        DETAIL_CONTENT="no_mismatch_no_ghost_members_no_unused_groups_gid_1000_plus"
    fi

else
    STATUS="FAIL"
    REASON_LINE="그룹 또는 사용자 정보 파일(/etc/group, /etc/passwd, /etc/gshadow)이 존재하지 않아 그룹 정합성 및 불필요/비정상 그룹 여부를 점검할 수 없으므로 취약합니다. 파일을 복구한 뒤 점검해야 합니다."

    DETAIL_CONTENT=""
    [ ! -f "$GROUP_FILE" ] && DETAIL_CONTENT="${DETAIL_CONTENT}group_not_found\n"
    [ -f "$GROUP_FILE" ] && DETAIL_CONTENT="${DETAIL_CONTENT}group_exists\n"
    [ ! -f "$PASSWD_FILE" ] && DETAIL_CONTENT="${DETAIL_CONTENT}passwd_not_found\n"
    [ -f "$PASSWD_FILE" ] && DETAIL_CONTENT="${DETAIL_CONTENT}passwd_exists\n"
    [ ! -f "$GSHADOW_FILE" ] && DETAIL_CONTENT="${DETAIL_CONTENT}gshadow_not_found"
    [ -f "$GSHADOW_FILE" ] && DETAIL_CONTENT="${DETAIL_CONTENT}gshadow_exists"
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