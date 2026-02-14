#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-32
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 중
# @Title       : 홈 디렉토리로 지정한 디렉토리의 존재 관리
# @Description : 사용자 계정과 홈 디렉토리의 일치 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-32"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/passwd"

# (수정) UID 조건 제거 + 로그인 불가 쉘 제외 로직 반영
CHECK_COMMAND='while IFS=: read -r u _ uid _ _ h s; do \
  case "$s" in */nologin|*/false) continue ;; esac; \
  echo "$u:$h:$s"; \
done < /etc/passwd'

MISSING_HOME_USERS=()
FOUND_VULN="N"
DETAIL_CONTENT=""
REASON_LINE=""

# /etc/passwd를 순회하며 홈 디렉터리 존재 여부 점검
# (추가) 로그인 불가 쉘(/sbin/nologin, /bin/false 등) 계정은 제외
# (추가) homedir가 비어있거나(-), 절대경로가 아니면 취약 처리
while IFS=: read -r username _ uid _ _ homedir shell; do
    # 로그인 불가 계정 제외
    case "$shell" in
        */nologin|*/false) continue ;;
    esac

    # 홈 디렉터리 값 자체가 비정상인 경우도 취약
    if [ -z "$homedir" ] || [ "$homedir" = "-" ] || [[ "$homedir" != /* ]]; then
        STATUS="FAIL"
        FOUND_VULN="Y"
        MISSING_HOME_USERS+=("$username:$homedir(비정상경로)")
        continue
    fi

    # 홈 디렉터리 실제 존재 여부 점검
    if [ ! -d "$homedir" ]; then
        STATUS="FAIL"
        FOUND_VULN="Y"
        MISSING_HOME_USERS+=("$username:$homedir")
    fi
done < "$TARGET_FILE"

# 결과에 따른 평가 이유 및 detail 구성
if [ "$FOUND_VULN" = "Y" ]; then
    REASON_LINE="로그인 가능한 계정 중 홈 디렉터리가 존재하지 않거나 비정상으로 지정된 계정이 있어 로그인 시 루트(/) 등 임의 디렉터리를 기준으로 동작할 위험이 있으므로 취약합니다. 해당 계정에 홈 디렉터리를 생성하여 할당하거나 불필요한 계정은 제거해야 합니다."
    DETAIL_CONTENT="$(printf "%s\n" "${MISSING_HOME_USERS[@]}" | sed 's/[[:space:]]*$//')"
else
    STATUS="PASS"
    REASON_LINE="로그인 가능한 계정이 모두 존재하는 홈 디렉터리를 사용하도록 설정되어 있어 로그인 환경과 파일 권한 관리가 정상적으로 동작하므로 이 항목에 대한 보안 위협이 없습니다."
    DETAIL_CONTENT="all_users_have_home"
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