#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-14
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : root 홈, 패스 디렉터리 권한 및 패스 설정
# @Description : PATH 환경변수 내 '.'을 마지막 위치로 이동
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================


# 1. 항목 정보 정의 (JSON 출력용)
ID="U-14"
CATEGORY="파일 및 디렉토리 관리"
TITLE="root 홈, 패스 디렉터리 권한 및 패스 설정"
IMPORTANCE="상"
STATUS="FAIL"
EVIDENCE=""
GUIDE=""
ACTION_RESULT="FAIL"
ACTION_LOG=""
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
CHECK_DATE="$(date '+%Y-%m-%d %H:%M:%S')"


# 2. root 로그인 쉘 확인 및 대상 파일 정의
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
        ACTION_RESULT="ERROR"
        STATUS="FAIL"
        ACTION_LOG="지원하지 않는 쉘 유형: $SHELL_NAME"
        EVIDENCE="지원하지 않는 쉘 사용으로 인하여 조치가 불가합니다."
        ;;
esac


# 3. 조치 전 PATH 확인 (증거 수집)
BEFORE_PATH=$(su - root -c "echo \$PATH" 2>/dev/null)
EVIDENCE="조치 전 root PATH: $BEFORE_PATH"

MODIFIED_FILES=()
MODIFIED_COUNT=0

# 4. 실제 조치 프로세스
for TARGET_FILE in "${TARGET_FILES[@]}"; do
    [ ! -f "$TARGET_FILE" ] && continue

    PATH_LINES=$(grep -E '^[[:space:]]*(export[[:space:]]+)?PATH=' "$TARGET_FILE" \
                 | grep -v '^[[:space:]]*#')

    [ -z "$PATH_LINES" ] && continue

    # '.'이 앞이나 중간에 존재하는 경우만 취약
    if echo "$PATH_LINES" | grep -qE '(^|:)\.(\:|$)'; then
        BACKUP_FILE="${TARGET_FILE}_bak_$(date +%Y%m%d_%H%M%S)"
        cp -p "$TARGET_FILE" "$BACKUP_FILE"

        # '.' 제거 후 맨 뒤로 이동
        sed -i -E '
            /^[[:space:]]*(export[[:space:]]+)?PATH=/{
                s#(^|:)\.(\:|$)#\1\2#g
                s#PATH=(.*)#PATH=\1:.#
            }
        ' "$TARGET_FILE"

        MODIFIED_FILES+=("$TARGET_FILE")
        MODIFIED_COUNT=$((MODIFIED_COUNT + 1))
    fi
done


# 5. 조치 후 PATH 재확인 (검증 단계)
AFTER_PATH=$(su - root -c "
    for f in ${TARGET_FILES[*]}; do
        [ -f \"\$f\" ] && . \"\$f\"
    done
    echo \$PATH
" 2>/dev/null)


# 6. 최종 판단
if echo "$AFTER_PATH" | grep -qE '(^|:)\.(\:|$)'; then
    # 여전히 취약
    ACTION_RESULT="PARTIAL_SUCCESS"
    STATUS="FAIL"
    ACTION_LOG="조치를 수행했으나 PATH 내 '.'이 여전히 앞 또는 중간에 존재합니다. 수동 확인이 필요합니다."
    EVIDENCE+="→ 조치 후 PATH: $AFTER_PATH 로 여전히 취약합니다."
    GUIDE="관리자가 직접 root 계정의 환경설정 파일(/.profile, /.bashrc 등)과 시스템 환경설정 파일(/etc/profile 등)에 설정된 PATH 환경변수에서 현재 디렉터리를 나타내는 '.'을 PATH 환경변수의 마지막으로 이동하도록 설정하십시오."
else
    ACTION_RESULT="SUCCESS"
    STATUS="PASS"
    
    if [ "$MODIFIED_COUNT" -gt 0 ]; then
        ACTION_LOG="PATH 내 '.' 위치 조정을 완료하였습니다. 조치 파일 ${MODIFIED_COUNT}개 (${MODIFIED_FILES[*]})"
    else
        ACTION_LOG="취약한 설정이 없습니다. PATH가 이미 안전한 상태였습니다."
    fi

    EVIDENCE+="→ 조치 후 PATH: $AFTER_PATH 로 양호합니다."
    GUIDE="KISA 가이드라인에 따른 보안 설정이 완료되었습니다."
fi


# 7. JSON 표준 출력
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
    "action_log": "$ACTION_LOG",
    "action_date": "$ACTION_DATE",
    "check_date": "$CHECK_DATE"
}
EOF
