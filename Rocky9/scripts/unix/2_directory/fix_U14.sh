#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 권순형
# @Last Updated: 2026-02-05
# ============================================================================
# [조치 항목 상세]
# @Check_ID    : U-14
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Debian
# @Importance  : 상
# @Title       : root 홈, 패스 디렉터리 권한 및 패스 설정
# @Description : PATH 환경변수 내 '.'을 마지막 위치로 이동
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-14"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
BEFORE_SETTING="N/A"
AFTER_SETTING="N/A"

# 1. root 로그인 쉘 확인
ROOT_SHELL=$(getent passwd root | cut -d: -f7)
SHELL_NAME=$(basename "$ROOT_SHELL")

# 2. 쉘 종류별 점검 대상 파일
TARGET_FILES=()

case "$SHELL_NAME" in
    sh)
        TARGET_FILES=(
            "/etc/profile"
            "/root/.profile"
        )
        ;;
    csh)
        TARGET_FILES=(
            "/etc/csh.cshrc"
            "/etc/csh.login"
            "/root/.cshrc"
            "/root/.login"
        )
        ;;
    ksh)
        TARGET_FILES=(
            "/etc/profile"
            "/root/.profile"
            "/root/.kshrc"
        )
        ;;
    bash)
        TARGET_FILES=(
            "/etc/profile"
            "/etc/bash.bashrc"
            "/root/.bash_profile"
            "/root/.bashrc"
        )
        ;;
    *)
        ACTION_RESULT="FAIL"
        ACTION_LOG="지원하지 않는 쉘 유형: $SHELL_NAME"
        ;;
esac

# 3. 조치 전 root PATH
BEFORE_SETTING=$(su - root -c "echo \$PATH" 2>/dev/null)

MODIFIED_COUNT=0
MODIFIED_FILES=()

# 4. 파일별 조건부 조치
for TARGET_FILE in "${TARGET_FILES[@]}"; do
    [ ! -f "$TARGET_FILE" ] && continue

    # 주석 제외 PATH 정의 라인
    PATH_LINES=$(grep -E '^[[:space:]]*(export[[:space:]]+)?PATH=' "$TARGET_FILE" \
                 | grep -v '^[[:space:]]*#')

    # PATH 정의 없으면 스킵
    [ -z "$PATH_LINES" ] && continue

    # '.'이 앞이나 중간에 있는 경우만 조치
    if echo "$PATH_LINES" | grep -qE '(^|:)\.(\:|$)'; then
        # 백업
        BACKUP_FILE="${TARGET_FILE}_bak_$(date +%Y%m%d_%H%M%S)"
        cp "$TARGET_FILE" "$BACKUP_FILE"

        # PATH에서 '.' 제거 후 맨 뒤에 추가
        sed -i -E '
            /^[[:space:]]*(export[[:space:]]+)?PATH=/{
                s#(^|:)\.(\:|$)#\1\2#g
                s#PATH=(.*)#PATH=\1:.#
            }
        ' "$TARGET_FILE"

        MODIFIED_COUNT=$((MODIFIED_COUNT + 1))
        MODIFIED_FILES+=("$TARGET_FILE")
    fi
done

# 5. 조치 후 root PATH 재확인
AFTER_SETTING=$(su - root -c "
    for f in ${TARGET_FILES[*]}; do
        [ -f \"\$f\" ] && . \"\$f\"
    done
    echo \$PATH
" 2>/dev/null)

# 6. 결과 판단
if [ "$MODIFIED_COUNT" -gt 0 ]; then
    ACTION_RESULT="SUCCESS"
    ACTION_LOG="PATH 내 '.' 위치 조정 파일 ${MODIFIED_COUNT}개 조치 완료 (${MODIFIED_FILES[*]})"
else
    ACTION_RESULT="SUCCESS"
    ACTION_LOG="조치 대상 없음 ('.'이 이미 마지막이거나 PATH 정의 없음)"
fi

# 7. JSON 출력
echo ""
cat << EOF
{
    "check_id": "$ID",
    "action_result": "$ACTION_RESULT",
    "before_setting": "$BEFORE_SETTING",
    "after_setting": "$AFTER_SETTING",
    "action_log": "$ACTION_LOG",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
