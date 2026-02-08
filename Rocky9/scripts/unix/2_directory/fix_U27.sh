#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 권순형
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-27
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Debian
# @Importance  : 상
# @Title       : $HOME/.rhosts, hosts.equiv 사용 금지
# @Description : $HOME/.rhosts 및 /etc/hosts.equiv 파일에 대해 적절한 소유자 및 접근 권한 설정
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-27"
TARGET_FILE="/etc/hosts.equiv, \$HOME/.rhosts"
ACTION_RESULT="SUCCESS"
ACTION_LOG=""
BEFORE_SETTING=""
AFTER_SETTING=""

ACTION_DATE=$(date '+%Y-%m-%d %H:%M:%S')

FILES=("/etc/hosts.equiv")
RHOSTS_FILES=$(find /home -name ".rhosts" 2>/dev/null)

for file in "${FILES[@]}" $RHOSTS_FILES; do
    if [ -f "$file" ]; then
        BEFORE_SETTING+="[$file] owner=$(stat -c %U "$file"), perm=$(stat -c %a "$file"), plus=$(grep -E '^\s*\+' "$file" >/dev/null && echo yes || echo no),"

        # 소유자 설정
        if [ "$file" = "/etc/hosts.equiv" ]; then
            chown root "$file"
        else
            FILE_USER=$(basename "$(dirname "$file")")
            chown "$FILE_USER" "$file"
        fi

        # 권한 설정
        chmod 600 "$file"

        # "+" 설정 제거
        sed -i '/^\s*\+/d' "$file"

        AFTER_SETTING+="[$file] owner=$(stat -c %U "$file"), perm=$(stat -c %a "$file"), plus=$(grep -E '^\s*\+' "$file" >/dev/null && echo yes || echo no),"
        ACTION_LOG+="$file 조치 완료,"
    fi
done

# 결과 정리
if [ -z "$ACTION_LOG" ]; then
    ACTION_RESULT="NO_ACTION"
    ACTION_LOG="조치 대상 파일 없음"
    BEFORE_SETTING="해당 파일 없음"
    AFTER_SETTING="해당 파일 없음"
else
    BEFORE_SETTING=${BEFORE_SETTING%,}
    AFTER_SETTING=${AFTER_SETTING%,}
    ACTION_LOG=${ACTION_LOG%,}
fi

echo ""

cat <<EOF
{
  "check_id": "$ID",
  "action_result": "$ACTION_RESULT",
  "before_setting": "$BEFORE_SETTING",
  "after_setting": "$AFTER_SETTING",
  "action_log": "$ACTION_LOG",
  "action_date": "$ACTION_DATE"
}
EOF