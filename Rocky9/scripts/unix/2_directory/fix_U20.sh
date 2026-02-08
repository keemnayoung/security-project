#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 권순형
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-20
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Debian
# @Importance  : 상
# @Title       : /etc/(x)inetd.conf 파일 소유자 및 권한 설정
# @Description : /etc/(x)inetd.conf 파일의 소유자가 root이고, 권한이 600 이하로 설정
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-20"
TARGET_FILE="/etc/inetd.conf /etc/xinetd.conf /etc/systemd/system.conf /etc/systemd/*"
ACTION_RESULT="SUCCESS"
ACTION_LOG=""
BEFORE_SETTING=""
AFTER_SETTING=""
ACTION_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

# 2. 조치 로직
fix_file() {
    local FILE="$1"

    if [ ! -e "$FILE" ]; then
        ACTION_LOG+="[INFO] $FILE 파일이 존재하지 않음\n"
        return
    fi

    BEFORE_SETTING+="[BEFORE] $FILE ($(stat -c 'OWNER=%U PERM=%a' "$FILE"))\n"

    chown root "$FILE" 2>/dev/null
    chmod 600 "$FILE" 2>/dev/null

    AFTER_SETTING+="[AFTER]  $FILE ($(stat -c 'OWNER=%U PERM=%a' "$FILE"))\n"
}

fix_directory_files() {
    local DIR="$1"

    if [ ! -d "$DIR" ]; then
        ACTION_LOG+="[INFO] $DIR 디렉터리가 존재하지 않음\n"
        return
    fi

    while IFS= read -r FILE; do
        BEFORE_SETTING+="[BEFORE] $FILE ($(stat -c 'OWNER=%U PERM=%a' "$FILE"))\n"

        chown root "$FILE" 2>/dev/null
        chmod 600 "$FILE" 2>/dev/null

        AFTER_SETTING+="[AFTER]  $FILE ($(stat -c 'OWNER=%U PERM=%a' "$FILE"))\n"
    done < <(find "$DIR" -type f 2>/dev/null)
}

# inetd / xinetd 설정 파일 조치
fix_file "/etc/inetd.conf"
fix_file "/etc/xinetd.conf"

# systemd 설정 파일 및 디렉터리 조치
fix_file "/etc/systemd/system.conf"
fix_directory_files "/etc/systemd"


# 3. 조치 결과 JSON 출력
echo ""
cat <<EOF
{
  "check_id": "$ID",
  "action_result": "$ACTION_RESULT",
  "before_setting": "$(echo -e "$BEFORE_SETTING" | sed ':a;N;$!ba;s/\n/\\n/g')",
  "after_setting": "$(echo -e "$AFTER_SETTING" | sed ':a;N;$!ba;s/\n/\\n/g')",
  "action_log": "$(echo -e "$ACTION_LOG" | sed ':a;N;$!ba;s/\n/\\n/g')",
  "action_date": "$ACTION_DATE"
}
EOF