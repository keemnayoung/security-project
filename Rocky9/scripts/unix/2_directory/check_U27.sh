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
# @Description : $HOME/.rhosts 및 /etc/hosts.equiv 파일에 대해 적절한 소유자 및 접근 권한 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

CHECK_ID="U-27"
CATEGORY="파일 및 디렉토리 관리"
TITLE="\$HOME/.rhosts, hosts.equiv 사용 금지"
IMPORTANCE="상"
STATUS="PASS"
EVIDENCE=""

CHECK_DATE=$(date '+%Y-%m-%d %H:%M:%S')

TARGET_FILES=("/etc/hosts.equiv")

# rlogin/rsh/rexec 서비스 사용 여부 확인
SERVICE_USED=$(ps -ef | grep -E 'rlogin|rsh|rexec' | grep -v grep)

# 홈 디렉터리 내 .rhosts 파일 수집
RHOSTS_FILES=$(find /home -name ".rhosts" 2>/dev/null)

if [ -z "$SERVICE_USED" ]; then
    EVIDENCE="rlogin, rsh, rexec 서비스 미사용"
else
    for file in "${TARGET_FILES[@]}" $RHOSTS_FILES; do
        if [ -f "$file" ]; then
            OWNER=$(stat -c %U "$file")
            PERM=$(stat -c %a "$file")
            PLUS_EXIST=$(grep -E '^\s*\+' "$file" 2>/dev/null)

            # /etc/hosts.equiv 소유자 점검
            if [[ "$file" == "/etc/hosts.equiv" && "$OWNER" != "root" ]]; then
                STATUS="FAIL"
                EVIDENCE+="[$file] 소유자가 root가 아님 (현재: $OWNER)\n"
            fi

            # .rhosts 소유자 점검
            if [[ "$file" != "/etc/hosts.equiv" ]]; then
                FILE_USER=$(basename "$(dirname "$file")")
                if [[ "$OWNER" != "$FILE_USER" && "$OWNER" != "root" ]]; then
                    STATUS="FAIL"
                    EVIDENCE+="[$file] 소유자가 계정 또는 root가 아님 (현재: $OWNER)\n"
                fi
            fi

            # 권한 점검
            if [ "$PERM" -gt 600 ]; then
                STATUS="FAIL"
                EVIDENCE+="[$file] 권한이 600 초과 (현재: $PERM)\n"
            fi

            # "+" 설정 점검
            if [ -n "$PLUS_EXIST" ]; then
                STATUS="FAIL"
                EVIDENCE+="[$file] '+' 설정 존재\n"
            fi
        fi
    done
fi

if [ -z "$EVIDENCE" ]; then
    EVIDENCE="모든 점검 기준 충족"
fi

# 3. 마스터 JSON 출력
echo ""
cat <<EOF
{
  "check_id": "$CHECK_ID",
  "category": "$CATEGORY",
  "title": "$TITLE",
  "importance": "$IMPORTANCE",
  "status": "$STATUS",
  "evidence": "$(echo -e "$EVIDENCE" | sed 's/"/\\"/g')",
  "target_file": "$TARGET_FILE",
  "check_date": "$CHECK_DATE"
}
EOF