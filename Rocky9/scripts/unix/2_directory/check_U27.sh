#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.1
# @Author: 권순형
# @Last Updated: 2026-02-09
# ============================================================================
# [점검 항목 상세]
# @Check_ID    : U-27
# @Category    : 파일 및 디렉토리 관리
# @Platform    : Rocky Linux
# @Importance  : 상
# @Title       : $HOME/.rhosts, hosts.equiv 사용 금지
# @Description : $HOME/.rhosts 및 /etc/hosts.equiv 파일에 대해 적절한 소유자 및 접근 권한 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="U-27"
CATEGORY="파일 및 디렉토리 관리"
TITLE="\$HOME/.rhosts, hosts.equiv 사용 금지"
IMPORTANCE="상"
STATUS="PASS"
EVIDENCE=""
IMPACT_LEVEL="LOW" 
ACTION_IMPACT="이 조치를 적용하더라도 일반적인 시스템 운영에는 영향이 없으나, 해당 방식에 의존하던 레거시 자동화 작업이나 원격 관리 기능은 더 이상 동작하지 않을 수 있습니다."
GUIDE="/etc/hosts.equiv, \$HOME/.rhosts 파일 소유자를 root 또는 해당 계정으로 변경해주시고 권한도 600 이하로 변경해주세요. 각 파일에 허용 호스트 및 계정을 등록해주세요."
TARGET_FILE="/etc/hosts.equiv"
FILE_HASH="N/A"
CHECK_DATE=$(date '+%Y-%m-%d %H:%M:%S')

VUL_OWNER_LIST=()
VUL_PERM_LIST=()
VUL_PLUS_LIST=()

# rlogin/rsh/rexec 서비스 사용 여부 확인
SERVICE_USED=$(ps -ef | grep -E 'rlogin|rsh|rexec' | grep -v grep)

# 홈 디렉터리 내 .rhosts 파일 수집
RHOSTS_FILES=$(find /home -name ".rhosts" 2>/dev/null)

if [ -z "$SERVICE_USED" ]; then
    EVIDENCE="rlogin, rsh, rexec 서비스 미사용"
else
    for file in $TARGET_FILE $RHOSTS_FILES; do
        if [ -f "$file" ]; then
            OWNER=$(stat -c %U "$file")
            PERM=$(stat -c %a "$file")
            PLUS_EXIST=$(grep -E '^[[:space:]]*\+' "$file" 2>/dev/null)

            # /etc/hosts.equiv 소유자 점검
            if [[ "$file" == "/etc/hosts.equiv" && "$OWNER" != "root" ]]; then
                STATUS="FAIL"
                VUL_OWNER_LIST+=("$file (owner=$OWNER); ")
            fi

            # .rhosts 소유자 점검
            if [[ "$file" != "/etc/hosts.equiv" ]]; then
                FILE_USER=$(basename "$(dirname "$file")")
                if [[ "$OWNER" != "$FILE_USER" && "$OWNER" != "root" ]]; then
                    STATUS="FAIL"
                    VUL_OWNER_LIST+=("$file (owner=$OWNER); ")
                fi
            fi

            # 권한 점검
            if [ "$PERM" -gt 600 ]; then
                STATUS="FAIL"
                VUL_PERM_LIST+=("$file (perm=$PERM); ")
            fi

            # "+" 설정 점검
            if [ -n "$PLUS_EXIST" ]; then
                STATUS="FAIL"
                VUL_PLUS_LIST+=("$file; ")
            fi
        fi
    done
fi

# 3. EVIDENCE 구성
if [ "$STATUS" = "FAIL" ]; then
  EVIDENCE="/etc/hosts.equiv에 부적절한 설정이 존재합니다. 다음 점검된 내용을 참고하여 소유자 또는 권한 또는 파일 내용을 재설정해주십시오. "
  if [ "${#VUL_OWNER_LIST[@]}" -gt 0 ]; then
    EVIDENCE+="[소유자 점검] ${VUL_OWNER_LIST[*]}"
  fi

  if [ "${#VUL_PERM_LIST[@]}" -gt 0 ]; then
    [ -n "$EVIDENCE" ] && EVIDENCE+=", "
    EVIDENCE+="[권한 점검] ${VUL_PERM_LIST[*]}"
  fi

  if [ "${#VUL_PLUS_LIST[@]}" -gt 0 ]; then
    [ -n "$EVIDENCE" ] && EVIDENCE+=", "
    EVIDENCE+="['+' 설정 점검] ${VUL_PLUS_LIST[*]}"
  fi
else
  STATUS="PASS"
  EVIDENCE+="사용자, 시스템 환경변수 파일 소유자 또는 권한 설정이 적절하게 설정되어 있어 이 항목에서 보안 위협이 없습니다."
  GUIDE="KISA 보안 가이드라인을 준수하고 있습니다."
fi

# 3. 마스터 템플릿 표준 출력
echo ""
cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$(echo -e "$EVIDENCE" | sed 's/"/\\"/g')",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "guide": "$GUIDE",
    "target_file": "/etc/hosts.equiv",
    "file_hash": "$FILE_HASH",
    "check_date": "$CHECK_DATE"
}
EOF