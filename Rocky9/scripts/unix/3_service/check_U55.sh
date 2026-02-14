#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-14
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-55
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 중 
# @Title : FTP 계정 shell 제한
# @Description : FTP 기본 계정에 쉘 설정 여부 점검
# @Criteria_Good : FTP 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정
# @Criteria_Bad : FTP 서비스 사용 시 FTP 계정에 /bin/false 쉘 부여 설정
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-55 FTP 계정 shell 제한

# 기본 변수
ID="U-55"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

PASSWD_FILE="/etc/passwd"
TARGET_FILE="$PASSWD_FILE"
CHECK_COMMAND='[ -f /etc/passwd ] && grep -nE "^ftp:" /etc/passwd || echo "ftp_account_not_found"'

REASON_LINE=""
DETAIL_CONTENT=""

VULNERABLE=0
FTP_LINE=""
FTP_SHELL=""
SHELL_OK=0

# 파일 존재 여부
if [ ! -f "$PASSWD_FILE" ]; then
  STATUS="FAIL"
  REASON_LINE="/etc/passwd 파일이 존재하지 않아 계정 정보 확인 및 접근 통제가 보장되지 않으므로 취약합니다. /etc/passwd 파일을 복구한 뒤 ftp 계정의 로그인 쉘 제한 여부를 점검해야 합니다."
  DETAIL_CONTENT="file_not_found"
else
  # ftp 계정 라인 수집(첫 1개만)
  FTP_LINE="$(grep -nE '^ftp:' "$PASSWD_FILE" 2>/dev/null | head -n1)"

  if [ -z "$FTP_LINE" ]; then
    STATUS="PASS"
    REASON_LINE="ftp 계정이 존재하지 않아 이 항목에 대한 보안 위협이 없습니다."
    DETAIL_CONTENT="ftp_account=not_found"
  else
    # 7번째 필드(로그인 쉘) 추출
    # 라인 형식: lineNo:ftp:x:...
    FTP_SHELL="$(echo "$FTP_LINE" | cut -d: -f8 2>/dev/null)"

    case "$FTP_SHELL" in
      "/bin/false"|"/sbin/nologin"|"/usr/sbin/nologin")
        SHELL_OK=1
        ;;
      *)
        SHELL_OK=0
        ;;
    esac

    if [ "$SHELL_OK" -eq 1 ]; then
      STATUS="PASS"
      REASON_LINE="ftp 계정의 로그인 쉘이 제한되어 있어 이 항목에 대한 보안 위협이 없습니다."
    else
      STATUS="FAIL"
      VULNERABLE=1
      REASON_LINE="ftp 계정의 로그인 쉘이 제한되지 않아 불필요한 로그인 접근이 가능하므로 취약합니다. ftp 계정의 쉘을 /sbin/nologin 또는 /bin/false 등 로그인 불가 쉘로 설정해야 합니다."
    fi

    DETAIL_CONTENT="ftp_entry=$FTP_LINE (ftp_shell=$FTP_SHELL shell_ok=$SHELL_OK)"
  fi
fi

# raw_evidence 구성 (첫 줄: 평가 이유 / 다음 줄: 현재 설정값)
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

# JSON 저장을 위한 escape 처리 (따옴표, 줄바꿈)
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