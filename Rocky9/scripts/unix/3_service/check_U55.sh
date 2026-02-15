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

set -u

# 기본 변수
ID="U-55"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

PASSWD_FILE="/etc/passwd"
TARGET_FILE="$PASSWD_FILE"
CHECK_COMMAND="awk -F: '\$1==\"ftp\"{print NR\"|\"\$7\"|\"\$0; exit}' $PASSWD_FILE"

REASON_LINE=""
DETAIL_CONTENT=""

FTP_REC=""
FTP_LINENO=""
FTP_SHELL=""
FTP_ENTRY=""

json_escape() {
  # 따옴표/역슬래시/줄바꿈 escape
  echo -n "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; :a;N;$!ba;s/\n/\\n/g'
}

# 1) /etc/passwd 존재 확인
if [ ! -f "$PASSWD_FILE" ]; then
  STATUS="FAIL"
  REASON_LINE="/etc/passwd 파일이 존재하지 않아 계정 확인이 불가하므로 취약합니다. /etc/passwd를 복구한 뒤 ftp 계정의 로그인 쉘 제한 여부를 점검해야 합니다."
  DETAIL_CONTENT="file_not_found"
else
  # 2) ftp 계정 1건 확인 (lineNo|shell|full_entry)
  FTP_REC="$(awk -F: '$1=="ftp"{print NR"|" $7 "|" $0; exit}' "$PASSWD_FILE" 2>/dev/null)"

  if [ -z "$FTP_REC" ]; then
    STATUS="PASS"
    REASON_LINE="/etc/passwd에 ftp 기본 계정이 존재하지 않아 이 항목에 대한 보안 위협이 없습니다."
    DETAIL_CONTENT="ftp_account=not_found"
  else
    IFS='|' read -r FTP_LINENO FTP_SHELL FTP_ENTRY <<< "$FTP_REC"

    case "$FTP_SHELL" in
      "/bin/false"|"/sbin/nologin"|"/usr/sbin/nologin")
        STATUS="PASS"
        REASON_LINE="/etc/passwd의 ftp 계정 로그인 쉘이 '$FTP_SHELL'(으)로 설정되어 있어 이 항목에 대한 보안 위협이 없습니다."
        ;;
      *)
        STATUS="FAIL"
        REASON_LINE="/etc/passwd의 ftp 계정 로그인 쉘이 '$FTP_SHELL'(으)로 설정되어 있어 취약합니다. 조치: usermod -s /sbin/nologin ftp (또는 /bin/false)로 로그인 쉘을 제한하세요."
        ;;
    esac

    DETAIL_CONTENT="ftp_entry(line=$FTP_LINENO)=$FTP_ENTRY"
  fi
fi

# raw_evidence 구성 (첫 줄: 평가 이유 / 다음 줄: 현재 설정값)
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE
$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

RAW_EVIDENCE_ESCAPED="$(json_escape "$RAW_EVIDENCE")"

# scan_history 저장용 JSON 출력
echo ""
cat <<EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF