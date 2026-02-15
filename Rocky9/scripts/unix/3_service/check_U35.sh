#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 이가영
# @Last Updated: 2026-02-06
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-35
# @Category : 서비스 관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : 공유 서비스에 대한 익명 접근 제한 설정
# @Description : 공유 서비스의 익명 접근 제한 설정 여부 점검
# @Criteria_Good : 공유 서비스에 대해 익명 접근을 제한한 경우
# @Criteria_Bad : 공유 서비스에 대해 익명 접근을 허용한 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# [진단] U-35 공유 서비스에 대한 익명 접근 제한 설정

# 기본 변수
ID="U-35"
STATUS="PASS"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/passwd /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf /etc/proftpd.conf /etc/proftpd/proftpd.conf /etc/exports /etc/samba/smb.conf"
CHECK_COMMAND='( [ -f /etc/passwd ] && (grep -nE "^ftp:" /etc/passwd; grep -nE "^anonymous:" /etc/passwd) || echo "passwd_not_found" ); ( for f in /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf; do [ -f "$f" ] && grep -nEv "^[[:space:]]*#" "$f" | grep -niE "^[[:space:]]*anonymous_enable[[:space:]]*=[[:space:]]*YES([[:space:]]|$)"; done ) ; ( for f in /etc/proftpd.conf /etc/proftpd/proftpd.conf; do [ -f "$f" ] && ( sed -n "/<Anonymous/,/<\\/Anonymous>/p" "$f" 2>/dev/null | grep -nEv "^[[:space:]]*#" ; grep -nEv "^[[:space:]]*#" "$f" 2>/dev/null | grep -niE "^[[:space:]]*(User|UserAlias)[[:space:]]+" ); done ); ( [ -f /etc/exports ] && grep -nEv "^[[:space:]]*#" /etc/exports | grep -nE "(anonuid|anongid)" || echo "exports_not_found_or_no_anon" ); ( [ -f /etc/samba/smb.conf ] && grep -nEv "^[[:space:]]*#" /etc/samba/smb.conf | grep -niE "guest[[:space:]]*ok[[:space:]]*=[[:space:]]*yes([[:space:]]|$)" || echo "smb_conf_not_found_or_no_guest_ok_yes" )'

REASON_LINE=""
DETAIL_CONTENT=""

SERVICE_EXISTS=0
VULNERABLE=0

DETAIL_LINES=""

# /etc/passwd 계정 기반(기본 FTP/anonymous 계정 존재 여부)
if [ -f /etc/passwd ]; then
    FTP_ACC=$(grep -nE "^ftp:" /etc/passwd 2>/dev/null | head -n 1)
    ANON_ACC=$(grep -nE "^anonymous:" /etc/passwd 2>/dev/null | head -n 1)

    if [ -n "$FTP_ACC" ]; then
        SERVICE_EXISTS=1
        VULNERABLE=1
        DETAIL_LINES+="/etc/passwd: ftp 계정이 존재하여 익명/공유 서비스 접근이 허용될 수 있습니다. (${FTP_ACC})"$'\n'
    else
        DETAIL_LINES+="/etc/passwd: ftp 계정 미존재."$'\n'
    fi

    if [ -n "$ANON_ACC" ]; then
        SERVICE_EXISTS=1
        VULNERABLE=1
        DETAIL_LINES+="/etc/passwd: anonymous 계정이 존재하여 익명 접근이 허용될 수 있습니다. (${ANON_ACC})"$'\n'
    else
        DETAIL_LINES+="/etc/passwd: anonymous 계정 미존재."$'\n'
    fi
else
    DETAIL_LINES+="/etc/passwd: 파일이 존재하지 않습니다."$'\n'
fi

# vsftpd 설정(anonymous_enable=YES 여부)
VSFTPD_CONF=""
if [ -f "/etc/vsftpd.conf" ]; then
    VSFTPD_CONF="/etc/vsftpd.conf"
elif [ -f "/etc/vsftpd/vsftpd.conf" ]; then
    VSFTPD_CONF="/etc/vsftpd/vsftpd.conf"
fi

if [ -n "$VSFTPD_CONF" ]; then
    SERVICE_EXISTS=1
    VS_ANON_LINE=$(grep -nEv "^[[:space:]]*#" "$VSFTPD_CONF" 2>/dev/null | grep -niE "^[[:space:]]*anonymous_enable[[:space:]]*=" | tail -n 1)
    if echo "$VS_ANON_LINE" | grep -qiE "=[[:space:]]*YES([[:space:]]|$)"; then
        VULNERABLE=1
        DETAIL_LINES+="${VSFTPD_CONF}: anonymous_enable=YES 로 설정되어 익명 FTP가 허용됩니다. (${VS_ANON_LINE})"$'\n'
    else
        if [ -n "$VS_ANON_LINE" ]; then
            DETAIL_LINES+="${VSFTPD_CONF}: ${VS_ANON_LINE} (anonymous_enable=YES 미확인)."$'\n'
        else
            DETAIL_LINES+="${VSFTPD_CONF}: anonymous_enable 설정 라인 미확인(기본값/미설정 가능)."$'\n'
        fi
    fi
else
    DETAIL_LINES+="vsftpd: 설정 파일 미존재(/etc/vsftpd.conf, /etc/vsftpd/vsftpd.conf)."$'\n'
fi

# proftpd 설정(<Anonymous> 블록 / User,UserAlias 활성 여부)
PROFTPD_CONF=""
if [ -f "/etc/proftpd.conf" ]; then
    PROFTPD_CONF="/etc/proftpd.conf"
elif [ -f "/etc/proftpd/proftpd.conf" ]; then
    PROFTPD_CONF="/etc/proftpd/proftpd.conf"
fi

if [ -n "$PROFTPD_CONF" ]; then
    SERVICE_EXISTS=1

    # 1) 주석 제외 후 <Anonymous> 블록 내용이 있으면 활성으로 판단
    ANON_BLOCK=$(sed -n '/<Anonymous/,/<\/Anonymous>/p' "$PROFTPD_CONF" 2>/dev/null | grep -Ev '^[[:space:]]*#' | sed '/^[[:space:]]*$/d')
    if [ -n "$ANON_BLOCK" ]; then
        VULNERABLE=1
        ANON_SAMPLE=$(printf "%s\n" "$ANON_BLOCK" | head -n 10)
        DETAIL_LINES+="${PROFTPD_CONF}: <Anonymous> 블록이 활성화되어 익명 접근이 허용될 수 있습니다."$'\n'
        DETAIL_LINES+="${ANON_SAMPLE}"$'\n'
    else
        DETAIL_LINES+="${PROFTPD_CONF}: <Anonymous> 블록 활성 내용 미확인(없음 또는 주석 처리됨)."$'\n'
    fi

    # 2) (가이드 반영) User / UserAlias 옵션이 주석이 아닌 상태로 존재하면 익명 접근 활성로 간주
    PROFTPD_USER_ALIAS=$(grep -nEv '^[[:space:]]*#' "$PROFTPD_CONF" 2>/dev/null | grep -niE '^[[:space:]]*(User|UserAlias)[[:space:]]+' | head -n 5)
    if [ -n "$PROFTPD_USER_ALIAS" ]; then
        VULNERABLE=1
        DETAIL_LINES+="${PROFTPD_CONF}: User/UserAlias 옵션이 활성화되어 익명 접근이 허용될 수 있습니다."$'\n'
        DETAIL_LINES+="${PROFTPD_USER_ALIAS}"$'\n'
    else
        DETAIL_LINES+="${PROFTPD_CONF}: User/UserAlias 활성 설정 미확인."$'\n'
    fi
else
    DETAIL_LINES+="proftpd: 설정 파일 미존재(/etc/proftpd.conf, /etc/proftpd/proftpd.conf)."$'\n'
fi

# NFS exports(anonuid/anongid 여부)
if [ -f "/etc/exports" ]; then
    SERVICE_EXISTS=1
    NFS_ANON=$(grep -nEv "^[[:space:]]*#" /etc/exports 2>/dev/null | grep -nE "(anonuid|anongid)" | head -n 5)
    if [ -n "$NFS_ANON" ]; then
        VULNERABLE=1
        DETAIL_LINES+="/etc/exports: anonuid/anongid 설정이 있어 익명 매핑 기반 접근이 허용됩니다."$'\n'
        DETAIL_LINES+="${NFS_ANON}"$'\n'
    else
        DETAIL_LINES+="/etc/exports: anonuid/anongid 설정 미확인."$'\n'
    fi
else
    DETAIL_LINES+="NFS: /etc/exports 파일이 존재하지 않습니다."$'\n'
fi

# Samba guest ok = yes 여부
if [ -f "/etc/samba/smb.conf" ]; then
    SERVICE_EXISTS=1
    SMB_GUEST=$(grep -nEv "^[[:space:]]*#" /etc/samba/smb.conf 2>/dev/null | grep -niE "guest[[:space:]]*ok[[:space:]]*=" | tail -n 1)
    if echo "$SMB_GUEST" | grep -qiE "=[[:space:]]*yes([[:space:]]|$)"; then
        VULNERABLE=1
        DETAIL_LINES+="/etc/samba/smb.conf: guest ok = yes 로 설정되어 익명(게스트) 접근이 허용됩니다. (${SMB_GUEST})"$'\n'
    else
        if [ -n "$SMB_GUEST" ]; then
            DETAIL_LINES+="/etc/samba/smb.conf: ${SMB_GUEST} (guest ok=yes 미확인)."$'\n'
        else
            DETAIL_LINES+="/etc/samba/smb.conf: guest ok 설정 라인 미확인."$'\n'
        fi
    fi
else
    DETAIL_LINES+="Samba: /etc/samba/smb.conf 파일이 존재하지 않습니다."$'\n'
fi

# detail(줄바꿈 유지)
DETAIL_CONTENT="$(printf "%s" "$DETAIL_LINES" | sed 's/[[:space:]]*$//')"

# 최종 판정 + raw_evidence 문구(요구사항 반영)
if [ "$SERVICE_EXISTS" -eq 0 ]; then
    STATUS="PASS"
    REASON_LINE="FTP/NFS/Samba 관련 설정 파일이 확인되지 않아 익명 접근이 구성되어 있을 가능성이 낮으므로 이 항목에 대한 보안 위협이 없습니다."
elif [ "$VULNERABLE" -eq 1 ]; then
    STATUS="FAIL"
    REASON_LINE="공유 서비스 설정에서 익명 접근이 허용되는 설정이 확인되어 취약합니다. 조치: FTP는 ftp/anonymous 계정 제거 및 vsftpd는 anonymous_enable=NO로 설정하고 재시작, ProFTPd는 <Anonymous> 블록 및 User/UserAlias 익명 관련 설정을 비활성화, NFS는 exports에서 anonuid/anongid 제거, Samba는 guest ok = no로 변경 후 설정을 재적용하십시오."
else
    STATUS="PASS"
    REASON_LINE="공유 서비스 설정에서 익명 접근 허용 설정이 확인되지 않아 이 항목에 대한 보안 위협이 없습니다."
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