#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 김나영
# @Last Updated: 2026-02-09
# ============================================================================
# [점검 항목 상세]
# @Check_ID : U-01
# @Category : 계정관리
# @Platform : Rocky Linux
# @Importance : 상
# @Title : root 계정 원격 접속 제한
# @Description : 원격 터미널 서비스를 통한 root 계정의 직접 접속 제한 여부 점검
# @Criteria_Good : 원격 접속 시 root 계정 접속을 제한한 경우
# @Criteria_Bad : 원격 접속 시 root 계정 접속을 허용한 경우
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# 기본 변수
ID="U-01"
STATUS="FAIL"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

# 점검 대상 파일
TARGET_SSHD="/etc/ssh/sshd_config"
TARGET_PAM_LOGIN="/etc/pam.d/login"
TARGET_SECURETTY="/etc/securetty"
TARGET_FILES="${TARGET_SSHD},${TARGET_PAM_LOGIN},${TARGET_SECURETTY}"

# 점검 명령(설명용) - 따옴표(") 포함하지 않도록 구성
CHECK_COMMAND=$(cat <<'CMD'
[SSH] if /etc/ssh/sshd_config exists -> sshd -T | grep ^permitrootlogin
[Telnet] detect active: ss/netstat port 23 listening OR systemctl telnet.* active OR xinetd telnet(disable=no) OR inetd.conf telnet entry
[Telnet] if active -> /etc/pam.d/login has auth required pam_securetty.so AND /etc/securetty has no pts/x entries
CMD
)

REASON_LINE=""
DETAIL_CONTENT=""

# 1) SSH 점검: PermitRootLogin (실적용값: sshd -T)
SSH_RESULT="PASS"
SSH_VAL="unknown"
SSH_REASON=""

if [ -f "$TARGET_SSHD" ]; then
    if command -v sshd >/dev/null 2>&1; then
        SSH_VAL="$(sshd -T 2>/dev/null | awk 'tolower($1)=="permitrootlogin"{v=tolower($2)} END{print v}')"
    else
        SSH_VAL=""
    fi

    if [ "$SSH_VAL" = "no" ]; then
        SSH_RESULT="PASS"
        SSH_REASON="SSH 설정에서 PermitRootLogin 값이 no로 적용되어 root 계정의 직접 원격 접속이 차단됩니다."
    else
        SSH_RESULT="FAIL"
        if [ -z "$SSH_VAL" ]; then
            SSH_VAL="unknown"
            if ! command -v sshd >/dev/null 2>&1; then
                SSH_REASON="SSH 설정 파일은 존재하나 sshd 명령을 확인할 수 없어 PermitRootLogin 실적용 값을 검증할 수 없으므로 취약합니다. OpenSSH 서버(sshd) 설치/동작 및 설정을 확인하고 PermitRootLogin을 no로 적용해야 합니다."
            else
                SSH_REASON="SSH 설정에서 PermitRootLogin 실적용 값을 확인할 수 없어 root 원격 접속 차단 여부가 보장되지 않으므로 취약합니다. sshd_config 설정과 sshd -T 출력값을 확인하여 PermitRootLogin을 no로 적용해야 합니다."
            fi
        else
            SSH_REASON="SSH 설정에서 PermitRootLogin 값이 ${SSH_VAL} 로 적용되어 root 계정의 직접 원격 접속이 허용될 수 있으므로 취약합니다. sudo 권한을 가진 일반 관리자 계정으로 접속 가능함을 확인한 뒤 PermitRootLogin을 no로 변경해야 합니다."
        fi
    fi
else
    SSH_RESULT="PASS"
    SSH_VAL="sshd_config_not_found"
    SSH_REASON="SSH 서비스 설정 파일(/etc/ssh/sshd_config)이 존재하지 않아 SSH 기반 root 원격 접속 설정이 적용되지 않습니다."
fi

# 2) Telnet/login 점검: (가이드) pam_securetty + /etc/securetty pts/x
#    - 원격터미널 서비스를 사용하지 않으면(비활성) 양호 처리
TELNET_ACTIVE="no"
TELNET_DETECTION="none"

# (1) 포트 23 리스닝 여부 우선 확인
if command -v ss >/dev/null 2>&1; then
    if ss -lnt 2>/dev/null | awk '{print $4}' | grep -Eq '(:|\.)(23)$'; then
        TELNET_ACTIVE="yes"
        TELNET_DETECTION="port23_listening(ss)"
    fi
elif command -v netstat >/dev/null 2>&1; then
    if netstat -lnt 2>/dev/null | awk '{print $4}' | grep -Eq '(:|\.)(23)$'; then
        TELNET_ACTIVE="yes"
        TELNET_DETECTION="port23_listening(netstat)"
    fi
fi

# (2) systemd 유닛 확인 (환경에 따라 존재하지 않을 수 있음)
if [ "$TELNET_ACTIVE" = "no" ] && command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet telnet.socket 2>/dev/null; then
        TELNET_ACTIVE="yes"
        TELNET_DETECTION="systemd:telnet.socket(active)"
    elif systemctl is-active --quiet telnet.service 2>/dev/null; then
        TELNET_ACTIVE="yes"
        TELNET_DETECTION="systemd:telnet.service(active)"
    fi
fi

# (3) xinetd 기반 telnet 설정 확인
if [ "$TELNET_ACTIVE" = "no" ] && [ -f /etc/xinetd.d/telnet ]; then
    TELNET_DISABLE_VAL="$(grep -i '^\s*disable\s*=' /etc/xinetd.d/telnet 2>/dev/null | tail -n 1 | awk -F= '{gsub(/[ \t]/,"",$2); print tolower($2)}')"
    if [ "$TELNET_DISABLE_VAL" = "no" ]; then
        TELNET_ACTIVE="yes"
        if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet xinetd 2>/dev/null; then
            TELNET_DETECTION="xinetd:/etc/xinetd.d/telnet(disable=no), xinetd(active)"
        else
            TELNET_DETECTION="xinetd:/etc/xinetd.d/telnet(disable=no)"
        fi
    fi
fi

# (4) inetd 설정 확인(존재 시)
if [ "$TELNET_ACTIVE" = "no" ] && [ -f /etc/inetd.conf ]; then
    if grep -Ev '^\s*#' /etc/inetd.conf 2>/dev/null | grep -Eq '^\s*telnet\s'; then
        TELNET_ACTIVE="yes"
        TELNET_DETECTION="/etc/inetd.conf:telnet_entry"
    fi
fi

# pam_securetty 적용 여부
PAM_SECURETTY_STATUS="not_checked"
if [ -f "$TARGET_PAM_LOGIN" ]; then
    if grep -Eqi '^\s*auth\s+required\s+.*pam_securetty\.so' "$TARGET_PAM_LOGIN"; then
        PAM_SECURETTY_STATUS="present"
    else
        PAM_SECURETTY_STATUS="absent"
    fi
else
    PAM_SECURETTY_STATUS="pam_login_not_found"
fi

# /etc/securetty pts/x 존재 여부
SECURETTY_PTS_STATUS="not_checked"
SECURETTY_PTS_LIST_CSV="unknown"
if [ -f "$TARGET_SECURETTY" ]; then
    SECURETTY_PTS_LIST="$(grep -Ev '^\s*#' "$TARGET_SECURETTY" 2>/dev/null | awk '{gsub(/[ \t]/,""); print}' | grep -E '^pts/' || true)"
    if [ -n "$SECURETTY_PTS_LIST" ]; then
        SECURETTY_PTS_STATUS="present"
        SECURETTY_PTS_LIST_CSV="$(echo "$SECURETTY_PTS_LIST" | paste -sd, -)"
    else
        SECURETTY_PTS_STATUS="absent"
        SECURETTY_PTS_LIST_CSV="none"
    fi
else
    SECURETTY_PTS_STATUS="securetty_not_found"
    SECURETTY_PTS_LIST_CSV="securetty_not_found"
fi

# Telnet/login 최종 판정
TELNET_RESULT="PASS"
TELNET_REASON=""

if [ "$TELNET_ACTIVE" = "no" ]; then
    TELNET_RESULT="PASS"
    TELNET_REASON="원격터미널(Telnet) 서비스 사용 흔적이 확인되지 않아(비활성) root 계정의 Telnet 기반 직접 접속 위험이 낮습니다."
else
    # Telnet 활성 시에만 가이드 항목 강제 점검
    if [ "$PAM_SECURETTY_STATUS" = "present" ] && [ "$SECURETTY_PTS_STATUS" = "absent" ]; then
        TELNET_RESULT="PASS"
        TELNET_REASON="원격터미널(Telnet) 서비스가 활성 상태로 판단되나 pam_securetty가 적용되어 있고 /etc/securetty에 pts/x 항목이 없어 root 직접 접속이 제한됩니다."
    else
        TELNET_RESULT="FAIL"
        # 실패 사유 상세 구성
        TELNET_REASON="원격터미널(Telnet) 서비스가 활성 상태로 판단되며(root 원격터미널 직접 접속 가능성), "
        if [ "$PAM_SECURETTY_STATUS" != "present" ]; then
            if [ "$PAM_SECURETTY_STATUS" = "absent" ]; then
                TELNET_REASON="${TELNET_REASON}/etc/pam.d/login에 pam_securetty.so 설정이 확인되지 않습니다. "
            else
                TELNET_REASON="${TELNET_REASON}/etc/pam.d/login 파일을 확인할 수 없어 pam_securetty 적용 여부를 보장할 수 없습니다. "
            fi
        fi
        if [ "$SECURETTY_PTS_STATUS" = "present" ]; then
            TELNET_REASON="${TELNET_REASON}/etc/securetty에 pts/x 항목(${SECURETTY_PTS_LIST_CSV})이 존재하여 root 원격터미널 접속을 허용할 수 있으므로 제거가 필요합니다."
        elif [ "$SECURETTY_PTS_STATUS" = "securetty_not_found" ]; then
            TELNET_REASON="${TELNET_REASON}/etc/securetty 파일을 확인할 수 없어 pts/x 허용 여부를 검증할 수 없습니다."
        fi
    fi
fi


# 3) 최종 STATUS 및 출력 메시지 구성
if [ "$SSH_RESULT" = "PASS" ] && [ "$TELNET_RESULT" = "PASS" ]; then
    STATUS="PASS"
    REASON_LINE="SSH 및 원격터미널(Telnet) 경로에서 root 계정 직접 원격 접속 제한이 적절히 적용되어 이 항목에 대한 보안 위협이 없습니다."
else
    STATUS="FAIL"
    REASON_LINE="root 계정 원격 접속 제한 설정이 일부 미흡하여 취약합니다."
fi

# detail 구성 (줄바꿈 포함)
DETAIL_CONTENT=$(cat <<EOF
ssh_check_result=${SSH_RESULT}
ssh_permitrootlogin=${SSH_VAL}
telnet_check_result=${TELNET_RESULT}
telnet_active=${TELNET_ACTIVE}
telnet_detection=${TELNET_DETECTION}
pam_securetty_in_${TARGET_PAM_LOGIN}=${PAM_SECURETTY_STATUS}
securetty_pts_entries_in_${TARGET_SECURETTY}=${SECURETTY_PTS_LIST_CSV}
ssh_reason=${SSH_REASON}
telnet_reason=${TELNET_REASON}
EOF
)

# raw_evidence 구성 (첫 줄: 평가 요약 / 다음 줄부터: 상세)
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "$TARGET_FILES"
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