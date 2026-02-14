#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-07
# ============================================================================
# [점검 항목 상세]
# @ID          : D-07
# @Category    : 계정 관리
# @Platform    : MySQL
# @IMPORTANCE  : 중
# @Title       : root 권한으로 서비스 구동 제한
# @Description : DBMS 서비스가 root 권한이 아닌 전용 계정으로 실행되는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-07"
STATUS="FAIL"
SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"

TARGET_FILE="/etc/my.cnf"

EVIDENCE="N/A"

# 실제 mysqld 바이너리(/proc/<pid>/exe)가 확인되는 프로세스만 수집
get_real_mysqld_proc_info() {
    local pid user comm exe
    while read -r pid user comm; do
        [[ -z "$pid" ]] && continue
        exe="$(readlink -f "/proc/${pid}/exe" 2>/dev/null || true)"
        [[ "$exe" == */mysqld || "$exe" == */mariadbd ]] || continue
        printf "%s\t%s\t%s\n" "$pid" "$user" "$exe"
    done < <(ps -eo pid=,user=,comm= 2>/dev/null | awk '$3=="mysqld" || $3=="mariadbd"{print $1, $2, $3}')
}

# mysqld 프로세스 실행 사용자 확인
PROC_INFO="$(get_real_mysqld_proc_info)"

REASON_LINE=""
DETAIL_CONTENT=""

if [[ -z "$PROC_INFO" ]]; then
    STATUS="FAIL"
    REASON_LINE="MySQL 서비스(mysqld) 프로세스를 확인할 수 없어, 서비스 구동 계정을 점검할 수 없습니다."
    DETAIL_CONTENT="proc_info=EMPTY"
else
    # root 계정으로 실행 중인 mysqld 존재 여부 확인
    ROOT_PROC=$(echo "$PROC_INFO" | awk -F'\t' '$2=="root"')

    if [[ -z "$ROOT_PROC" ]]; then
        STATUS="PASS"
        RUN_USER=$(echo "$PROC_INFO" | awk -F'\t' 'NR==1{print $2}')
        REASON_LINE="MySQL 서비스가 root 권한이 아닌 '${RUN_USER}' 계정으로 실행되고 있어, 서비스 권한 남용으로 인한 시스템 손상 위험이 낮습니다."
        DETAIL_CONTENT="run_user=${RUN_USER}; proc_count=$(echo "$PROC_INFO" | awk 'END{print NR+0}')"
    else
        STATUS="FAIL"
        REASON_LINE="MySQL 서비스가 root 권한으로 실행되고 있어, 서비스 취약점 악용 시 시스템 전체가 손상될 수 있는 위험이 있습니다."
        DETAIL_CONTENT="root_proc=$(echo "$ROOT_PROC" | awk -F'\t' '{print $1":"$3}' | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
    fi
fi

CHECK_COMMAND="ps -eo pid=,user=,comm= | awk '\$3==\"mysqld\" || \$3==\"mariadbd\"{print \$1, \$2, \$3}' + readlink -f /proc/<pid>/exe"
RAW_EVIDENCE=$(cat <<EOF
{
  "command": "$CHECK_COMMAND",
  "detail": "$REASON_LINE\n$DETAIL_CONTENT",
  "target_file": "$TARGET_FILE"
}
EOF
)

RAW_EVIDENCE_ESCAPED=$(echo "$RAW_EVIDENCE" \
  | sed 's/"/\\"/g' \
  | sed ':a;N;$!ba;s/\n/\\n/g')

echo ""
cat << EOF
{
    "item_code": "$ID",
    "status": "$STATUS",
    "raw_evidence": "$RAW_EVIDENCE_ESCAPED",
    "scan_date": "$SCAN_DATE"
}
EOF