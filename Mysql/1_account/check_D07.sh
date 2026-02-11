#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-07
# ============================================================================
# [점검 항목 상세]
# @ID          : D-07
# @Category    : DBMS (Database Management System)
# @Platform    : MySQL
# @IMPORTANCE  : 중
# @Title       : root 권한으로 서비스 구동 제한
# @Description : DBMS 서비스가 root 권한이 아닌 전용 계정으로 실행되는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-07"
CATEGORY="DBMS"
TITLE="root 권한으로 서비스 구동 제한"
IMPORTANCE="중"
TARGET_FILE="/etc/my.cnf"

STATUS="FAIL"
EVIDENCE="N/A"

# mysqld 프로세스 실행 사용자 확인
PROC_INFO=$(ps -eo user,comm | grep -w mysqld | grep -v grep || true)

if [[ -z "$PROC_INFO" ]]; then
    STATUS="FAIL"
    EVIDENCE="MySQL 서비스(mysqld) 프로세스를 확인할 수 없어, 서비스 구동 계정을 점검할 수 없습니다."
else
    # root 계정으로 실행 중인 mysqld 존재 여부 확인
    ROOT_PROC=$(echo "$PROC_INFO" | awk '$1=="root"')

    if [[ -z "$ROOT_PROC" ]]; then
        STATUS="PASS"
        RUN_USER=$(echo "$PROC_INFO" | awk 'NR==1{print $1}')
        EVIDENCE="MySQL 서비스가 root 권한이 아닌 '${RUN_USER}' 계정으로 실행되고 있어, 서비스 권한 남용으로 인한 시스템 손상 위험이 낮습니다."
    else
        STATUS="FAIL"
        EVIDENCE="MySQL 서비스가 root 권한으로 실행되고 있어, 서비스 취약점 악용 시 시스템 전체가 손상될 수 있는 위험이 있습니다."
    fi
fi

# 파일 해시
if [ -f "$TARGET_FILE" ]; then
    FILE_HASH=$(sha256sum "$TARGET_FILE" 2>/dev/null | awk '{print $1}')
    [[ -z "$FILE_HASH" ]] && FILE_HASH="HASH_ERROR"
else
    FILE_HASH="NOT_FOUND"
fi

ACTION_IMPACT="이 조치를 적용하면 MySQL 서버가 지정된 일반 사용자 계정으로 실행되도록 설정이 변경됩니다. 일반적인 시스템 운영에는 영향이 없으며, 서버 시작 및 데이터베이스 접근에도 문제를 일으키지 않습니다. 다만, 서버 구동 사용자 계정 변경 후 파일 권한이나 소유권이 올바르게 설정되어 있는지 확인해야 합니다."

cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "DBMS 서비스는 root가 아닌 전용 계정(mysql 등)으로 구동되도록 설정하고, systemd 또는 서비스 설정 파일에서 실행 계정을 점검하세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF


