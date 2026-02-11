#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-07
# ============================================================================
# [점검 항목 상세]
# @ID          : D-04
# @Category    : DBMS (Database Management System)
# @Platform    : MySQL 
# @IMPORTANCE  : 상
# @Title       : 데이터베이스 관리자 권한을 꼭 필요한 계정에만 부여
# @Description : 관리자 권한이 필요한 계정 및 그룹에만 관리자 권한을 부여하였는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-04"
CATEGORY="DBMS"
TITLE="관리자 권한 최소 부여"
IMPORTANCE="상"
TARGET_FILE="mysql.user"

STATUS="FAIL"
EVIDENCE="N/A"

# TCP 강제(소켓 미생성 환경 대응)
MYSQL_CMD="mysql --connect-timeout=5 --protocol=TCP -uroot -N -s -B -e"

# [가이드 취지] 관리자급 권한만 점검(일반 DML 권한 제외)
ADMIN_PRIVS="'SUPER','SYSTEM_USER','CREATE USER','RELOAD','SHUTDOWN','PROCESS'"

QUERY="
SELECT grantee
FROM information_schema.user_privileges
WHERE privilege_type IN (${ADMIN_PRIVS})
GROUP BY grantee;
"

# 1) 관리자 권한 보유 계정 목록 조회
RESULT=$($MYSQL_CMD "$QUERY" 2>/dev/null)
RC=$?

if [[ $RC -ne 0 ]]; then
    STATUS="FAIL"
    EVIDENCE="MySQL 접속 실패 또는 쿼리 실행 오류로 관리자 권한 부여 상태를 확인할 수 없습니다."
else
    # 2) 가이드 판정 로직(조금 더 엄격하게)
    # - root@localhost 는 기본 관리자 계정으로 허용
    # - root@% 또는 root@원격호스트 는 원격 root 가능성이므로 취약으로 판단
    # - 그 외 관리자 권한 보유 계정은(허용목록 제외) 취약으로 판단

    ROOT_LOCAL=$(echo "$RESULT" | grep -E "root@localhost" || true)
    ROOT_REMOTE=$(echo "$RESULT" | grep -E "root@%" || true)

    # root@'host' 형태라 따옴표 포함 가능 -> 공백/따옴표 제거해 비교
    ROOT_REMOTE2=$(echo "$RESULT" | grep -E "root@" | grep -v "localhost" || true)

    # 허용 계정 목록(필요 시 추가 가능): 예) ALLOWLIST=("root@localhost" "dba@localhost")
    ALLOWLIST=("root@localhost")

    # 결과에서 따옴표 제거 후 비교용 정규화
    NORMALIZED=$(echo "$RESULT" | tr -d "'" | sed 's/[[:space:]]//g')

    # 허용 목록 제외한 관리자 권한 보유 계정 추출
    NON_ALLOWED="$NORMALIZED"
    for a in "${ALLOWLIST[@]}"; do
        NON_ALLOWED=$(echo "$NON_ALLOWED" | grep -v -F "$a" || true)
    done

    # root 원격 계정 판단(정규화 기준)
    ROOT_REMOTE_NORM=$(echo "$NORMALIZED" | grep -E "^root@%" || true)
    ROOT_OTHER_REMOTE_NORM=$(echo "$NORMALIZED" | grep -E "^root@" | grep -v "^root@localhost$" || true)

    if [[ -n "$ROOT_REMOTE_NORM" || -n "$ROOT_OTHER_REMOTE_NORM" ]]; then
        STATUS="FAIL"
        SAMPLE=$( (echo "$ROOT_REMOTE_NORM"; echo "$ROOT_OTHER_REMOTE_NORM") | head -n 1 )
        EVIDENCE="원격 root 계정에 관리자 권한이 부여되어 있습니다. (예: ${SAMPLE})"
    else
        if [[ -z "$NON_ALLOWED" ]]; then
            STATUS="PASS"
            EVIDENCE="관리자 권한이 필요한 계정(예: root@localhost)에만 권한이 부여되어 있습니다."
        else
            COUNT=$(echo "$NON_ALLOWED" | wc -l | tr -d ' ')
            SAMPLE=$(echo "$NON_ALLOWED" | head -n 1)
            STATUS="FAIL"
            EVIDENCE="허용되지 않은 계정(${COUNT}개)에 관리자 권한이 부여되어 있습니다. (예: ${SAMPLE})"
        fi
    fi
fi

# 파일 해시(요구사항 유지)
if [ -f "$TARGET_FILE" ]; then
    FILE_HASH=$(sha256sum "$TARGET_FILE" 2>/dev/null | awk '{print $1}')
    [[ -z "$FILE_HASH" ]] && FILE_HASH="HASH_ERROR"
else
    FILE_HASH="NOT_FOUND"
fi

cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "관리자 권한이 필요하지 않은 계정에서는 SUPER, SYSTEM_USER 등 관리자 권한을 회수하고, 최소 권한 원칙에 따라 필요한 권한만 부여하세요.",
    "target_file": "$TARGET_FILE",
    "file_hash": "$FILE_HASH",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
