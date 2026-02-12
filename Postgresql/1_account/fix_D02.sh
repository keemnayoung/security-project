# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-02
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : 데이터베이스의 불필요 계정을 제거하거나, 잠금설정 후 사용
# @Description : DBMS에 존재하는 계정 중 DB 관리나 운용에 사용하지 않는 불필요한 계정이 존재하는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

ID="D-02"
CATEGORY="계정관리"
TITLE="데이터베이스의 불필요 계정을 제거하거나, 잠금설정 후 사용"
IMPORTANCE="상"

STATUS="FAIL"
ACTION_RESULT="MANUAL_REQUIRED"
ACTION_LOG="수동 조치 필요"
EVIDENCE="N/A"
ACTION_DATE=$(date '+%Y-%m-%d %H:%M:%S')

# 1. 전체 ROLE 조회

ALL_ROLES=$(sudo -u postgres psql -t -A -F ',' -c "
SELECT rolname,
       rolcanlogin,
       rolsuper,
       rolcreatedb,
       rolcreaterole
FROM pg_roles
ORDER BY rolname;
" 2>/dev/null | sed '/^\s*$/d')

ROLE_MEMBERS=$(sudo -u postgres psql -t -A -F ',' -c "
SELECT u.rolname AS member,
       r.rolname AS role
FROM pg_auth_members m
JOIN pg_roles u ON m.member = u.oid
JOIN pg_roles r ON m.roleid = r.oid
ORDER BY u.rolname;
" 2>/dev/null | sed '/^\s*$/d')

# 2. 안내 구성
if [ -z "$ALL_ROLES" ]; then
    STATUS="FAIL"
    ACTION_RESULT="ERROR"
    ACTION_LOG="ROLE 조회 실패"
    EVIDENCE="ROLE 정보를 조회할 수 없음"
    GUIDE_MSG="PostgreSQL 접속 권한을 확인한 후 다시 시도하십시오."
else
    EVIDENCE="전체 ROLE 목록:\n$ALL_ROLES\n\n불필요 계정 후보:\n${CANDIDATES}"

    GUIDE_MSG="PostgreSQL은 불필요 계정을 자동으로 삭제하지 않습니다. 위 ROLE 정보를 검토하여 운영 및 서비스에 필요하지 않은 계정을 식별하십시오.\n※ 조치 대상 후보 계정: ${CANDIDATES}\n

1) 로그인 차단:
ALTER ROLE <계정명> NOLOGIN;

2) 객체 소유 여부 확인:
SELECT n.nspname, c.relname
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relowner = (SELECT oid FROM pg_roles WHERE rolname='<계정명>');

3) 소유권 이전:
REASSIGN OWNED BY <계정명> TO postgres;

4) 최종 삭제:
DROP ROLE <계정명>;"
fi


# 3. JSON 안전 처리 (줄바꿈 + 따옴표 escape)

GUIDE_ESCAPED=$(echo "$GUIDE_MSG" | sed ':a;N;$!ba;s/\n/\\n/g' | sed 's/"/\\"/g')
EVIDENCE_ESCAPED=$(echo "$EVIDENCE" | sed ':a;N;$!ba;s/\n/\\n/g' | sed 's/"/\\"/g')
ACTION_LOG_ESCAPED=$(echo "$ACTION_LOG" | sed 's/"/\\"/g')


# 4. JSON 출력 (JSON 1개만 출력)


cat <<EOF
{
  "check_id": "$ID",
  "category": "$CATEGORY",
  "title": "$TITLE",
  "importance": "$IMPORTANCE",
  "status": "$STATUS",
  "evidence": "$EVIDENCE_ESCAPED",
  "guide": "$GUIDE_ESCAPED",
  "action_result": "$ACTION_RESULT",
  "action_log": "$ACTION_LOG_ESCAPED",
  "action_date": "$ACTION_DATE",
  "check_date": "$ACTION_DATE"
}
EOF


