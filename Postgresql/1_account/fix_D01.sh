# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-01
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : 기본 계정의 비밀번호, 정책 등을 변경하여 사용
# @Description : DBMS 기본 계정의 초기 비밀번호 및 권한 정책 변경 사용 유무 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

ID="D-01"
CATEGORY="계정관리"
TITLE="관리자(SUPERUSER) 계정 비밀번호 설정(수동조치 안내)"
IMPORTANCE="상"

STATUS="FAIL"
ACTION_RESULT="MANUAL_REQUIRED"
ACTION_LOG="N/A"
EVIDENCE="N/A"
ACTION_DATE=$(date '+%Y-%m-%d %H:%M:%S')

# 1. SUPERUSER 계정 목록 조회
SUPERUSERS=$(sudo -u postgres psql -t -A -c "
SELECT rolname
FROM pg_roles
WHERE rolsuper = true;
" 2>/dev/null)

# 2. 조치 안내 구성
if [ $? -ne 0 ] || [ -z "$SUPERUSERS" ]; then
    STATUS="FAIL"
    ACTION_RESULT="ERROR"
    ACTION_LOG="PostgreSQL 접속 실패 또는 SUPERUSER 계정 조회 실패"
    EVIDENCE="관리자 계정 목록을 확인할 수 없음"
    GUIDE_MSG="PostgreSQL 접속 권한을 확인한 후 다시 조치를 시도하십시오."
else
    STATUS="FAIL"
    ACTION_RESULT="MANUAL_REQUIRED"
    TARGET_USERS=$(echo "$SUPERUSERS" | tr '\n' ',' | sed 's/,$//')

    ACTION_LOG="수동 조치 필요: SUPERUSER 계정 비밀번호 설정"
    EVIDENCE="관리자(SUPERUSER) 계정 목록: ${TARGET_USERS}"

    GUIDE_MSG="PostgreSQL은 관리자(SUPERUSER) 계정의 비밀번호를 자동으로 변경하지 않습니다. 아래 절차에 따라 수동으로 비밀번호를 설정하십시오.\n\n1) 관리자 계정 확인:\nSELECT rolname FROM pg_roles WHERE rolsuper = true;\n\n2) 관리자 계정으로 접속:\nsudo -u postgres psql\n\n3) 비밀번호 설정:\nALTER USER <SUPERUSER_계정명> WITH PASSWORD '<강력한 비밀번호>';\n\n※ 조치 대상 계정: ${TARGET_USERS}"
fi

# 3. JSON 출력 
cat <<EOF
{
  "check_id": "$ID",
  "category": "$CATEGORY",
  "title": "$TITLE",
  "importance": "$IMPORTANCE",
  "status": "$STATUS",
  "evidence": "$EVIDENCE",
  "guide": "$GUIDE_MSG",
  "action_result": "$ACTION_RESULT",
  "action_log": "$ACTION_LOG",
  "action_date": "$ACTION_DATE",
  "check_date": "$ACTION_DATE"
}
EOF