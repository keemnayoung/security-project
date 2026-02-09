#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-07
# ============================================================================
# [점검 항목 상세]
# @ID          : D-25
# @Category    : DBMS (Database Management System)
# @Platform    : MySQL 8.0.44
# @IMPORTANCE  : 상
# @Title       : 주기적 보안 패치 및 벤더 권고 사항 적용
# @Description : 안전한 버전의 데이터베이스를 사용하고 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash

ID="D-25"
CATEGORY="패치관리"
TITLE="주기적 보안 패치 및 벤더 권고 사항 적용"
IMPORTANCE="상"

ACTION_TYPE="manual"
ACTION_RESULT="GUIDE"
CURRENT_STATUS="PASS"
EVIDENCE=""
ACTION_LOG=""

NOW=$(date '+%Y-%m-%d %H:%M:%S')

MYSQL_CMD="mysql -uroot -N -B 2>/dev/null"

############################################
# 1. MySQL 버전 확인
############################################
DB_VERSION=$($MYSQL_CMD -e "SELECT VERSION();" 2>/dev/null)

if [ -z "$DB_VERSION" ]; then
    CURRENT_STATUS="점검불가"
    EVIDENCE="MySQL 접속 불가"
    ACTION_LOG="DB 접속 실패로 버전 확인 불가"

else
    ############################################
    # 2. 메이저 버전 파싱
    ############################################
    MAJOR_VERSION=$(echo "$DB_VERSION" | cut -d'.' -f1)
    MINOR_VERSION=$(echo "$DB_VERSION" | cut -d'.' -f2)

    ############################################
    # 3. 판단 기준 (예: MySQL 8.x 이상 권장)
    ############################################
    if [ "$MAJOR_VERSION" -lt 8 ]; then
        CURRENT_STATUS="FAIL"
        EVIDENCE="구버전 MySQL 사용 중 (버전: $DB_VERSION)"
        ACTION_LOG="보안 패치 미적용 가능성 높음"
    else
        CURRENT_STATUS="PASS"
        EVIDENCE="보안 패치 적용 가능한 최신 계열 버전 사용 중 (버전: $DB_VERSION)"
        ACTION_LOG="버전 관리 상태 양호"
    fi
fi

############################################
# 4. 조치 가이드
############################################
GUIDE_TEXT="MySQL 최신 보안 패치 버전으로 업그레이드 필요 시 수행:
1) 현재 버전 확인: SELECT VERSION();
2) MySQL 공식 릴리즈 노트에서 최신 보안 패치 버전 확인
3) 패키지 업데이트 (Rocky Linux 예시):
   sudo dnf update mysql-community-server
4) 업데이트 후 서비스 재시작:
   sudo systemctl restart mysqld"

############################################
# 5. JSON 출력
############################################
cat <<EOF
{
  "check_id": "$ID",
  "category": "$CATEGORY",
  "title": "$TITLE",
  "importance": "$IMPORTANCE",
  "status": "$CURRENT_STATUS",
  "evidence": "$EVIDENCE",
  "guide": "$GUIDE_TEXT",
  "action_type": "$ACTION_TYPE",
  "action_result": "$ACTION_RESULT",
  "action_log": "$ACTION_LOG",
  "action_date": "$NOW",
  "check_date": "$NOW"
}
EOF
