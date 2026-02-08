# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-25
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : 데이터베이스의 접근, 변경, 삭제 등의 감사 기록이 기관의 감사 기록 정책에 적합하도록 설정
# @Description : 감사 기록 정책 설정이 기관 정책에 적합하게 설정되어 있는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
ITEM_ID="D-25"
CATEGORY="패치관리"
CHECK_ITEM="DBMS 보안 패치 적용"
DESCRIPTION="감사 기록 정책 설정이 기관 정책에 적합하게 설정되어 있는지 점검"
IMPORTANCE="상"
CHECKED_AT=$(date -Iseconds)

version=$(psql -U postgres -t -c "SHOW server_version;" | xargs)

major_ver=$(echo "$version" | cut -d'.' -f1)

if [ "$major_ver" -ge 14 ]; then
  STATUS="양호"
  RESULT_MSG="보안 패치 지원 버전(PostgreSQL $version) 사용 중"
else
  STATUS="취약"
  RESULT_MSG="보안 패치 지원 종료(EOL) 또는 취약 가능 버전(PostgreSQL $version) 사용 중"
fi

cat <<EOF
{ "item_id":"$ITEM_ID",
"category":"$CATEGORY",
"check_item":"$CHECK_ITEM",
"description":"$DESCRIPTION",
"IMPORTANCE":"$IMPORTANCE",
"checked_at":"$CHECKED_AT",
"status":"$STATUS",
"result":"$RESULT_MSG",
"checked":true }
EOF
