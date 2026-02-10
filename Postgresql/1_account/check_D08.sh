# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 윤영아
# @Last Updated: 2026-02-05
# ============================================================================
# [점검 항목 상세]
# @ID          : D-08
# @Category    : DBMS
# @Platform    : PostgreSQL 16.11
# @Importance  : 상
# @Title       : 안전한 암호화 알고리즘 사용
# @Description : 해시 알고리즘 SHA-256 이상의 암호화 알고리즘을 사용하는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

#!/bin/bash
ID="D-08"
CATEGORY="계정 관리"
TITLE="비밀번호 암호화 알고리즘"
IMPORTANCE="상"
DATE=(date '+%Y-%m-%d %H:%M:%S')
TARGET_FILE="password_encryption"
ACTION_IMPACT="비밀번호 암호화 알고리즘 설정은 신규 계정 생성 또는 비밀번호 변경 시점에만 적용되므로, 기존 계정의 인증 정보나 서비스 가용성에는 영향을 주지 않습니다."
IMPACT_LEVEL="LOW"

enc=$(psql -U postgres -t -c "SHOW password_encryption;" | xargs)
if [ "$enc" = "scram-sha-256" ]; then
  STATUS="양호"
   EVIDENCE="SHA-256 기반 SCRAM 암호화 알고리즘 사용"
else
  STATUS="취약"
   EVIDENCE="SHA-256 미만 암호화 알고리즘 사용($enc)"
fi

cat <<EOF
{ "check_id":"$ID",
"category":"$CATEGORY",
"title":"$TITLE",
"importance":"$IMPORTANCE",
"status":"$STATUS",
"evidence":"$EVIDENCE",
"guide":"psql 접속 후 password_encryption 설정을 확인하고, 신규 사용자 생성 또는 기존 사용자 비밀번호 변경 시 SCRAM-SHA-256 알고리즘이 적용되도록 구성해야 합니다.",
"target_file":"$TARGET_FILE",
"action_impact":"$ACTION_IMPACT",
"impact_level":"$IMPACT_LEVEL",
"check_date": "$DATE" }
EOF
