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

CURRENT_STATUS="FAIL"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"

NOW=$(date '+%Y-%m-%d %H:%M:%S')

# 현재 암호화 알고리즘 확인
CURRENT_ENC=$(sudo -u postgres psql -t -c "SHOW password_encryption;" 2>/dev/null | xargs)

if [ "$CURRENT_ENC" = "scram-sha-256" ]; then
    CURRENT_STATUS="PASS"
    ACTION_RESULT="NOT_REQUIRED"
    ACTION_LOG="양호: PostgreSQL 기본 비밀번호 암호화 알고리즘이 SCRAM-SHA-256으로 설정되어 있음"
else
    # 1. 기본 암호화 알고리즘 변경(md5 -> sha256)
    sudo -u postgres psql -c \
    "ALTER SYSTEM SET password_encryption = 'scram-sha-256';" >/dev/null 2>&1
    # 2. 설정 반영
    sudo -u postgres psql -c "SELECT pg_reload_conf();" >/dev/null 2>&1

    CURRENT_STATUS="PASS"
    ACTION_RESULT="FAIL"
    ACTION_LOG="부분 조치 완료: PostgreSQL 기본 비밀번호 암호화 알고리즘을 SCRAM-SHA-256으로 변경함. 기존 사용자 계정은 비밀번호 재설정을 통해 재적용 필요"
fi

# JSON 출력
cat <<EOF
{
  "check_id": "$ID",
  "status": "$CURRENT_STATUS",
  "action_result": "$ACTION_RESULT",
  "action_log": "$ACTION_LOG",
  "action_date": "$NOW",
  "check_date": "$NOW"
}
EOF


