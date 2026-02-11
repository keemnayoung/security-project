#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 1.0.0
# @Author: 한은결
# @Last Updated: 2026-02-07
# ============================================================================
# [점검 항목 상세]
# @ID          : D-08
# @Category    : DBMS (Database Management System)
# @Platform    : MySQL 8.0.44
# @IMPORTANCE  : 상
# @Title       : 안전한 암호화 알고리즘 사용
# @Description : SHA-256 이상 기반 인증 암호 알고리즘 사용 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-08"
CATEGORY="계정관리"
TITLE="안전한 암호화 알고리즘 사용"
IMPORTANCE="상"
IMPACT_LEVEL="LOW"
ACTION_IMPACT="이 조치를 적용하면 취약하거나 구식 인증 플러그인(mysql_native_password 등)을 사용하는 계정이 caching_sha2_password(SHA-256) 기반 인증으로 전환됩니다. 일반적인 시스템 운영에는 영향이 없으나, 애플리케이션이 해당 계정으로 접속하는 경우 드라이버/클라이언트 호환성에 따라 접속 설정 변경이 필요할 수 있으므로 사전 점검 후 적용해야 합니다."

# 조치 결과 변수
STATUS="FAIL"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
EVIDENCE="N/A"

# 무한 로딩 방지
TIMEOUT_BIN="$(command -v timeout 2>/dev/null)"
MYSQL_TIMEOUT_SEC=5
MYSQL_CMD_BASE="mysql --connect-timeout=${MYSQL_TIMEOUT_SEC} -uroot -N -s -B -e"

run_mysql() {
    local sql="$1"
    if [[ -n "$TIMEOUT_BIN" ]]; then
        $TIMEOUT_BIN ${MYSQL_TIMEOUT_SEC}s $MYSQL_CMD_BASE "$sql" 2>/dev/null
        return $?
    else
        $MYSQL_CMD_BASE "$sql" 2>/dev/null
        return $?
    fi
}

# 0) 입력값(환경변수) 확인
# 대상 계정/호스트/비밀번호는 반드시 제공되어야 안전하게 조치 가능합니다.
# 예)
#   TARGET_USER='appuser' TARGET_HOST='10.0.0.%' TARGET_PASS='Strong!234' ./FIX_D08.sh
TARGET_USER="${TARGET_USER:-}"
TARGET_HOST="${TARGET_HOST:-}"
TARGET_PASS="${TARGET_PASS:-}"

if [[ -z "$TARGET_USER" || -z "$TARGET_HOST" || -z "$TARGET_PASS" ]]; then
    STATUS="FAIL"
    ACTION_RESULT="FAIL"
    ACTION_LOG="조치가 수행되지 않았습니다. 대상 계정 정보 또는 비밀번호가 제공되지 않았습니다."
    EVIDENCE="TARGET_USER, TARGET_HOST, TARGET_PASS 값이 누락되어 계정의 인증 플러그인 전환 조치를 수행할 수 없습니다."
else
  
    # 1) 계정별 인증 플러그인 확인
    
    CHECK_SQL="SELECT user, host, plugin FROM mysql.user WHERE user='${TARGET_USER}' AND host='${TARGET_HOST}';"
    ROW="$(run_mysql "$CHECK_SQL")"
    RC1=$?

    if [[ $RC1 -eq 124 ]]; then
        STATUS="FAIL"
        ACTION_RESULT="FAIL"
        ACTION_LOG="조치가 수행되지 않았습니다. 계정 정보 조회 명령이 제한 시간 내 완료되지 않아 중단하였습니다."
        EVIDENCE="MySQL 명령 실행이 ${MYSQL_TIMEOUT_SEC}초 내에 완료되지 않아 대기 또는 지연이 발생하였으며, 무한 로딩 방지를 위해 처리를 중단하였습니다."
    elif [[ $RC1 -ne 0 || -z "$ROW" ]]; then
        STATUS="FAIL"
        ACTION_RESULT="FAIL"
        ACTION_LOG="조치가 수행되지 않았습니다. 대상 계정을 조회할 수 없어 인증 방식 전환을 수행하지 못하였습니다."
        EVIDENCE="mysql.user에서 대상 계정 정보를 확인할 수 없어 계정 존재 여부 또는 권한을 점검해야 합니다."
    else
        # 결과: user<TAB>host<TAB>plugin
        CUR_PLUGIN="$(echo "$ROW" | awk '{print $3}')"

        
        # 2) caching_sha2_password로 전환 필요 여부 판단
        
        if [[ "$CUR_PLUGIN" == "caching_sha2_password" ]]; then
            STATUS="PASS"
            ACTION_RESULT="SUCCESS"
            ACTION_LOG="대상 계정이 이미 caching_sha2_password(SHA-256) 기반 인증을 사용하고 있어 추가 조치 없이 안전한 인증 상태를 유지하였습니다."
            EVIDENCE="대상 계정(${TARGET_USER}@${TARGET_HOST})의 인증 플러그인이 caching_sha2_password로 확인되었습니다."
        else
            
            # 3) 구식 인증 플러그인 → caching_sha2_password로 전환
    
            FIX_SQL="ALTER USER '${TARGET_USER}'@'${TARGET_HOST}' IDENTIFIED WITH caching_sha2_password BY '${TARGET_PASS}';"
            run_mysql "$FIX_SQL" >/dev/null
            RC2=$?

            if [[ $RC2 -eq 124 ]]; then
                STATUS="FAIL"
                ACTION_RESULT="FAIL"
                ACTION_LOG="조치가 수행되지 않았습니다. 인증 플러그인 전환 명령이 제한 시간 내 완료되지 않아 중단하였습니다."
                EVIDENCE="인증 플러그인 전환 명령 실행이 ${MYSQL_TIMEOUT_SEC}초 내에 완료되지 않아 무한 로딩 방지를 위해 처리를 중단하였습니다."
            elif [[ $RC2 -ne 0 ]]; then
                STATUS="FAIL"
                ACTION_RESULT="FAIL"
                ACTION_LOG="조치가 수행되지 않았습니다. 인증 플러그인 전환에 실패하였습니다."
                EVIDENCE="ALTER USER 명령 수행에 실패하여 대상 계정의 인증 방식을 caching_sha2_password로 변경할 수 없습니다."
            else
                # 재확인
                VERIFY_SQL="SELECT plugin FROM mysql.user WHERE user='${TARGET_USER}' AND host='${TARGET_HOST}';"
                NEW_PLUGIN="$(run_mysql "$VERIFY_SQL" | head -n 1)"
                if [[ "$NEW_PLUGIN" == "caching_sha2_password" ]]; then
                    STATUS="PASS"
                    ACTION_RESULT="SUCCESS"
                    ACTION_LOG="대상 계정의 인증 플러그인을 caching_sha2_password(SHA-256)로 전환하여 안전한 암호화 알고리즘이 적용되도록 조치하였습니다."
                    EVIDENCE="대상 계정(${TARGET_USER}@${TARGET_HOST})의 인증 플러그인이 caching_sha2_password로 변경된 것이 확인되었습니다."
                else
                    STATUS="FAIL"
                    ACTION_RESULT="FAIL"
                    ACTION_LOG="조치가 수행되지 않았습니다. 인증 플러그인 전환 후 상태 확인에 실패하였습니다."
                    EVIDENCE="인증 플러그인 변경을 수행했으나, 변경 결과를 확인할 수 없어 추가 점검이 필요합니다."
                fi
            fi
        fi
    fi
fi

# JSON 표준 출력 (고정 구조)
echo ""
cat << EOF
{
    "check_id": "$ID",
    "category": "$CATEGORY",
    "title": "$TITLE",
    "importance": "$IMPORTANCE",
    "impact_level": "$IMPACT_LEVEL",
    "action_impact": "$ACTION_IMPACT",
    "status": "$STATUS",
    "evidence": "$EVIDENCE",
    "guide": "KISA 가이드라인 기준 보안 설정 조치 완료",
    "action_result": "$ACTION_RESULT",
    "action_log": "$ACTION_LOG",
    "action_date": "$(date '+%Y-%m-%d %H:%M:%S')",
    "check_date": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF