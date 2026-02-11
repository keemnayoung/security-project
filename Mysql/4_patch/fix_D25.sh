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

ID="D-25"
CATEGORY="패치관리"
TITLE="주기적 보안 패치 및 벤더 권고 사항 적용"
IMPORTANCE="상"
IMPACT_LEVEL="HIGH"
ACTION_IMPACT="이 조치를 적용하면 MySQL을 최신 버전으로 업데이트하게 되므로, 기존 시스템에서 사용되던 애플리케이션, 스크립트, 드라이버 등과 호환성 문제가 발생할 수 있습니다. 따라서 업데이트 전에는 영향 범위를 충분히 검토하고, 테스트 환경에서 사전 검증을 수행한 후 운영 환경에 적용해야 합니다."

# 조치 결과 변수
STATUS="FAIL"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
EVIDENCE="N/A"

# 무한 로딩 방지
TIMEOUT_BIN="$(command -v timeout 2>/dev/null)"
CMD_TIMEOUT_SEC=8
MYSQL_TIMEOUT_SEC=5
MYSQL_CMD_BASE="mysql --connect-timeout=${MYSQL_TIMEOUT_SEC} -uroot -N -s -B -e"

run_cmd() {
    local cmd="$1"
    if [[ -n "$TIMEOUT_BIN" ]]; then
        $TIMEOUT_BIN ${CMD_TIMEOUT_SEC}s bash -lc "$cmd" 2>/dev/null
        return $?
    else
        bash -lc "$cmd" 2>/dev/null
        return $?
    fi
}

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


# 0) 실행 옵션(환경변수)
# 기본은 실제 업데이트 미수행(점검/안내)
DO_UPDATE="${DO_UPDATE:-N}"          # Y이면 실제 업데이트 수행
RESTART_MYSQL="${RESTART_MYSQL:-N}"  # Y이면 업데이트 후 mysqld 재시작 시도
PACKAGE_NAME="${PACKAGE_NAME:-}"     # 패키지명 강제 지정(선택)

# MySQL 버전 확인(SELECT VERSION())
MYSQL_VERSION_RAW="$(run_mysql "SELECT VERSION();")"
RC0=$?

if [[ $RC0 -eq 124 ]]; then
    STATUS="FAIL"
    ACTION_RESULT="FAIL"
    ACTION_LOG="조치가 수행되지 않았습니다. MySQL 버전 확인 명령이 제한 시간 내 완료되지 않아 중단하였습니다."
    EVIDENCE="MySQL 버전 확인(SELECT VERSION()) 명령 실행이 ${MYSQL_TIMEOUT_SEC}초 내에 완료되지 않아 무한 로딩 방지를 위해 처리를 중단하였습니다."
elif [[ $RC0 -ne 0 || -z "$MYSQL_VERSION_RAW" ]]; then
    STATUS="FAIL"
    ACTION_RESULT="FAIL"
    ACTION_LOG="조치가 수행되지 않았습니다. MySQL 버전을 확인할 수 없어 업데이트 여부를 판단하지 못하였습니다."
    EVIDENCE="SELECT VERSION() 수행에 실패하여 현재 설치된 MySQL 버전을 확인할 수 없습니다."
else
    # 패키지 매니저 탐지
    PM=""
    if command -v apt-get >/dev/null 2>&1; then PM="apt"
    elif command -v dnf >/dev/null 2>&1; then PM="dnf"
    elif command -v yum >/dev/null 2>&1; then PM="yum"
    elif command -v zypper >/dev/null 2>&1; then PM="zypper"
    else PM="unknown"
    fi

    # 설치 패키지명 자동 추정(환경마다 다름)
    if [[ -z "$PACKAGE_NAME" ]]; then
        case "$PM" in
            apt)    PACKAGE_NAME="mysql-server" ;;
            dnf|yum) PACKAGE_NAME="mysql-community-server" ;;  # 오라클 repo 사용 시 흔함
            zypper) PACKAGE_NAME="mysql-community-server" ;;
            *)      PACKAGE_NAME="mysql-server" ;;
        esac
    fi

    # "저장소 기준 최신 후보 버전" 조회 (벤더 사이트 직접 확인은 본 스크립트에서 수행하지 않음)
    CANDIDATE_VER="N/A"
    case "$PM" in
        apt)
            # apt-cache policy 출력에서 Candidate 추출
            CANDIDATE_VER="$(run_cmd "apt-cache policy ${PACKAGE_NAME} | awk '/Candidate:/{print \$2; exit}'")"
            ;;
        dnf)
            # dnf info에서 Version/Release 추출(가능한 경우)
            CANDIDATE_VER="$(run_cmd "dnf -q info ${PACKAGE_NAME} | awk -F': ' '/^Version/{v=\$2} /^Release/{r=\$2} END{if(v!=\"\"){print v\"-\"r}else{print \"N/A\"}}'")"
            ;;
        yum)
            CANDIDATE_VER="$(run_cmd "yum -q info ${PACKAGE_NAME} | awk -F': ' '/^Version/{v=\$2} /^Release/{r=\$2} END{if(v!=\"\"){print v\"-\"r}else{print \"N/A\"}}'")"
            ;;
        zypper)
            CANDIDATE_VER="$(run_cmd "zypper -q info ${PACKAGE_NAME} | awk -F': ' '/^Version/{print \$2; exit}'")"
            ;;
        *)
            CANDIDATE_VER="N/A"
            ;;
    esac

    # 현재 버전과 후보 버전을 evidence에 서술형으로 남김
    BASE_EVID="현재 MySQL 버전은 ${MYSQL_VERSION_RAW}이며, 패키지 저장소에서 확인되는 ${PACKAGE_NAME}의 최신 후보 버전은 ${CANDIDATE_VER}입니다."

    if [[ "$PM" == "unknown" || "$CANDIDATE_VER" == "N/A" || -z "$CANDIDATE_VER" ]]; then
        STATUS="FAIL"
        ACTION_RESULT="FAIL"
        ACTION_LOG="조치가 수행되지 않았습니다. 패키지 저장소에서 최신 버전을 확인할 수 없어 업데이트를 진행하지 못하였습니다."
        EVIDENCE="${BASE_EVID} 시스템의 패키지 관리 환경 또는 MySQL 설치 방식(수동 설치 등)을 확인해야 합니다."
    else
        # 단순 비교(정확한 SemVer 비교가 어려운 환경이 있어, 동일 문자열이면 최신으로 간주)
        if [[ "$MYSQL_VERSION_RAW" == *"$CANDIDATE_VER"* ]]; then
            STATUS="PASS"
            ACTION_RESULT="SUCCESS"
            ACTION_LOG="MySQL이 최신 후보 버전을 사용 중으로 확인되어 추가 업데이트 없이 보안 패치 적용 상태를 유지하였습니다."
            EVIDENCE="${BASE_EVID} 현재 버전이 최신 후보 버전과 동일한 것으로 확인됩니다."
        else
            # 최신이 아닐 수 있음 → DO_UPDATE에 따라 실제 업데이트 수행
            if [[ "$DO_UPDATE" != "Y" ]]; then
                STATUS="FAIL"
                ACTION_RESULT="FAIL"
                ACTION_LOG="조치가 수행되지 않았습니다. 최신 버전 확인 결과 업데이트가 필요하나, 자동 업데이트는 수행하지 않도록 설정되어 있습니다."
                EVIDENCE="${BASE_EVID} 업데이트 적용이 필요하며, DO_UPDATE=Y로 실행 시 패키지 업데이트를 수행할 수 있습니다."
            else
                # 실제 업데이트 수행
                UPGRADE_RC=1
                case "$PM" in
                    apt)
                        run_cmd "apt-get update -y" >/dev/null
                        run_cmd "DEBIAN_FRONTEND=noninteractive apt-get install -y ${PACKAGE_NAME}" >/dev/null
                        UPGRADE_RC=$?
                        ;;
                    dnf)
                        run_cmd "dnf -y upgrade ${PACKAGE_NAME}" >/dev/null
                        UPGRADE_RC=$?
                        ;;
                    yum)
                        run_cmd "yum -y update ${PACKAGE_NAME}" >/dev/null
                        UPGRADE_RC=$?
                        ;;
                    zypper)
                        run_cmd "zypper -n up ${PACKAGE_NAME}" >/dev/null
                        UPGRADE_RC=$?
                        ;;
                esac

                if [[ $UPGRADE_RC -ne 0 ]]; then
                    STATUS="FAIL"
                    ACTION_RESULT="FAIL"
                    ACTION_LOG="조치가 수행되지 않았습니다. MySQL 패키지 업데이트 수행에 실패하였습니다."
                    EVIDENCE="${BASE_EVID} 패키지 업데이트 명령 수행에 실패하여 보안 패치를 적용할 수 없습니다."
                else
                    # (선택) mysqld 재시작
                    if [[ "$RESTART_MYSQL" == "Y" ]]; then
                        # systemctl 우선, 없으면 service 시도
                        if command -v systemctl >/dev/null 2>&1; then
                            run_cmd "systemctl restart mysqld || systemctl restart mysql" >/dev/null
                        else
                            run_cmd "service mysqld restart || service mysql restart" >/dev/null
                        fi
                    fi

                    # 업데이트 후 버전 재확인
                    NEW_MYSQL_VER="$(run_mysql "SELECT VERSION();")"
                    if [[ -z "$NEW_MYSQL_VER" ]]; then
                        NEW_MYSQL_VER="확인되지 않음"
                    fi

                    STATUS="PASS"
                    ACTION_RESULT="SUCCESS"
                    ACTION_LOG="MySQL을 패키지 저장소 기준 최신 보안 패치 버전으로 업데이트하여 벤더 권고 사항을 적용하였습니다."
                    EVIDENCE="업데이트 전 MySQL 버전은 ${MYSQL_VERSION_RAW}였으며, 업데이트 후 버전은 ${NEW_MYSQL_VER}로 확인됩니다."
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
