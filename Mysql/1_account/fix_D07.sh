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
# @Platform    : MySQL 8.0.44
# @IMPORTANCE  : 중
# @Title       : root 권한으로 서비스 구동 제한
# @Description : DBMS 서비스가 root 권한이 아닌 전용 계정으로 실행되는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

ID="D-07"
CATEGORY="계정관리"
TITLE="root 권한으로 서비스 구동 제한"
IMPORTANCE="중"
IMPACT_LEVEL="LOW"
ACTION_IMPACT="이 조치를 적용하면 MySQL 서버가 지정된 일반 사용자 계정으로 실행되도록 설정이 변경됩니다. 일반적인 시스템 운영에는 영향이 없으며, 서버 시작 및 데이터베이스 접근에도 문제를 일으키지 않습니다. 다만, 서버 구동 사용자 계정 변경 후 파일 권한이나 소유권이 올바르게 설정되어 있는지 확인해야 합니다."

# 조치 결과 변수
STATUS="FAIL"
ACTION_RESULT="FAIL"
ACTION_LOG="N/A"
EVIDENCE="N/A"

# 무한 로딩 방지(프로세스/파일 조작은 빠르지만 형식 통일)
TIMEOUT_BIN="$(command -v timeout 2>/dev/null)"
CMD_TIMEOUT_SEC=5

run_cmd() {
    # 사용: run_cmd "명령"
    local cmd="$1"
    if [[ -n "$TIMEOUT_BIN" ]]; then
        $TIMEOUT_BIN ${CMD_TIMEOUT_SEC}s bash -lc "$cmd" 2>/dev/null
        return $?
    else
        bash -lc "$cmd" 2>/dev/null
        return $?
    fi
}

# 0) 설정값(환경변수로 조정 가능)
# MySQL을 구동할 일반 사용자 계정(기본: mysql)
MYSQL_RUN_USER="${MYSQL_RUN_USER:-mysql}"

# 설정 파일 위치를 지정하려면 MY_CNF 사용
# 예) MY_CNF="/etc/mysql/my.cnf" ./FIX_D07.sh
MY_CNF="${MY_CNF:-}"

# 1) 실행 중 프로세스 확인 (root 구동 여부)
# mysqld 프로세스가 없으면 조치 대상이 아닐 수 있으나, 설정은 사전 반영 가능하므로 계속 진행
PROC_USER="$(run_cmd "ps -eo user,comm | awk '\$2==\"mysqld\"{print \$1; exit}'")"
RC1=$?

if [[ $RC1 -eq 124 ]]; then
    STATUS="FAIL"
    ACTION_RESULT="FAIL"
    ACTION_LOG="조치가 수행되지 않았습니다. 프로세스 확인 명령이 제한 시간 내 완료되지 않아 중단하였습니다."
    EVIDENCE="프로세스 확인 명령 실행이 ${CMD_TIMEOUT_SEC}초 내에 완료되지 않아 무한 로딩 방지를 위해 처리를 중단하였습니다."
else
    # 프로세스가 실행 중이 아닌 경우 PROC_USER는 비어있을 수 있음
    if [[ -n "$PROC_USER" && "$PROC_USER" == "root" ]]; then
        NEED_FIX="Y"
        PROC_EVID="현재 mysqld 프로세스가 root 권한으로 실행되고 있어 권한 남용 위험이 있습니다."
    else
        NEED_FIX="N"
        if [[ -n "$PROC_USER" ]]; then
            PROC_EVID="현재 mysqld 프로세스가 ${PROC_USER} 계정으로 실행되고 있습니다."
        else
            PROC_EVID="현재 mysqld 프로세스가 실행 중인지 확인되지 않으나, 설정 파일 기준으로 구동 계정을 점검합니다."
        fi
    fi
fi

# 2) 설정 파일 탐지 및 [mysqld] user 지시자 확인
detect_cnf() {
    # 우선순위: 사용자가 지정(MY_CNF) > 일반 경로 탐지
    if [[ -n "$MY_CNF" && -f "$MY_CNF" ]]; then
        echo "$MY_CNF"
        return 0
    fi

    # 대표 경로 후보(환경별)
    local candidates=(
        "/etc/my.cnf"
        "/etc/mysql/my.cnf"
        "/etc/mysql/mysql.conf.d/mysqld.cnf"
        "/etc/my.cnf.d/mysql-server.cnf"
        "/etc/my.cnf.d/mysqld.cnf"
        "/etc/mysql/conf.d/my.cnf"
    )

    for f in "${candidates[@]}"; do
        if [[ -f "$f" ]]; then
            echo "$f"
            return 0
        fi
    done

    return 1
}

CNF_FILE="$(detect_cnf)"
if [[ -z "$CNF_FILE" ]]; then
    STATUS="FAIL"
    ACTION_RESULT="FAIL"
    ACTION_LOG="조치가 수행되지 않았습니다. MySQL 설정 파일을 자동으로 찾을 수 없습니다."
    EVIDENCE="${PROC_EVID} MySQL 설정 파일 경로를 MY_CNF 환경변수로 지정해야 합니다."
else
    # [mysqld] 섹션에서 user 지시자 값 추출(주석 제외)
    # - [mysqld] 시작 후 다음 [섹션] 전까지 탐색
    CNF_USER="$(run_cmd "awk '
        BEGIN{in=0}
        /^\[mysqld\]/{in=1; next}
        /^\[/{in=0}
        in==1 && \$0 ~ /^[[:space:]]*user[[:space:]]*=/ {
            line=\$0
            sub(/^[[:space:]]*/, \"\", line)
            if(line !~ /^user[[:space:]]*=[[:space:]]*#/){
                split(line,a,\"=\"); gsub(/[[:space:]]/,\"\",a[2]); print a[2]; exit
            }
        }
    ' \"$CNF_FILE\"")"
    RC2=$?

    if [[ $RC2 -eq 124 ]]; then
        STATUS="FAIL"
        ACTION_RESULT="FAIL"
        ACTION_LOG="조치가 수행되지 않았습니다. 설정 파일 확인 명령이 제한 시간 내 완료되지 않아 중단하였습니다."
        EVIDENCE="설정 파일 확인 명령 실행이 ${CMD_TIMEOUT_SEC}초 내에 완료되지 않아 무한 로딩 방지를 위해 처리를 중단하였습니다."
    else
        # user 지시자가 없거나 root로 되어 있으면 조치 필요
        if [[ -z "$CNF_USER" ]]; then
            NEED_FIX="Y"
            CNF_EVID="MySQL 설정 파일(${CNF_FILE})의 [mysqld] 섹션에 user 지시자가 설정되어 있지 않습니다."
        elif [[ "$CNF_USER" == "root" ]]; then
            NEED_FIX="Y"
            CNF_EVID="MySQL 설정 파일(${CNF_FILE})의 [mysqld] user 값이 root로 설정되어 있어 권한 남용 위험이 있습니다."
        else
            CNF_EVID="MySQL 설정 파일(${CNF_FILE})의 [mysqld] user 값이 ${CNF_USER}로 설정되어 있습니다."
        fi

        # 3) [mysqld] user 지시자 설정(필요 시)
        if [[ "${NEED_FIX}" != "Y" ]]; then
            STATUS="PASS"
            ACTION_RESULT="SUCCESS"
            ACTION_LOG="MySQL 서버가 root 권한으로 구동되지 않도록 설정되어 있어 추가 조치 없이 보안 설정을 유지하였습니다."
            EVIDENCE="${PROC_EVID} ${CNF_EVID}"
        else
            # 조치 전 백업
            BACKUP_FILE="${CNF_FILE}.bak_$(date '+%Y%m%d%H%M%S')"
            run_cmd "cp -p \"$CNF_FILE\" \"$BACKUP_FILE\""
            RC3=$?

            if [[ $RC3 -ne 0 ]]; then
                STATUS="FAIL"
                ACTION_RESULT="FAIL"
                ACTION_LOG="조치가 수행되지 않았습니다. 설정 파일 백업에 실패하였습니다."
                EVIDENCE="${PROC_EVID} ${CNF_EVID} 설정 파일 백업에 실패하여 안전을 위해 조치를 중단하였습니다."
            else
                # [mysqld] 섹션 내 user= 라인이 있으면 교체, 없으면 [mysqld] 다음 줄에 추가
                # sed -i는 플랫폼 차이가 있어 임시 파일 방식 사용
                TMP_FILE="$(mktemp)"

                run_cmd "awk -v newuser=\"${MYSQL_RUN_USER}\" '
                    BEGIN{in=0; done=0}
                    {
                        if(\$0 ~ /^\[mysqld\]/){in=1; print; next}
                        if(\$0 ~ /^\[/ && \$0 !~ /^\[mysqld\]/){
                            if(in==1 && done==0){
                                print \"user=\" newuser
                                done=1
                            }
                            in=0
                        }
                        if(in==1 && \$0 ~ /^[[:space:]]*user[[:space:]]*=/ && done==0){
                            print \"user=\" newuser
                            done=1
                            next
                        }
                        print
                    }
                    END{
                        if(in==1 && done==0){
                            print \"user=\" newuser
                        }
                    }
                ' \"$CNF_FILE\" > \"$TMP_FILE\" && mv \"$TMP_FILE\" \"$CNF_FILE\""
                RC4=$?

                if [[ $RC4 -eq 124 ]]; then
                    STATUS="FAIL"
                    ACTION_RESULT="FAIL"
                    ACTION_LOG="조치가 수행되지 않았습니다. 설정 파일 수정 명령이 제한 시간 내 완료되지 않아 중단하였습니다."
                    EVIDENCE="설정 파일 수정 명령 실행이 ${CMD_TIMEOUT_SEC}초 내에 완료되지 않아 무한 로딩 방지를 위해 처리를 중단하였습니다."
                elif [[ $RC4 -ne 0 ]]; then
                    STATUS="FAIL"
                    ACTION_RESULT="FAIL"
                    ACTION_LOG="조치가 수행되지 않았습니다. MySQL 구동 계정 설정 변경에 실패하였습니다."
                    EVIDENCE="${PROC_EVID} ${CNF_EVID} 설정 파일 수정에 실패하여 구동 계정 변경을 완료할 수 없습니다."
                else
                    STATUS="PASS"
                    ACTION_RESULT="SUCCESS"
                    ACTION_LOG="MySQL 서버가 root 권한으로 구동되지 않도록 [mysqld] 구동 계정을 일반 사용자(${MYSQL_RUN_USER})로 설정하였습니다."
                    EVIDENCE="${PROC_EVID} ${CNF_EVID} 설정 파일(${CNF_FILE})에 user=${MYSQL_RUN_USER} 설정을 적용하였습니다."
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


