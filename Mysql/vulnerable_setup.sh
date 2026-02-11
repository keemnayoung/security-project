#!/bin/bash
# ============================================================================
# Rocky Linux 9.7 - Oracle MySQL 8.0 취약 환경 구성 스크립트
# 목적: scripts/unix/6_db/mysql/check_*.sh 전 항목 FAIL 유도
# 주의: 로컬 소켓(/var/lib/mysql/mysql.sock) 미생성 환경에서도 동작하도록 TCP 접속 강제
# ============================================================================

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "[ERROR] root 권한으로 실행하세요."
  exit 1
fi

log()  { echo "[INFO] $*"; }
warn() { echo "[WARN] $*"; }

# MySQL 접속 옵션: 소켓 대신 TCP 강제 (2002 mysql.sock 오류 방지)
MYSQL_TCP_OPTS=(--protocol=tcp -h 127.0.0.1 -P 3306)

# 마지막에 서비스를 끌지 여부 (원래 스크립트 의도 유지: FAIL 유도 위해 중지)
STOP_MYSQL_AT_END=1

############################################
# 0. 기존 서비스 정리
############################################
log "기존 DB 서비스 중지(있으면)"
systemctl stop mariadb >/dev/null 2>&1 || true
systemctl disable mariadb >/dev/null 2>&1 || true
systemctl stop mysqld  >/dev/null 2>&1 || true
systemctl disable mysqld >/dev/null 2>&1 || true

############################################
# 1. MariaDB 완전 제거
############################################
log "MariaDB 제거"
dnf remove -y mariadb mariadb-server >/dev/null 2>&1 || true

############################################
# 1-1. MySQL 데이터/로그 초기화 (취약환경용)
############################################
log "MySQL 데이터 디렉토리 및 로그 초기화"
rm -rf /var/lib/mysql
rm -f /var/log/mysqld.log

############################################
# 2. MySQL 8.0 공식 Repo 설치
############################################
log "MySQL 8.0 공식 Repo 설치"
dnf install -y https://repo.mysql.com/mysql80-community-release-el9.rpm >/dev/null

############################################
# 3. MySQL 8.0 서버 설치
############################################
log "MySQL 8.0 서버 설치"
dnf install -y mysql-community-server >/dev/null

############################################
# 3-1. 데이터 디렉토리 권한 설정 (mysqld가 초기화하면서 생성)
############################################
log "데이터 디렉토리 권한 선설정(없으면 생성)"
mkdir -p /var/lib/mysql
chown -R mysql:mysql /var/lib/mysql
chmod 750 /var/lib/mysql

############################################
# 4. MySQL 서비스 시작
############################################
log "mysqld 서비스 시작"
systemctl enable --now mysqld >/dev/null

############################################
# 4-1. 기동 대기 (TCP로 ping)
############################################
log "MySQL 기동 대기(최대 30초)"
for i in {1..30}; do
  if mysqladmin "${MYSQL_TCP_OPTS[@]}" ping >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if ! mysqladmin "${MYSQL_TCP_OPTS[@]}" ping >/dev/null 2>&1; then
  warn "MySQL이 정상 기동되지 않았습니다. 로그를 확인하세요."
  journalctl -u mysqld -xe --no-pager | tail -n 120 || true
  [[ -f /var/log/mysqld.log ]] && tail -n 120 /var/log/mysqld.log || true
  exit 1
fi

############################################
# 5. root 임시 비밀번호 획득
############################################
log "root 임시 비밀번호 확인"
TMP_PW="$(grep -i 'temporary password' /var/log/mysqld.log 2>/dev/null | awk '{print $NF}' | tail -1 || true)"

if [[ -z "${TMP_PW}" ]]; then
  warn "임시 비밀번호 확인 실패(/var/log/mysqld.log 확인 필요)"
  [[ -f /var/log/mysqld.log ]] && tail -n 80 /var/log/mysqld.log || true
  exit 1
fi

############################################
# 6. root 비밀번호 약하게 변경 (1820/1819 대응)
############################################
log "root 비밀번호 취약하게 설정(2단계: 강한 비번 → 정책 완화 → 약한 비번)"

# 6-1) 1차: expired 상태 해제용 '강한 비밀번호'로 먼저 변경(정책 통과 목적)
STRONG_PW='TempStrong1!Aa'

mysql "${MYSQL_TCP_OPTS[@]}" --connect-expired-password -uroot -p"${TMP_PW}" <<EOF
ALTER USER 'root'@'localhost' IDENTIFIED BY '${STRONG_PW}';
FLUSH PRIVILEGES;
EOF

# 6-2) 2차: 강한 비번으로 다시 접속해서 정책 완화 후, 약한 비번으로 변경
# validate_password 변수명 차이 대응(점 있는/없는 버전 모두)
VP_VARS="$(mysql "${MYSQL_TCP_OPTS[@]}" -uroot -p"${STRONG_PW}" -Nse "SHOW VARIABLES LIKE 'validate_password%';" 2>/dev/null || true)"
RELAX_SQL=""

if echo "$VP_VARS" | grep -q "^validate_password\.policy"; then
  RELAX_SQL+=$'SET GLOBAL validate_password.policy=LOW;\n'
fi
if echo "$VP_VARS" | grep -q "^validate_password\.length"; then
  RELAX_SQL+=$'SET GLOBAL validate_password.length=4;\n'
fi
if echo "$VP_VARS" | grep -q "^validate_password_policy"; then
  RELAX_SQL+=$'SET GLOBAL validate_password_policy=LOW;\n'
fi
if echo "$VP_VARS" | grep -q "^validate_password_length"; then
  RELAX_SQL+=$'SET GLOBAL validate_password_length=4;\n'
fi

mysql "${MYSQL_TCP_OPTS[@]}" -uroot -p"${STRONG_PW}" <<EOF
${RELAX_SQL}
ALTER USER 'root'@'localhost' IDENTIFIED BY 'root123!';
FLUSH PRIVILEGES;
EOF

############################################
# 7. 취약 DB / 테이블 생성
############################################
log "취약 DB 및 테이블 생성"
mysql "${MYSQL_TCP_OPTS[@]}" -uroot -p'root123!' <<'EOF'
CREATE DATABASE IF NOT EXISTS vuln_db;
USE vuln_db;

CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50),
  password VARCHAR(50)
);

INSERT INTO users(username,password) VALUES
('admin','admin123'),
('test','test123');
EOF

############################################
# 8. 취약 계정 생성 (공용 / 원격 접속)
############################################
log "취약 계정 생성"
mysql "${MYSQL_TCP_OPTS[@]}" -uroot -p'root123!' <<'EOF'
CREATE USER IF NOT EXISTS 'admin'@'%'  IDENTIFIED BY 'admin123!';
CREATE USER IF NOT EXISTS 'guest'@'%'  IDENTIFIED BY 'guest123!';
CREATE USER IF NOT EXISTS 'test'@'%'   IDENTIFIED BY 'test123!';
CREATE USER IF NOT EXISTS 'appuser'@'%' IDENTIFIED BY 'app123!';

GRANT ALL PRIVILEGES ON *.* TO 'admin'@'%' WITH GRANT OPTION;
GRANT SELECT ON mysql.* TO 'guest'@'%';
GRANT SELECT,INSERT,UPDATE,DELETE ON vuln_db.* TO 'appuser'@'%';

FLUSH PRIVILEGES;
EOF

############################################
# 9. 보안 설정 의도적 미적용 (설정 파일로 일부 명시)
############################################
log "보안 설정 미적용(취약 설정 일부 반영)"
# 필요 시 원격 점검 FAIL 유도 위해 bind-address 열어둠(환경에 따라)
# 단, 방화벽/SELinux 설정에 따라 외부 접속은 별도 조치 필요할 수 있음.
cat >/etc/my.cnf.d/zz-vuln.cnf <<'EOF'
[mysqld]
# 원격 접속 가능하게(취약)
bind-address=0.0.0.0

# TLS 강제 안 함(취약)
require_secure_transport=OFF

# 로깅/감사 설정 미적용(취약 의도)
# general_log=OFF
# audit_log=OFF
EOF

systemctl restart mysqld >/dev/null

############################################
# 10. 전체 FAIL 유도용 서비스 중지(원래 의도 유지)
############################################
if [[ "${STOP_MYSQL_AT_END}" -eq 1 ]]; then
  log "점검 FAIL 유도를 위해 MySQL 서비스 중지"
  systemctl stop mysqld >/dev/null
  systemctl disable mysqld >/dev/null
fi

############################################
# 완료
############################################
cat <<EOF
[DONE] MySQL 8.0 취약 환경 구성 완료

- OS        : Rocky Linux 9.7
- DBMS      : Oracle MySQL 8.0
- 목적      : check_D01 ~ D25 FAIL 유도
- 상태 요약 :
  * 취약 계정 존재(admin/guest/test/appuser)
  * 약한 비밀번호(root123!, admin123!, guest123! ...)
  * 원격 접속 허용 설정(bind-address=0.0.0.0)
  * SSL/TLS 강제 미적용(require_secure_transport=OFF)
  * 감사 로그 / 계정 잠금 정책 미설정
  * mysqld 서비스: $( [[ "${STOP_MYSQL_AT_END}" -eq 1 ]] && echo "중지/비활성화" || echo "실행 중" )

[점검 실행 예시]
cd scripts/unix/6_db/mysql
bash 1_account/check_D01.sh
bash 1_account/check_D07.sh

[참고]
- 스크립트는 mysql.sock(로컬 소켓)을 사용하지 않고 TCP(127.0.0.1:3306)로 접속합니다.
- 만약 점검 스크립트가 DB 접속이 필요하다면, STOP_MYSQL_AT_END=0으로 바꾸고 실행하세요.

EOF
