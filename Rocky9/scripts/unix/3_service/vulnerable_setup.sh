#!/bin/bash
# ============================================================================
# @Project: 시스템 보안 자동화 프로젝트
# @Version: 3.0.0
# @Author: 이가영
# @Last Updated: 2026-02-08
# ============================================================================
# [취약 환경 설정 스크립트 - Rocky Linux 9]
# @Description : U-34 ~ U-63 취약점 테스트를 위한 취약 환경 구성
# @Warning : 이 스크립트는 테스트 목적으로만 사용! 실제 운영 환경에서 실행 금지!
# @Reference : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${RED}======================================================================${NC}"
echo -e "${RED}  경고: 이 스크립트는 시스템을 의도적으로 취약하게 만듭니다!${NC}"
echo -e "${RED}  테스트 환경(VM)에서만 실행하세요!${NC}"
echo -e "${RED}  대상 OS: Rocky Linux 9${NC}"
echo -e "${RED}======================================================================${NC}"
echo ""
read -p "계속하시겠습니까? (yes/no): " CONFIRM
if [ "$CONFIRM" != "yes" ]; then
    echo "취소되었습니다."
    exit 1
fi

LOG_FILE="/var/log/vulnerable_setup_$(date +%Y%m%d_%H%M%S).log"
echo "설정 로그: $LOG_FILE"

log_action() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

# EPEL 저장소 활성화 (필수 패키지 설치용)
enable_epel() {
    log_action "EPEL 저장소 활성화..."
    dnf install -y epel-release 2>/dev/null
    dnf config-manager --set-enabled crb 2>/dev/null
}

# ============================================================================
# U-34: Finger 서비스 활성화
# 점검: /etc/xinetd.d/finger에서 disable = no 확인
# ============================================================================
setup_U34() {
    log_action "U-34: Finger 서비스 설정 중..."
    dnf install -y xinetd 2>/dev/null
    
    mkdir -p /etc/xinetd.d
    cat > /etc/xinetd.d/finger << 'EOF'
service finger
{
    disable         = no
    socket_type     = stream
    wait            = no
    user            = nobody
    server          = /usr/sbin/in.fingerd
}
EOF
    
    systemctl enable xinetd 2>/dev/null
    systemctl start xinetd 2>/dev/null
    log_action "U-34: /etc/xinetd.d/finger 생성 (disable = no)"
}

# ============================================================================
# U-35: 공유 서비스에 대한 익명 접근 허용
# 점검: vsFTPd anonymous_enable=YES, NFS everyone 공유
# ============================================================================
setup_U35() {
    log_action "U-35: 익명 접근 설정 중..."
    
    # vsFTPd 익명 접근
    dnf install -y vsftpd 2>/dev/null
    if [ -f "/etc/vsftpd/vsftpd.conf" ]; then
        sed -i 's/^anonymous_enable=.*/anonymous_enable=YES/' /etc/vsftpd/vsftpd.conf
        grep -q "^anonymous_enable" /etc/vsftpd/vsftpd.conf || echo "anonymous_enable=YES" >> /etc/vsftpd/vsftpd.conf
        systemctl enable vsftpd 2>/dev/null
        systemctl start vsftpd 2>/dev/null
    fi
    
    # NFS everyone 공유
    dnf install -y nfs-utils 2>/dev/null
    mkdir -p /export/public
    chmod 777 /export/public
    echo "/export/public *(rw,sync,no_root_squash,insecure)" >> /etc/exports
    systemctl enable nfs-server 2>/dev/null
    systemctl start nfs-server 2>/dev/null
    exportfs -ra 2>/dev/null
    
    log_action "U-35: vsFTPd anonymous_enable=YES, NFS everyone 공유 설정"
}

# ============================================================================
# U-36: r 계열 서비스 활성화
# 점검: xinetd.d에서 rsh, rlogin, rexec disable=no
# ============================================================================
setup_U36() {
    log_action "U-36: r 계열 서비스 설정 중..."
    dnf install -y xinetd 2>/dev/null
    
    # rsh 설정
    cat > /etc/xinetd.d/rsh << 'EOF'
service shell
{
    disable         = no
    socket_type     = stream
    wait            = no
    user            = root
    server          = /usr/sbin/in.rshd
}
EOF

    # rlogin 설정
    cat > /etc/xinetd.d/rlogin << 'EOF'
service login
{
    disable         = no
    socket_type     = stream
    wait            = no
    user            = root
    server          = /usr/sbin/in.rlogind
}
EOF

    # rexec 설정
    cat > /etc/xinetd.d/rexec << 'EOF'
service exec
{
    disable         = no
    socket_type     = stream
    wait            = no
    user            = root
    server          = /usr/sbin/in.rexecd
}
EOF

    echo "+ +" > /root/.rhosts
    echo "+ +" > /etc/hosts.equiv
    
    systemctl restart xinetd 2>/dev/null
    log_action "U-36: rsh, rlogin, rexec 서비스 설정 (disable = no)"
}

# ============================================================================
# U-37: crontab 설정파일 권한 취약
# 점검: /etc/crontab 권한이 640 초과
# ============================================================================
setup_U37() {
    log_action "U-37: crontab 취약 권한 설정 중..."
    
    chmod 777 /etc/crontab 2>/dev/null
    chmod 777 /etc/cron.d 2>/dev/null
    chmod 777 /etc/cron.daily 2>/dev/null
    chmod 777 /etc/cron.hourly 2>/dev/null
    chmod 777 /etc/cron.weekly 2>/dev/null
    chmod 777 /etc/cron.monthly 2>/dev/null
    
    log_action "U-37: /etc/crontab 권한 777 설정"
}

# ============================================================================
# U-38: DoS 공격에 취약한 서비스 활성화
# 점검: echo, discard, daytime, chargen 서비스 활성화
# ============================================================================
setup_U38() {
    log_action "U-38: DoS 취약 서비스 설정 중..."
    dnf install -y xinetd 2>/dev/null
    
    for svc in echo discard daytime chargen; do
        cat > /etc/xinetd.d/$svc << EOF
service $svc
{
    disable         = no
    type            = INTERNAL
    id              = ${svc}-stream
    socket_type     = stream
    protocol        = tcp
    wait            = no
}
EOF
    done
    
    systemctl restart xinetd 2>/dev/null
    log_action "U-38: echo, discard, daytime, chargen 서비스 설정 (disable = no)"
}

# ============================================================================
# U-39: 불필요한 NFS 서비스 활성화
# 점검: nfs-server 서비스 활성화 상태
# ============================================================================
setup_U39() {
    log_action "U-39: NFS 서비스 설정 중..."
    dnf install -y nfs-utils 2>/dev/null
    
    systemctl enable nfs-server 2>/dev/null
    systemctl start nfs-server 2>/dev/null
    
    log_action "U-39: nfs-server 서비스 활성화"
}

# ============================================================================
# U-40: NFS 접근 통제 미흡
# 점검: /etc/exports에 everyone(*) 공유 또는 insecure 옵션
# ============================================================================
setup_U40() {
    log_action "U-40: NFS 취약 접근 통제 설정 중..."
    
    mkdir -p /export/insecure
    chmod 777 /export/insecure
    echo "/export/insecure *(rw,sync,no_root_squash,insecure)" >> /etc/exports
    
    systemctl restart nfs-server 2>/dev/null
    exportfs -ra 2>/dev/null
    
    log_action "U-40: /etc/exports에 everyone(*) 및 insecure 옵션 설정"
}

# ============================================================================
# U-41: automountd 활성화
# 점검: autofs 서비스 활성화 상태
# ============================================================================
setup_U41() {
    log_action "U-41: automountd 설정 중..."
    dnf install -y autofs 2>/dev/null
    
    systemctl enable autofs 2>/dev/null
    systemctl start autofs 2>/dev/null
    
    log_action "U-41: autofs 서비스 활성화"
}

# ============================================================================
# U-42: 불필요한 RPC 서비스 활성화
# 점검: rpcbind 서비스 활성화 상태
# ============================================================================
setup_U42() {
    log_action "U-42: RPC 서비스 설정 중..."
    dnf install -y rpcbind 2>/dev/null
    
    systemctl enable rpcbind 2>/dev/null
    systemctl start rpcbind 2>/dev/null
    
    log_action "U-42: rpcbind 서비스 활성화"
}

# ============================================================================
# U-43: NIS 서비스 활성화
# 점검: ypserv, ypbind 서비스 활성화 상태
# 주의: Rocky Linux 9에서는 NIS 패키지(ypserv, ypbind)가 제공되지 않음
# ============================================================================
setup_U43() {
    log_action "U-43: NIS 서비스 설정 중... (Rocky Linux 9에서는 NIS 패키지 미제공)"
    # Rocky Linux 9에서는 ypserv, ypbind 패키지가 없음
    # 이 항목은 취약 환경 구축 불가 - PASS로 처리됨
    log_action "U-43: [SKIP] NIS 패키지 미지원 - 취약 환경 구축 불가"
}

# ============================================================================
# U-44: tftp, talk 서비스 활성화
# 점검: tftp 또는 talk 서비스 활성화 상태
# ============================================================================
setup_U44() {
    log_action "U-44: tftp, talk 서비스 설정 중..."
    dnf install -y tftp-server xinetd 2>/dev/null
    
    # tftp xinetd 설정
    cat > /etc/xinetd.d/tftp << 'EOF'
service tftp
{
    disable         = no
    socket_type     = dgram
    protocol        = udp
    wait            = yes
    user            = root
    server          = /usr/sbin/in.tftpd
    server_args     = -s /var/lib/tftpboot
}
EOF
    
    systemctl restart xinetd 2>/dev/null
    systemctl enable tftp.socket 2>/dev/null
    systemctl start tftp.socket 2>/dev/null
    
    log_action "U-44: tftp 서비스 설정 (disable = no)"
}

# ============================================================================
# U-45: sendmail 버전 점검
# 점검: sendmail 또는 postfix 서비스 활성화
# ============================================================================
setup_U45() {
    log_action "U-45: 메일 서비스 설정 중..."
    dnf install -y postfix 2>/dev/null
    
    systemctl enable postfix 2>/dev/null
    systemctl start postfix 2>/dev/null
    
    log_action "U-45: postfix 서비스 활성화"
}

# ============================================================================
# U-46: 일반 사용자의 sendmail 실행 방지 미흡
# 점검: sendmail 또는 postqueue에 SUID 비트 또는 일반 사용자 실행 가능
# ============================================================================
setup_U46() {
    log_action "U-46: sendmail 실행 권한 취약 설정 중..."
    
    if [ -f "/usr/sbin/sendmail" ]; then
        chmod 4755 /usr/sbin/sendmail 2>/dev/null
    fi
    if [ -f "/usr/sbin/postqueue" ]; then
        chmod 4755 /usr/sbin/postqueue 2>/dev/null
    fi
    
    log_action "U-46: sendmail/postqueue SUID 설정"
}

# ============================================================================
# U-47: 스팸 메일 릴레이 제한 미흡
# 점검: postfix mynetworks에 0.0.0.0/0 또는 모든 네트워크 허용
# ============================================================================
setup_U47() {
    log_action "U-47: 메일 릴레이 취약 설정 중..."
    
    if [ -f "/etc/postfix/main.cf" ]; then
        sed -i '/^mynetworks/d' /etc/postfix/main.cf
        echo "mynetworks = 0.0.0.0/0" >> /etc/postfix/main.cf
        systemctl restart postfix 2>/dev/null
    fi
    
    log_action "U-47: mynetworks = 0.0.0.0/0 설정"
}

# ============================================================================
# U-48: expn, vrfy 명령어 허용
# 점검: disable_vrfy_command = no 또는 미설정
# ============================================================================
setup_U48() {
    log_action "U-48: SMTP expn/vrfy 허용 설정 중..."
    
    if [ -f "/etc/postfix/main.cf" ]; then
        sed -i '/^disable_vrfy_command/d' /etc/postfix/main.cf
        echo "disable_vrfy_command = no" >> /etc/postfix/main.cf
        systemctl restart postfix 2>/dev/null
    fi
    
    log_action "U-48: disable_vrfy_command = no 설정"
}

# ============================================================================
# U-49: DNS 보안 버전 패치 미적용
# 점검: named 서비스 활성화 상태
# ============================================================================
setup_U49() {
    log_action "U-49: DNS 서비스 설정 중..."
    dnf install -y bind bind-utils 2>/dev/null
    
    systemctl enable named 2>/dev/null
    systemctl start named 2>/dev/null
    
    log_action "U-49: named 서비스 활성화"
}

# ============================================================================
# U-50: DNS Zone Transfer 취약
# 점검: allow-transfer { any; } 설정
# ============================================================================
setup_U50() {
    log_action "U-50: DNS Zone Transfer 취약 설정 중..."
    
    if [ -f "/etc/named.conf" ]; then
        # 기존 allow-transfer 제거
        sed -i '/allow-transfer/d' /etc/named.conf
        # options 블록에 allow-transfer { any; } 추가
        sed -i '/options {/a\        allow-transfer { any; };' /etc/named.conf
        systemctl restart named 2>/dev/null
    fi
    
    log_action "U-50: allow-transfer { any; } 설정"
}

# ============================================================================
# U-51: DNS 동적 업데이트 허용
# 점검: allow-update { any; } 설정
# ============================================================================
setup_U51() {
    log_action "U-51: DNS 동적 업데이트 허용 설정 중..."
    
    if [ -f "/etc/named.conf" ]; then
        # 기존 allow-update 제거
        sed -i '/allow-update/d' /etc/named.conf
        # options 블록에 allow-update { any; } 추가
        sed -i '/options {/a\        allow-update { any; };' /etc/named.conf
        systemctl restart named 2>/dev/null
    fi
    
    log_action "U-51: allow-update { any; } 설정"
}

# ============================================================================
# U-52: Telnet 서비스 활성화
# 점검: telnet 서비스 활성화 상태
# ============================================================================
setup_U52() {
    log_action "U-52: Telnet 서비스 설정 중..."
    dnf install -y telnet-server xinetd 2>/dev/null
    
    cat > /etc/xinetd.d/telnet << 'EOF'
service telnet
{
    disable         = no
    socket_type     = stream
    wait            = no
    user            = root
    server          = /usr/sbin/in.telnetd
}
EOF
    
    systemctl restart xinetd 2>/dev/null
    systemctl enable telnet.socket 2>/dev/null
    systemctl start telnet.socket 2>/dev/null
    
    log_action "U-52: telnet 서비스 설정 (disable = no)"
}

# ============================================================================
# U-53: FTP 서버 정보 노출
# 점검: ftpd_banner 미설정 또는 버전 정보 노출
# ============================================================================
setup_U53() {
    log_action "U-53: FTP 배너 제거 중..."
    
    if [ -f "/etc/vsftpd/vsftpd.conf" ]; then
        sed -i '/^ftpd_banner/d' /etc/vsftpd/vsftpd.conf
        # 배너 없음 = 기본 배너(버전 노출)
        systemctl restart vsftpd 2>/dev/null
    fi
    
    log_action "U-53: ftpd_banner 제거 (기본 배너 노출)"
}

# ============================================================================
# U-54: 암호화되지 않는 FTP 활성화
# 점검: ssl_enable=NO 또는 미설정
# ============================================================================
setup_U54() {
    log_action "U-54: 비암호화 FTP 설정 중..."
    
    if [ -f "/etc/vsftpd/vsftpd.conf" ]; then
        sed -i '/^ssl_enable/d' /etc/vsftpd/vsftpd.conf
        echo "ssl_enable=NO" >> /etc/vsftpd/vsftpd.conf
        systemctl restart vsftpd 2>/dev/null
    fi
    
    log_action "U-54: ssl_enable=NO 설정"
}

# ============================================================================
# U-55: FTP 계정 Shell 미제한
# 점검: ftp 계정 shell이 /bin/false, /sbin/nologin 아님
# ============================================================================
setup_U55() {
    log_action "U-55: FTP 계정 Shell 취약 설정 중..."
    
    if id ftp &>/dev/null; then
        usermod -s /bin/bash ftp 2>/dev/null
    else
        useradd -m -s /bin/bash ftp 2>/dev/null
        echo "ftp:ftp123" | chpasswd
    fi
    
    log_action "U-55: ftp 계정 shell을 /bin/bash로 설정"
}

# ============================================================================
# U-56: FTP 접근 제어 미설정 (ftpusers에서 root 제거)
# 점검: ftpusers 또는 user_list에 root 없음
# ============================================================================
setup_U56() {
    log_action "U-56: FTP ftpusers에서 root 제거..."
    
    if [ -f "/etc/vsftpd/ftpusers" ]; then
        sed -i '/^root$/d' /etc/vsftpd/ftpusers
    fi
    if [ -f "/etc/vsftpd/user_list" ]; then
        sed -i '/^root$/d' /etc/vsftpd/user_list
    fi
    systemctl restart vsftpd 2>/dev/null
    
    log_action "U-56: ftpusers, user_list에서 root 제거"
}

# ============================================================================
# U-57: ftpusers 파일 미설정
# 점검: /etc/ftpusers에 root 없음
# ============================================================================
setup_U57() {
    log_action "U-57: ftpusers 취약 설정 중..."
    
    # /etc/ftpusers 파일에서 root 제거
    if [ -f "/etc/ftpusers" ]; then
        sed -i '/^root$/d' /etc/ftpusers
    else
        touch /etc/ftpusers
    fi
    
    log_action "U-57: /etc/ftpusers에서 root 제거"
}

# ============================================================================
# U-58: SNMP 서비스 활성화
# 점검: snmpd 서비스 활성화 상태
# ============================================================================
setup_U58() {
    log_action "U-58: SNMP 서비스 설정 중..."
    dnf install -y net-snmp net-snmp-utils 2>/dev/null
    
    systemctl enable snmpd 2>/dev/null
    systemctl start snmpd 2>/dev/null
    
    log_action "U-58: snmpd 서비스 활성화"
}

# ============================================================================
# U-59: 안전하지 않은 SNMP 버전 사용
# 점검: SNMPv1/v2c 사용 (rocommunity, rwcommunity public/private)
# ============================================================================
setup_U59() {
    log_action "U-59: SNMPv1/v2c 설정 중..."
    
    if [ -f "/etc/snmp/snmpd.conf" ]; then
        # 기존 community 설정 제거 후 추가
        grep -q "^rocommunity public" /etc/snmp/snmpd.conf || echo "rocommunity public" >> /etc/snmp/snmpd.conf
        grep -q "^rwcommunity private" /etc/snmp/snmpd.conf || echo "rwcommunity private" >> /etc/snmp/snmpd.conf
        systemctl restart snmpd 2>/dev/null
    fi
    
    log_action "U-59: rocommunity public, rwcommunity private 설정"
}

# ============================================================================
# U-60: SNMP Community String 기본값 사용
# 점검: community string이 public 또는 private
# ============================================================================
setup_U60() {
    log_action "U-60: SNMP 기본 Community String 설정 중..."
    
    if [ -f "/etc/snmp/snmpd.conf" ]; then
        cat > /etc/snmp/snmpd.conf << 'EOF'
# 취약한 SNMP 설정
com2sec notConfigUser default public
group notConfigGroup v1 notConfigUser
group notConfigGroup v2c notConfigUser
view systemview included .1
access notConfigGroup "" any noauth exact systemview none none
rocommunity public
rwcommunity private
EOF
        systemctl restart snmpd 2>/dev/null
    fi
    
    log_action "U-60: com2sec default public 설정"
}

# ============================================================================
# U-61: SNMP 접근 제어 미설정
# 점검: com2sec에 default 사용 (모든 호스트 허용)
# ============================================================================
setup_U61() {
    log_action "U-61: SNMP 접근 제어 미설정 중..."
    
    # U-60에서 이미 설정됨 (com2sec default)
    if [ -f "/etc/snmp/snmpd.conf" ]; then
        sed -i 's/^agentAddress.*/agentAddress udp:0.0.0.0:161/' /etc/snmp/snmpd.conf
        grep -q "^agentAddress" /etc/snmp/snmpd.conf || echo "agentAddress udp:0.0.0.0:161" >> /etc/snmp/snmpd.conf
        systemctl restart snmpd 2>/dev/null
    fi
    
    log_action "U-61: agentAddress 0.0.0.0:161 설정 (모든 IP 허용)"
}

# ============================================================================
# U-62: 로그인 경고 메시지 미설정
# 점검: /etc/issue, /etc/motd 비어있거나 경고 메시지 없음
# ============================================================================
setup_U62() {
    log_action "U-62: 경고 메시지 제거 중..."
    
    echo "" > /etc/issue 2>/dev/null
    echo "" > /etc/issue.net 2>/dev/null
    echo "" > /etc/motd 2>/dev/null
    
    # SSH 배너 제거
    if [ -f "/etc/ssh/sshd_config" ]; then
        sed -i 's/^Banner/#Banner/g' /etc/ssh/sshd_config
        systemctl restart sshd 2>/dev/null
    fi
    
    log_action "U-62: /etc/issue, /etc/motd 비움, SSH Banner 주석처리"
}

# ============================================================================
# U-63: sudoers 파일 권한 취약
# 점검: /etc/sudoers 권한이 640 초과 또는 소유자가 root 아님
# ============================================================================
setup_U63() {
    log_action "U-63: sudoers 취약 설정 중..."
    
    # 주의: 실제로 sudoers 권한을 너무 변경하면 sudo 사용 불가
    # 테스트를 위해 권한만 변경 (소유자는 유지)
    chmod 644 /etc/sudoers 2>/dev/null
    
    log_action "U-63: /etc/sudoers 권한 644 설정"
}

# ============================================================================
# 메인 실행
# ============================================================================
echo ""
echo -e "${YELLOW}취약 환경 설정을 시작합니다... (Rocky Linux 9)${NC}"
echo ""

# EPEL 활성화
enable_epel

# dnf 업데이트
dnf update -y -q 2>/dev/null

# 각 취약점 설정
setup_U34
setup_U35
setup_U36
setup_U37
setup_U38
setup_U39
setup_U40
setup_U41
setup_U42
setup_U43
setup_U44
setup_U45
setup_U46
setup_U47
setup_U48
setup_U49
setup_U50
setup_U51
setup_U52
setup_U53
setup_U54
setup_U55
setup_U56
setup_U57
setup_U58
setup_U59
setup_U60
setup_U61
setup_U62
setup_U63

echo ""
echo -e "${GREEN}======================================================================${NC}"
echo -e "${GREEN}  취약 환경 설정 완료! (Rocky Linux 9)${NC}"
echo -e "${GREEN}  로그 파일: $LOG_FILE${NC}"
echo -e "${GREEN}======================================================================${NC}"
echo ""
echo -e "${YELLOW}설정된 취약점 요약:${NC}"
echo "  U-34: Finger 서비스 (xinetd disable=no)"
echo "  U-35: 익명 FTP/NFS 접근"
echo "  U-36: r 계열 서비스 (rsh, rlogin, rexec)"
echo "  U-37: crontab 권한 777"
echo "  U-38: DoS 취약 서비스 (echo, discard, daytime, chargen)"
echo "  U-39: NFS 서비스 활성화"
echo "  U-40: NFS everyone 공유"
echo "  U-41: autofs 서비스 활성화"
echo "  U-42: rpcbind 서비스 활성화"
echo "  U-43: NIS(ypserv/ypbind) 서비스 활성화"
echo "  U-44: tftp 서비스 활성화"
echo "  U-45: postfix 서비스 활성화"
echo "  U-46: sendmail SUID 설정"
echo "  U-47: 메일 릴레이 제한 없음"
echo "  U-48: SMTP vrfy 명령 허용"
echo "  U-49: DNS(named) 서비스 활성화"
echo "  U-50: DNS Zone Transfer 허용"
echo "  U-51: DNS 동적 업데이트 허용"
echo "  U-52: Telnet 서비스 활성화"
echo "  U-53: FTP 배너 미설정"
echo "  U-54: 비암호화 FTP"
echo "  U-55: FTP 계정 shell /bin/bash"
echo "  U-56: ftpusers에서 root 제거"
echo "  U-57: /etc/ftpusers에서 root 제거"
echo "  U-58: SNMP 서비스 활성화"
echo "  U-59: SNMPv1/v2c public/private"
echo "  U-60: SNMP community string 기본값"
echo "  U-61: SNMP 접근 제어 없음"
echo "  U-62: 로그인 경고 메시지 없음"
echo "  U-63: sudoers 권한 644"
echo ""
echo -e "${YELLOW}다음 단계:${NC}"
echo "  1. Ubuntu에서 점검 실행: ansible-playbook -i hosts run_audit.yml"
echo "  2. 대시보드에서 결과 확인"
echo ""
