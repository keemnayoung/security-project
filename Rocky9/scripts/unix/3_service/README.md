# 3_service 보안 점검 및 조치 가이드 (U-34 ~ U-63)

## 📋 개요

이 디렉토리는 KISA 2026 보안 가이드라인에 따른 **서비스 관리(3_service)** 카테고리의 보안 점검 및 자동 조치 스크립트를 포함합니다.

- **점검 항목**: U-34 ~ U-63 (총 30개)
- **구성**: 각 항목당 `check_*.sh` (점검), `fix_*.sh` (조치) 스크립트
- **자동화 수준**: 23개 완전 자동화, 7개 부분 자동화 (수동 확정 필요)

---

## 🎯 스크립트 동작 방식

### Check 스크립트 (`check_*.sh`)
1. **점검 수행**: 시스템 상태를 점검하여 취약 여부 판단
2. **결과 출력**: JSON 형식으로 점검 결과 반환
   - `status`: `PASS` (양호) / `FAIL` (취약)
   - `evidence`: 구체적인 점검 증거
   - `guide`: 조치 가이드
   - `action_result`: `SUCCESS` / `AUTO` / `MANUAL_REQUIRED`

### Fix 스크립트 (`fix_*.sh`)
1. **자동 조치**: 가능한 경우 자동으로 보안 설정 적용
2. **검증**: 조치 후 실제 상태를 재확인하여 성공 여부 판단
3. **결과 출력**: JSON 형식으로 조치 결과 반환
   - `action_result`: `SUCCESS` / `MANUAL` / `FAIL`
   - `action_log`: 수행한 조치 내역

---

## 📊 항목별 시나리오

### 🔹 U-34: Finger 서비스 비활성화

**Check**
- `/etc/inetd.conf`, `/etc/xinetd.d/finger` 확인
- Finger 서비스가 활성화되어 있으면 `FAIL`

**Fix**
- `xinetd`: disable=yes 설정 후 재시작
- `inetd`: 해당 라인 주석 처리 후 재시작
- **자동화**: ✅ 완전 자동

---

### 🔹 U-35: 익명 FTP 비활성화

**Check**
- FTP/NFS/Samba에서 anonymous 접근 허용 여부 확인
- `/etc/passwd`의 ftp, anonymous 계정 확인
- vsFTPd/ProFTPd/NFS/Samba 설정 점검

**Fix**
- vsFTPd: `anonymous_enable=NO`
- ProFTPd: Anonymous 블록 주석 처리
- NFS: anonuid/anongid 옵션 제거
- Samba: `guest ok = no`
- **자동화**: ✅ 완전 자동 (일부 환경 수동 확인)

---

### 🔹 U-36: r 계열 서비스 비활성화

**Check**
- rsh, rlogin, rexec 서비스 활성화 여부 확인

**Fix**
- 해당 서비스들 stop 및 disable
- **자동화**: ✅ 완전 자동

---

### 🔹 U-37: cron 접근 제어

**Check**
- `/etc/cron.allow`, `/etc/cron.deny`, `/etc/at.allow`, `/etc/at.deny`
- 소유자가 root인지, 권한이 640 이하인지 확인

**Fix**
- 소유자를 root로 변경
- 권한을 640 이하로 보정
- **자동화**: ✅ 완전 자동

---

### 🔹 U-38: DoS 공격 취약 서비스 비활성화

**Check**
- inetd/xinetd에서 echo, discard, daytime, chargen 서비스 확인

**Fix**
- 취약 서비스들을 disable 설정
- **자동화**: ✅ 완전 자동

---

### 🔹 U-39: NFS 서비스 비활성화

**Check**
- nfs-server 서비스 활성화 여부 확인

**Fix**
- NFS 서비스 stop 및 disable
- **자동화**: ✅ 완전 자동

---

### 🔹 U-40: NFS 접근 통제 ⚠️

**Check**
- `/etc/exports`의 공유 권한 점검
- everyone(*) 권한 확인

**Fix**
- 소유자 root, 권한 644로 변경
- everyone(*)을 127.0.0.1(로컬)로 자동 변경
- exportfs -ra 실행
- **자동화**: ✅ 기본 로컬 제한 자동 설정

**📍 수동 확정 항목**: 특정 네트워크에서 NFS 접근이 필요한 경우
```bash
# /etc/exports
/share 192.168.1.0/24 (ro,root_squash)
```

---

### 🔹 U-41: automountd 제거

**Check**
- automount 서비스 활성화 여부 확인

**Fix**
- automount 서비스 stop 및 disable
- **자동화**: ✅ 완전 자동

---

### 🔹 U-42: RPC 서비스 확인

**Check**
- rpcbind 등 RPC 관련 서비스 확인

**Fix**
- 불필요한 RPC 서비스 비활성화
- **자동화**: ✅ 완전 자동

---

### 🔹 U-43: NIS/NIS+ 점검

**Check**
- NIS/NIS+ 서비스 활성화 여부 확인

**Fix**
- NIS/NIS+ 서비스 비활성화 및 설정 정리
- **자동화**: ✅ 완전 자동

---

### 🔹 U-44: tftp, talk 서비스 비활성화

**Check**
- tftp, talk, ntalk 서비스 활성화 여부 확인

**Fix**
- 해당 서비스들 비활성화
- **자동화**: ✅ 완전 자동

---

### 🔹 U-45: 메일 서비스 버전 점검 ⚠️

**Check**
- sendmail, postfix, exim 버전 확인
- **요구 버전** (각 메일 서비스별):
  - Sendmail: 8.18.2 이상
  - Postfix: 3.10.7 이상
  - Exim: 4.99.1 이상
- 실행 중 + 해당 메일 서비스 요구 버전 미만 → `FAIL` + `MANUAL_REQUIRED`

**Fix**
- 미사용: 자동 중지 (주석 처리됨 - 현재 미구현)
- **사용 중**: 수동 패치 필요
- **자동화**: ⚠️ **수동 필수** (MANUAL_REQUIRED)

**📍 수동 확정 항목**: 사용 중인 메일 서비스의 최신 보안 패치 적용
```bash
# Sendmail 패치
dnf update sendmail
systemctl restart sendmail

# Postfix 패치
dnf update postfix
systemctl restart postfix

# Exim 패치
dnf update exim
systemctl restart exim4
```

**⚙️ 버전 설정 변경**
```bash
# check_U45.sh 파일 수정
SENDMAIL_REQUIRED_VERSION="8.18.2"
POSTFIX_REQUIRED_VERSION="3.10.7"
EXIM_REQUIRED_VERSION="4.99.1"
```

---

### 🔹 U-46: 메일 실행 제한

**Check**
- sendmail Privacy 옵션 확인

**Fix**
- Privacy 옵션 보정 (goaway, noexpn, novrfy 등)
- **자동화**: ✅ 완전 자동

---

### 🔹 U-47: 릴레이 제한

**Check**
- sendmail, postfix, exim의 릴레이 제한 규칙 확인

**Fix**
- Sendmail: access 파일에 127.0.0.1 RELAY 설정
- Postfix: mynetworks = 127.0.0.0/8로 제한
- Exim: relay_from_hosts = 127.0.0.1로 제한
- **자동화**: ✅ 완전 자동

---

### 🔹 U-48: expn/vrfy 명령어 제한

**Check**
- SMTP expn, vrfy 명령어 제한 옵션 확인

**Fix**
- 서비스별 옵션 적용
- **자동화**: ✅ 완전 자동

---

### 🔹 U-49: DNS 보안 버전 패치 ⚠️

**Check**
- named(BIND) 버전 확인
- **요구 버전**: 9.20.18 (변수로 설정 가능)
- 실행 중 + 버전 9.20.18 미만 → `FAIL` + `MANUAL_REQUIRED`

**Fix**
- 미사용: 자동 중지 (주석 처리됨 - 현재 미구현)
- **사용 중**: 수동 패치 필요
- **자동화**: ⚠️ **수동 필수** (MANUAL_REQUIRED)

**📍 수동 확정 항목**: 사용 중인 BIND의 최신 보안 패치 적용
```bash
# 패치 적용
dnf update bind

# 서비스 재시작
systemctl restart named
```

**⚙️ 버전 설정 변경**
```bash
# check_U49.sh 파일 수정
REQUIRED_VERSION="9.20.18"  # 원하는 버전으로 변경
```

---

### 🔹 U-50: DNS Zone Transfer 설정 ⚠️

**Check**
- `allow-transfer` 설정 확인
- `any` 허용은 취약

**Fix**
- `allow-transfer { none; }`로 변경
- **자동화**: ✅ 기본값 none 자동 설정

**📍 수동 확정 항목**: Secondary DNS 서버가 있는 경우 해당 IP를 수동 지정
```bash
# named.conf
allow-transfer { <Secondary DNS IP>; };
```

---

### 🔹 U-51: DNS 동적 업데이트 설정 ⚠️

**Check**
- `allow-update` 설정 확인
- `any` 허용은 취약

**Fix**
- `allow-update { none; }`로 변경
- **자동화**: ✅ 기본값 none 자동 설정

**📍 수동 확정 항목**: 동적 업데이트가 필요한 경우 허용 IP를 수동 지정
```bash
# named.conf
allow-update { <허용할 IP>; };
```

---

### 🔹 U-52: 텔넷(Telnet) 서비스 비활성화

**Check**
- telnet 서비스 활성화 여부 확인

**Fix**
- telnet 비활성화 및 SSH 확인
- **자동화**: ✅ 완전 자동

---

### 🔹 U-53: FTP 서비스 확인

**Check**
- FTP 배너의 버전 정보 노출 여부 확인

**Fix**
- ftpd_banner 설정 추가
- **자동화**: ✅ 완전 자동

---

### 🔹 U-54: 평문 FTP 비활성화

**Check**
- FTP 서비스 활성화 여부 확인

**Fix**
- FTP 서비스 비활성화
- **자동화**: ✅ 완전 자동

---

### 🔹 U-55: ftp 계정 쉘 제한

**Check**
- FTP 사용자 계정의 로그인 쉘 확인

**Fix**
- 쉘을 `/bin/false` 또는 `/sbin/nologin`으로 변경
- **자동화**: ✅ 완전 자동

---

### 🔹 U-56: FTP 서비스 접근 제어 ⚠️

**Check**
- ftpusers, user_list, hosts.allow/deny 확인
- root 차단 여부 및 권한 점검

**Fix**
- 기본 보정 (root 차단, 권한 640)
- **자동화**: ⚠️ 기본 보정 자동

**📍 수동 확정 항목**: 허용할 FTP 접근 IP/호스트 목록

---

### 🔹 U-57: ftpusers root 차단

**Check**
- ftpusers 파일 내 root 차단 규칙 확인

**Fix**
- ftpusers에 root 추가
- **자동화**: ✅ 완전 자동

---

### 🔹 U-58: SNMP 불필요 구동

**Check**
- snmpd 서비스 활성화 여부 확인

**Fix**
- SNMP 서비스 stop 및 disable
- **자동화**: ✅ 완전 자동

---

### 🔹 U-59: SNMP 버전 ⚠️

**Check**
- SNMP v3 사용 여부 확인 (rouser, rwuser, createUser 설정)
- v2 이하(Community String)만 사용 시 취약

**Fix**
- v2c Community String 주석 처리 (자동)
- SNMP 서비스 중지 및 비활성화 (자동)
- **자동화**: ⚠️ 부분 자동

**📍 수동 확정 항목**: SNMPv3 필요 시 v3 사용자 생성
```bash
# 1. v3 사용자 생성
net-snmp-create-v3-user -ro -A <인증암호> -X <암호화암호> -a SHA -x AES <사용자명>

# 2. 서비스 시작
systemctl start snmpd
systemctl enable snmpd

# 3. v3 동작 확인
snmpwalk -v3 -l authPriv -u <사용자명> -a SHA -A <인증암호> -x AES -X <암호화암호> 127.0.0.1
```

---

### 🔹 U-60: SNMP Community String 복잡성 ⚠️

**Check**
- SNMP 서비스 사용 여부 확인
- **미사용**: `FAIL` (중지/비활성화 필요)
- **사용 중 + 취약 community string**: `FAIL` + `MANUAL_REQUIRED`

**Fix**
- **미사용**: 자동 중지 및 비활성화
- **사용 중 취약**: 수동 조치 필요
- **자동화**: ⚠️ 미사용은 자동, **사용 중은 수동 필수**

**📍 수동 확정 항목**: 사용 중인 경우 안전한 Community String 값
- 영문자+숫자 10자 이상 또는
- 영문자+숫자+특수문자 8자 이상

---

### 🔹 U-61: SNMP 접근 제어 ⚠️

**Check**
- com2sec에서 default 사용 여부 확인

**Fix**
- `default` → `127.0.0.1`로 변경 (로컬만 허용)
- **자동화**: ✅ 로컬 제한 자동 설정

**📍 수동 확정 항목**: 허용해야 할 SNMP 네트워크 대역
```bash
# snmpd.conf
com2sec <name> <네트워크 대역> <community string>
# 예: com2sec mynetwork 192.168.1.0/24 SecureString123
```

---

### 🔹 U-62: 로그인 경고 메시지

**Check**
- 시스템 및 서비스 배너 점검

**Fix**
- `/etc/motd`, `/etc/issue` 및 서비스별 배너 보정
- **자동화**: ✅ 완전 자동

---

### 🔹 U-63: sudo 접근 관리

**Check**
- `/etc/sudoers` 파일 권한 점검

**Fix**
- 소유자 root, 권한 440 이하로 보정
- **자동화**: ✅ 완전 자동

---

## 🔧 운영값 수동 확정이 필요한 항목 (3가지)

이 항목들은 자동 조치가 일부만 적용되며, 운영 환경에 맞게 수동 확정이 필요합니다.

| 항목 | 내용 | 수동 확정 사유 |
|------|------|---------------|
| **U-45** | 사용 중인 메일 서비스 버전 패치 | 서비스 영향도 평가 및 변경관리 절차 필요 |
| **U-49** | BIND(named) 버전 패치 | DNS 패치 적용 시 서비스 중단 위험 |
| **U-60** | Community String 값 | 안전한 복잡도의 새 Community String |

## 🔧 운영값 추후 수정 확정이 필요한 항목 (5가지)
| **U-40** | NFS 접근 허용 네트워크 대역 | 로컬 제한 후 NFS 접근이 필요한 네트워크 대역 |
| **U-50** | `ALLOW_TRANSFER_IP` | Secondary DNS 서버 IP 주소 |
| **U-51** | `ALLOW_UPDATE_IP` | 동적 업데이트 허용 IP 주소 |
| **U-56** | 허용 FTP IP/호스트 | FTP 접근이 필요한 IP/호스트 목록 |
| **U-59** | SNMPv3 사용자 설정 | 인증/암호화 프로토콜 및 실제 비밀번호 설정 |
| **U-61** | 허용 SNMP 네트워크 대역 | SNMP 모니터링이 필요한 네트워크 대역 |

---

## 📈 자동화 수준 통계

```
✅ 완전 자동화: 24개 항목
⚠️ 부분 자동화: 6개 항목 (수동 확정 필요)
📊 총 항목: 30개
```

**자동화율**: 80.0% (24/30)

---

