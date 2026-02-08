# 🛡️ 시스템 보안 자동화 프로젝트 - 설치 및 실행 가이드

## 📁 프로젝트 및 디렉토리 구조

프로젝트 루트: `~/security_project/`

```bash
~/security_project/
├── .venv/                  # 파이썬 가상환경 (Streamlit 및 라이브러리 독립성 유지)
├── ansible.cfg             # 앤서블 설정 (Pipelining 활성화, scp_if_ssh=True 등 최적화)
├── dashboard.py            # [UI] Streamlit 기반 대시보드 및 시각화 로직
├── hosts                   # 타겟 서버 (Rocky 9, 10 등) 및 DB 그룹 관리 인벤토리
├── run_audit.yml           # [자동화] 전 서버 대상 보안 진단 스크립트 배포 및 결과 수집
├── run_fix.yml             # [자동화] 취약 항목에 대한 자동 조치 실행 플레이북
├── results/                # [JSON] 서버별/항목별 JSON 점검 결과 로그 저장소
├── fix_logs/               # [JSON] 조치 스크립트 실행 결과 및 성공/실패 로그 기록
└── scripts/                # 실제 점검 및 조치가 수행되는 쉘 스크립트 저장소
    └── unix/               # Unix 서버 취약점 진단
        ├── 1_account/      # 1. 계정 관리 스크립트 (U01~U13)
        ├── 2_directory/    # 2. 파일 및 디렉터리 관리 스크립트 (U14~U33)
        ├── 3_service/      # 3. 서비스 관리 스크립트 (U34~U63)
        ├── 4_patch/        # 4. 패치 관리 스크립트 (U64)
        ├── 5_logs/         # 5. 로그 관리 스크립트 (U65~U67)
        ├── 6_db/           # DBMS별 서버 취약점 진단
        │   ├── mysql/      # [Rocky 9 기반] MySQL 보안 관리
        │   └── postgresql/ # [Rocky 10 기반] PostgreSQL 보안 관리
        └── 7_patch/        # [OS별] Rocky 9 vs 10 버전별 커널 및 보안 패치 관리
```

---

## 🚀 Step 1: 사전 설정 (Ubuntu)

### 1.1 시스템 패키지 설치
```bash
sudo apt update && sudo apt install -y ansible python3-venv sshpass
```

### 1.2 Python 가상환경 생성 및 패키지 설치
**[실행 위치: 📂`~/security_project`]**

```bash
cd ~/security_project
# 가상환경 생성
python3 -m venv ~/security_project/.venv

# 가상환경 활성화
source ~/security_project/.venv/bin/activate

# Python 패키지 설치
pip install streamlit pandas plotly xlsxwriter
```

> ⚠️ **중요**: 대시보드 실행 전 항상 `source ~/security_project/.venv/bin/activate` 실행 필요!

### 1.3 SSH 키 설정
**[실행 위치: 🏠 홈 디렉터리 (`~`)]**
```bash
cd ~
ssh-keygen -t rsa -b 4096
ssh-copy-id <계정명>@<Rocky_IP>
```

---

## 🚀 Step 2: 인벤토리 설정

```bash
nano ~/security_project/hosts
```

```ini
```ini
[target_servers]
# 대상 서버 IP 및 접속 정보 (실제 환경에 맞게 수정)
# [옵션 1] SSH 키 인증 (권장) - 이미 키가 설정된 경우
Rocky-Target-01 ansible_host=192.168.182.128 ansible_user=audit_2026 ansible_become_pass=qwer1234

# [옵션 2] 비밀번호 인증 (sshpass 필요) - 키 설정이 안 된 경우 주석 해제
# Rocky-Target-01 ansible_host=192.168.182.128 ansible_user=audit_2026 ansible_ssh_pass=qwer1234 ansible_become_pass=qwer1234
```

### 연결 테스트
```bash
cd ~/security_project
ansible -i hosts target_servers -m ping
```

---

##  Step 3: 보안 점검 워크플로우

### 1단계: 최초 보안 진단 (Audit)
Ubuntu에 있는 점검 스크립트를 원격 서버(Rocky)에서 직접 실행하고, 결과를 가져옵니다. (`run_audit.yml`)
**[실행 위치: 📂 `~/security_project` | 🐍 가상환경 불필요]**
```bash
# 전체 진단 실행
cd ~/security_project
ansible-playbook -i hosts run_audit.yml

# (선택) 특정 항목만 진단 (예: U-59)
# ansible-playbook -i hosts run_audit.yml -e "target_id=U59"
```

### 2단계: 취약점 자동 조치 (Remediation)
발견된 취약점을 자동으로 수정하고 보안 설정을 강화합니다.
**[실행 위치: 📂 `~/security_project` | 🐍 가상환경 불필요]**
> `run_fix.yml`은 **`target_id` 변수가 필수**입니다! (단일 항목 조치 전용)

```bash
cd ~/security_project
# 예: U-59 항목 조치
ansible-playbook -i hosts run_fix.yml -e "target_id=U59"
```

### 3단계: ★ 결과 확인을 위한 재진단 ★
> ⚠️ **이 과정을 생략하면 대시보드 데이터가 갱신되지 않습니다!**
**[실행 위치: 📂 `~/security_project`]**
```bash
cd ~/security_project
ansible-playbook -i hosts run_audit.yml
```

---

##  Step 4: 대시보드 실행

**[실행 위치: 📂 `~/security_project` | 🐍 가상환경 필수!]**

```bash
cd ~/security_project
# 가상환경 활성화 (필수)
source .venv/bin/activate

# Streamlit 실행
streamlit run dashboard.py --server.port 8501

# (사용 종료 시) 대시보드 중단(Ctrl+C) 후 가상환경 해제
deactivate
```

브라우저: `http://localhost:8501`
*대시보드에서 '승인 후 조치' 버튼 클릭 시 `run_fix.yml`이 자동으로 실행됩니다.*

---

## � 대시보드가 읽는 JSON 형식

```json
{
    "check_id": "U34",
    "category": "서비스관리",
    "title": "Finger 서비스 비활성화",
    "importance": "상",
    "status": "PASS",
    "evidence": "Finger 서비스가 비활성화되어 있음",
    "guide": "xinetd에서 finger 서비스를 disable=yes로 설정하세요.",
    "check_date": "2026-02-07 20:30:00"
}
```

