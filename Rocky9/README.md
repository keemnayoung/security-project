# 🛡️ Rocky Linux 보안 자동화 프로젝트 가이드
> **KISA ISMS-P 기반 취약점 진단 및 자동 조치 시스템**

---

## 🛠️ 1. 개발 환경 연결 (Windows ↔ Ubuntu)
우분투 터미널에 직접 치지 않고, **윈도우의 VS Code**를 연결해서 작업하여 생산성을 높입니다.

* **VS Code 확장 설치**: 윈도우 VS Code에서 **Remote - SSH**를 설치합니다.
* **SSH 연결**: `F1` 키 → `SSH: Connect to Host...` 클릭 → `계정명@우분투IP` 입력 후 접속합니다.
* **폴더 생성**: `~/security_project` 폴더를 만들고 VS Code로 해당 폴더를 엽니다.

---

## 📦 2. 가상환경(venv) 세팅 및 패키지 설치
시스템 파이썬과 분리된 **독립적인 가상환경(`.venv`)**을 생성하여 프로젝트를 안전하게 관리합니다.

```bash
# 1. 시스템 업데이트 및 필수 도구 설치
sudo apt update && sudo apt install -y python3-venv ansible

# 2. 가상환경 생성 및 활성화
python3 -m venv .venv
source .venv/bin/activate

# 3. 필수 패키지 설치
pip install --upgrade pip
pip install streamlit pandas xlsxwriter
```
---

## 🚀 3. 진단 및 조치 실행 순서 (핵심 워크플로우)
모든 명령어는 가상환경이 활성화된 상태(source .venv/bin/activate)에서 실행해야 합니다.

```bash
1단계: 인벤토리 설정
hosts 파일에 진단 대상인 로키 리눅스(Rocky 9/10), 우분투 등의 IP 주소와 비밀번호를 정확히 기재합니다.

2단계: 최초 보안 진단 (Audit)
현재 서버의 보안 취약점 상태를 KISA 가이드(U67 등) 기준으로 수집합니다.
ansible-playbook -i hosts run_audit.yml -k -K

3단계: 취약점 자동 조치 (Remediation)
발견된 취약점을 Ansible을 통해 자동으로 수정하고 보안 설정을 강화합니다.
ansible-playbook -i hosts run_fix.yml -k -K

4단계: ★ 결과 확인을 위한 재진단 ★
이 과정을 생략하면 대시보드 데이터가 갱신되지 않습니다. 반드시 다시 진단하여 조치 결과를 반영하세요.
ansible-playbook -i hosts run_audit.yml -k -K
```
---

## 📊 4. 통합 보안 대시보드 실행
Python 기반의 Streamlit 대시보드를 통해 시각화된 보고서를 확인합니다.

```bash
가상환경 활성화 상태에서 실행
streamlit run dashboard.py
브라우저 접속: http://localhost:8501
