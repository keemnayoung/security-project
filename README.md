#🛡️ ISMS-P 기반 멀티 OS 보안 진단 및 자동 조치 시스템
Hyundai AutoEver IT Security Bootcamp Project

###📝 프로젝트 개요 (Overview)
KISA ISMS-P 인증 기준(2.11.2 취약점 점검)을 바탕으로, 이기종 인프라 환경에서 보안 취약점을 자동으로 진단하고 즉각적인 조치를 수행하는 통합 보안 자동화 도구입니다.

###🚀 핵심 기능 (Key Features)
Multi-OS 지원: Ubuntu, Rocky Linux 9/10 등 다양한 리눅스 환경에 최적화된 보안 진단 쉘 스크립트 제공.

DB 보안 진단: MySQL 및 PostgreSQL 데이터베이스의 설정 보안 및 권한 관리 자동 점검.

KISA 가이드 준수: KISA 리눅스 서버 보안 가이드(U-67 등)를 준수한 정밀 진단 로직 구현.

자동화된 조치(Remediation): Ansible을 활용하여 진단된 취약점을 실시간으로 패치하고 보안 설정을 최적화.

통합 대시보드: Python 기반의 시각화 도구를 통해 진단 결과 및 조치 현황을 직관적으로 확인.

###📂 프로젝트 구조 (Structure)
Ubuntu/, Rocky9/, Rocky10/: 각 OS별 맞춤형 진단 및 조치 스크립트.

Mysql/, Postgresql/: 데이터베이스 보안 설정 자동화 스크립트.

results/: 진단 결과 보고서 및 데이터 관리.
