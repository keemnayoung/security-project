import streamlit as st  # Streamlit 라이브러리 임포트 (웹 대시보드 UI용)
import pandas as pd     # Pandas 라이브러리 임포트 (데이터 처리용)
import json             # JSON 라이브러리 임포트 (결과 파일 읽기용)
import os               # OS 라이브러리 임포트 (파일 경로 및 시스템 명령용)
import io               # IO 라이브러리 임포트 (메모리 상의 파일 처리용)
import subprocess       # Subprocess 라이브러리 임포트 (외부 터미널 명령 실행용 - Ansible 등)
import time             # Time 라이브러리 임포트 (시간 지연 및 대기용)
from datetime import datetime  # Datetime 모듈 임포트 (날짜 및 시간 처리용)

# --- 1. 페이지 설정 및 UI 디자인  ---
# Streamlit 페이지 기본 설정 (제목, 레이아웃 등)
st.set_page_config(page_title="Security Ops Master v6.1", layout="wide", initial_sidebar_state="expanded")

# CSS 스타일 정의 (HTML/CSS 코드를 직접 삽입하여 UI 커스터마이징)
st.markdown("""
   <style>
    /* Google Fonts (Pretendard) 로드 */
    @import url('https://fonts.googleapis.com/css2?family=Pretendard:wght@400;600;800&display=swap');
    
    /* 전체 폰트 설정 */
    * { font-family: 'Pretendard', sans-serif; }

    /* 메인 앱 배경색 설정 */
    .stApp { background-color: #F8FAFC; color: #1E293B; }

    /* 사이드바 배경 및 테두리 설정 */
    [data-testid="stSidebar"] {
        background-color: white !important;
        border-right: 1px solid #E2E8F0;
    }

    /* 상단 지표(Metric) 카드 컨테이너 스타일 */
     .metric-container { display: flex; gap: 20px; margin-bottom: 30px; }
    
    /* 개별 지표 카드 스타일 (배경, 그림자, 테두리 등) */
    .metric-card {
        background: white; padding: 25px; border-radius: 20px; flex: 1;
        box-shadow: 0 4px 15px rgba(0,0,0,0.05); border: 1px solid #E2E8F0; text-align: center;
    }
    
    /* 지표 값 텍스트 스타일 */
    .metric-value { font-size: 2.2rem; font-weight: 800; margin: 10px 0; }
    
    /* 보안 상태별 색상 (양호: 초록, 취약: 빨강) */
    .status-secure { color: #10B981 !important; font-weight: 800; font-size: 1.3rem; }
    .status-vulnerable { color: #EF4444 !important; font-weight: 800; font-size: 1.3rem; }

    /* 뱃지 스타일 (중요도, ISMS 인증 등) */
    .badge {
        padding: 5px 14px; border-radius: 50px; font-weight: 700; font-size: 0.85rem;
        background: #F1F5F9; color: #475569; border: 1px solid #E2E8F0; margin-right: 5px;
    }

    /* 점검 결과 아이템 카드 디자인 */
    .item-card {
        background: white; border-radius: 16px; padding: 25px; margin-bottom: 25px;
        box-shadow: 0 10px 25px rgba(0,0,0,0.03); border: 1px solid #E2E8F0;
    }
    
    /* 카드 상단 테두리 색상 (양호/취약 구분) */
    .border-pass { border-top: 8px solid #10B981 !important; }
    .border-vulnerable { border-top: 8px solid #EF4444 !important; }

    /* --- 버튼 스타일 전체 수정 --- */
    .stButton > button {
        border-radius: 12px !important;
        font-weight: 700 !important;
        transition: all 0.2s ease-in-out !important;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1) !important;
        border: none !important;
    }

    /* 1. 승인 완료 버튼 (Primary 스타일 - 파란색 그라데이션) */
    .stButton > button[kind="primary"] {
        background: linear-gradient(135deg, #3B82F6 0%, #2563EB 100%) !important;
        color: white !important;
    }

    /* 2. 전 서버 점검 버튼 (사이드바 - 어두운 배경) */
    button[key="sidebar_scan"] {
        background: #334155 !important;
        color: white !important;
    }

    /* 3. 개별 서버 점검 버튼 (사이드바 - 흰색 배경) */
    button[key="single_server_scan"] {
        background: white !important;
        color: #1E293B !important;
        border: 1px solid #E2E8F0 !important;
    }

    /* 4. 보고서 다운로드 버튼 스타일 */
    .stDownloadButton > button {
        background-color: #1E293B !important;
        color: white !important;
        width: 100% !important;
        border-radius: 12px !important;
        border: none !important;
    }

    /* 5. 조치 시작 및 일반 버튼 (Secondary 스타일) */
    .stButton > button[kind="secondary"] {
        background-color: white !important;
        color: #475569 !important;
        border: 1px solid #E2E8F0 !important;
    }

    /* 버튼 호버 효과 (살짝 떠오르는 느낌) */
    .stButton > button:hover, .stDownloadButton > button:hover {
        transform: translateY(-2px) !important;
        box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1) !important;
        filter: brightness(1.1) !important;
    }
    </style>
""", unsafe_allow_html=True)

# --- 2. 데이터 로드 로직 ---
# results 폴더에서 점검 결과 JSON 파일들을 읽어와 DataFrame으로 변환하는 함수
def load_all_data():
    results_path = "./results"  # 결과 파일이 저장된 경로
    all_data = []               # 데이터를 담을 리스트 초기화
    
    # 해당 경로가 없으면 빈 DataFrame 반환
    if not os.path.exists(results_path): return pd.DataFrame()

    # 폴더 내의 모든 파일을 순회
    for file in os.listdir(results_path):
        # .json 확장자를 가진 파일만 처리
        if file.endswith(".json"):
            try:
                # 파일 열기 및 JSON 파싱
                with open(os.path.join(results_path, file), 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    
                    # 파일명에서 타겟 정보(호스트명) 추출 (예: Rocky9_check_U01.json -> Rocky9)
                    data['target'] = file.split('_')[0]
                    
                    # check_id(또는 item_id)를 문자열로 변환하여 저장
                    check_id = str(data.get('check_id', data.get('item_id', '')))
                    
                    # DB 항목인지 OS 항목인지 분류 (D로 시작하면 DB)
                    if 'D' in check_id.upper():
                        # 호스트명에 따라 DB 종류 구분 (Rocky9 = MySQL, Rocky10 = PostgreSQL 가정)
                        if "Rocky9" in data['target']:
                            data['db_type'] = "MySQL"
                        else:
                            data['db_type'] = "PostgreSQL"
                    else:
                        data['db_type'] = "OS"  # 그 외는 OS 항목으로 분류
                    
                    # 리스트에 데이터 추가
                    all_data.append(data)
            except:
                continue  # 에러 발생 시 해당 파일 건너뜀

    # 리스트를 Pandas DataFrame으로 변환
    df = pd.DataFrame(all_data)
    
    # 데이터가 있다면 전처리 수행
    if not df.empty:
        df = df.fillna("")  # 결측치(NaN)를 빈 문자열로 채움
        df = df.replace([float('inf'), float('-inf')], 0)  # 무한대 값을 0으로 대체
        
        # 점검 날짜를 날짜 형식으로 변환 (에러 발생 시 무효화)
        df['check_date'] = pd.to_datetime(df['check_date'], errors='coerce')
        
        # 최신 데이터를 남기기 위해 정렬 후 중복 제거 (타겟, 항목별 최신 1개만 유지)
        df = df.sort_values(by=['target', 'check_id', 'check_date'], ascending=[True, True, False])
        df = df.drop_duplicates(subset=['target', 'check_id'], keep='first')
        
        # 항목 ID 기준으로 정렬
        df = df.sort_values(by='check_id')
        
    return df

# --- 3. 엑셀 출력 로직  ---
# DataFrame을 엑셀 파일(바이너리)로 변환하는 함수
def to_excel(df):
    output = io.BytesIO()  # 메모리 내 바이트 스트림 생성
    
    # 1. 데이터 클렌징 (보고서용 컬럼 추출 및 정리)
    # 필요한 컬럼 정의
    cols = ['category', 'check_id', 'title', 'importance', 'status', 'evidence', 'guide']
    # 없는 컬럼은 채우고 결측치는 N/A로 처리
    report_df = df.reindex(columns=cols).fillna("N/A").copy()
    
    # 양호(PASS)인 경우 가이드 내용을 간단히 수정
    report_df.loc[report_df['status'] == 'PASS', 'guide'] = "조치가 필요 없습니다."
    
    # 상태값 한글 변환 파생 컬럼 생성
    report_df['status_label'] = report_df['status'].map({'FAIL': '취약', 'PASS': '양호'}).fillna('미점검')
    
    # 컬럼명 한글화
    report_df.columns = ['분류', '항목ID', '점검항목', '중요도', '상태_원문', '점검결과', '조치 가이드', '상태']
    # 출력할 컬럼 순서 재조정
    report_df = report_df[['분류', '항목ID', '점검항목', '중요도', '상태', '점검결과', '조치 가이드']]

    # 2. 요약 지표 계산 (분모가 0일 경우 대비)
    total_val = len(report_df)  # 전체 건수
    fail_val = len(report_df[report_df['상태'] == '취약'])  # 취약 건수
    
    # 이행률 계산
    if total_val > 0:
        pass_rate = f"{round(((total_val - fail_val) / total_val) * 100, 1)} %"
    else:
        pass_rate = "0.0 %"

    # 3. 엑셀 파일 생성 (xlsxwriter 엔진 사용)
    # nan_inf_to_errors 옵션은 에러 대신 빈 값을 넣어줌
    with pd.ExcelWriter(output, engine='xlsxwriter', engine_kwargs={'options': {'nan_inf_to_errors': True}}) as writer:
        # 데이터프레임을 엑셀 시트에 기록 (8번째 줄부터 시작)
        report_df.to_excel(writer, index=False, sheet_name='보안점검_리포트', startrow=7)
        
        workbook = writer.book
        worksheet = writer.sheets['보안점검_리포트']
        
        # 엑셀 스타일 포맷 정의
        header_fmt = workbook.add_format({'bold': True, 'bg_color': '#4472C4', 'font_color': 'white', 'border': 1, 'align': 'center'})
        pass_cell_fmt = workbook.add_format({'bg_color': '#C6EFCE', 'font_color': '#006100', 'border': 1, 'align': 'center'})
        fail_cell_fmt = workbook.add_format({'bg_color': '#FFC7CE', 'font_color': '#9C0006', 'border': 1, 'align': 'center'})
        default_fmt = workbook.add_format({'border': 1})
        title_fmt = workbook.add_format({'bold': True, 'font_size': 18})

        # 상단 요약 정보 작성 (제목 및 통계)
        worksheet.write(0, 0, f"◐ 서버 보안 취약점 점검 요약 보고서", title_fmt)
        worksheet.write(2, 0, "전체 점검 건수"); worksheet.write(2, 1, f"{total_val} 건")
        worksheet.write(2, 2, "점검 이행률"); worksheet.write(2, 3, pass_rate)
        worksheet.write(3, 0, "취약 항목(FAIL)"); worksheet.write(3, 1, f"{fail_val} 건")
        worksheet.write(3, 2, "점검 일시"); worksheet.write(3, 3, datetime.now().strftime('%Y-%m-%d %H:%M'))

        # 데이터 헤더 서식 적용
        for col_num, value in enumerate(report_df.columns.values):
            worksheet.write(7, col_num, value, header_fmt)
            
        # 데이터 본문 서식 적용 (조건부 서식 포함)
        for row_num in range(len(report_df)):
            current_row = row_num + 8
            for col_num in range(len(report_df.columns)):
                cell_value = report_df.iloc[row_num, col_num]
                
                # NaN 값 처리
                if pd.isna(cell_value): cell_value = ""
                
                # 기본 테두리 포맷 적용
                fmt = default_fmt
                # '상태' 컬럼(4번째)인 경우 양호/취약에 따라 색상 변경
                if col_num == 4: 
                    fmt = pass_cell_fmt if cell_value == '양호' else fail_cell_fmt
                
                # 셀에 값 쓰기
                worksheet.write(current_row, col_num, cell_value, fmt)

        # 열 너비 조정
        worksheet.set_column('A:G', 22)
        
    return output.getvalue()

# --- 4. 메인 데이터 로드 및 사이드바 구성 ---
df = load_all_data()  # 전체 데이터 로드

# 사이드바 영역 시작
with st.sidebar:
    st.markdown("## 🛡️ 제어 센터")
    
    # [버튼] 전 서버 점검
    if st.button("🔍 전 서버 점검", key="sidebar_scan", use_container_width=True):
        with st.spinner("🚀 전체 서버 보안 점검 중..."):
            # Ansible 플레이북 실행 (run_audit.yml)
            subprocess.run(["ansible-playbook", "-i", "hosts", "run_audit.yml"])
        st.rerun()  # 실행 완료 후 화면 새로고침

    st.divider() # 구분선

    # 대상 서버 선택 로직
    base_servers = ["Rocky9", "Rocky10"]
    # 실제 ./results 폴더에 데이터가 있는 서버 목록 추출
    existing_servers = df['target'].unique().tolist() if not df.empty else []
    # 기본 목록과 실제 데이터 목록 병합 및 정렬
    server_list = sorted(list(set(base_servers + existing_servers)), reverse=True)
    
    # 셀렉트박스로 대상 서버 선택
    selected_target = st.selectbox("🎯 대상 서버 선택", server_list, key="main_target_select")

    # [버튼] 선택된 서버만 점검
    if st.button(f"⚡ {selected_target} 서버만 점검", key="single_server_scan", use_container_width=True):
        with st.spinner(f"🔍 {selected_target} 보안 점검 중..."):
            # Ansible 실행 시 --limit 옵션으로 특정 호스트만 지정
            subprocess.run(["ansible-playbook", "-i", "hosts", "run_audit.yml", "--limit", selected_target])
        st.success(f"✔️ {selected_target} 점검이 완료되었습니다!")
        time.sleep(1) # 1초 대기
        st.rerun()    # 화면 새로고침
    
    st.divider() # 구분선

    # 보고서 다운로드 버튼 (데이터가 있을 때만 표시)
    if not df.empty:
        # 선택된 서버의 데이터만 필터링
        target_df = df[df['target'] == selected_target].reset_index(drop=True)
        # 엑셀 다운로드 버튼 생성
        st.download_button("📊 보고서 다운로드", to_excel(target_df), f"Report_{selected_target}.xlsx", use_container_width=True)
    else:
        # 데이터가 없으면 실행 중단
        st.stop()

# --- 5. 보안 지표 계산 함수 ---
def get_metrics(data):
    # 중요도별 가중치 설정 (상:5, 중:3, 하:1)
    weights = {'상': 5, '중': 3, '하': 1}
    # 각 항목에 가중치 부여
    data['weight'] = data['importance'].map(lambda x: weights.get(x, 1))
    
    # 점수 계산
    total_w = data['weight'].sum()  # 전체 가중치 합
    pass_w = data[data['status'] == 'PASS']['weight'].sum()  # 양호 항목 가중치 합
    
    # 100점 만점 환산
    score = (pass_w / total_w * 100) if total_w > 0 else 0
    
    # 등급 산정 (A, B, F)
    grade = "A" if score >= 90 else "B" if score >= 80 else "F"
    
    # 취약 건수 계산
    vuln_count = len(data[data['status'] != 'PASS'])
    
    # 무결성 지수 계산 (file_hash가 있는 항목 대상)
    integrity_items = data[data.get('file_hash', '') != ""]
    integrity = (len(integrity_items[integrity_items['status'] == 'PASS']) / len(integrity_items) * 100) if not integrity_items.empty else score
    
    return score, grade, vuln_count, integrity

# 선택된 서버의 지표 계산
score, grade, vuln_count, integrity = get_metrics(target_df)

# --- 6. 상단 지표 카드 레이아웃 렌더링 ---
st.markdown(f"""
    <div class="metric-container">
        <!-- 보안 등급 카드 -->
        <div class="metric-card">
            <div style="color:#64748B; font-weight:600;">보안 양호도 등급</div>
            <div class="metric-value {'grade-a' if score>=85 else 'grade-f'}">{grade} <span style="font-size:1.1rem; color:#94A3B8;">({score:.1f}%)</span></div>
        </div>
        <!-- 취약점 건수 카드 -->
        <div class="metric-card">
            <div style="color:#64748B; font-weight:600;">취약점 탐지</div>
            <div class="metric-value" style="color:#EF4444;">{vuln_count} <span style="font-size:1rem;">건</span></div>
        </div>
        <!-- 무결성 지수 카드 -->
        <div class="metric-card">
            <div style="color:#64748B; font-weight:600;">시스템 무결성 지수</div>
            <div class="metric-value" style="color:#3B82F6;">{integrity:.1f}%</div>
        </div>
    </div>
""", unsafe_allow_html=True)

# 탭 구성 (OS 보안 / DB 보안)
tab_os, tab_db = st.tabs(["💻 리눅스 서버 보안", "🗄️ 데이터베이스 보안"])

# --- 7. 상세 점검 항목 카드 렌더링 함수 ---
def draw_security_cards(data):
    # 데이터가 없으면 안내 메시지 출력
    if data.empty:
        st.info("💡 해당하는 점검 항목이 없습니다.")
        return
        
    # 카테고리별로 그룹화하여 출력
    # [수정] 카테고리 정렬 순서 정의
    CATEGORY_ORDER = ["계정 관리", "파일 및 디렉토리 관리", "서비스 관리", "패치 관리", "로그 관리"]
    
    # 데이터에 있는 카테고리만 추출
    unique_cats = data['category'].unique()
    # 정의된 순서대로 정렬 (정의되지 않은 카테고리는 뒤쪽으로 배치)
    sorted_cats = sorted(unique_cats, key=lambda x: CATEGORY_ORDER.index(x) if x in CATEGORY_ORDER else 999)

    for cat in sorted_cats:
        # [수정] 항목 정렬 로직: U-숫자 형식에서 숫자만 추출하여 정렬
        # 예: U-1 -> 1, U-10 -> 10 (문자열 정렬 시 U-1, U-10, U-2 순서 되는 문제 해결)
        cat_items = data[data['category'] == cat].sort_values(
            by='check_id',
            key=lambda x: x.str.extract(r'(\d+)')[0].astype(int)
        ).reset_index(drop=True)

        fail_count = len(cat_items[cat_items['status'] == 'FAIL'])
        
        border_color = "#EF4444" if fail_count > 0 else "#10B981"
        bg_color = "#FFF5F5" if fail_count > 0 else "#F0FDF4"
        text_color = "#C53030" if fail_count > 0 else "#15803D"
        icon = "⚠️" if fail_count > 0 else "✅"
        status_label = f"취약 {fail_count}건" if fail_count > 0 else "보안 양호"

        # 카테고리 헤더 출력 (HTML커스텀 디자인)
        st.markdown(f"""
            <style>
            /* Expander(접기/펼치기) 기본 스타일 제거 및 커스터마이징 */
            div[data-testid="stExpander"] {{ border: none !important; box-shadow: none !important; margin-top: -72px !important; padding: 0 !important; }}
            div[data-testid="stExpander"] > details {{ border: none !important; box-shadow: none !important; }}
            div[data-testid="stExpander"] details[open] > div {{ border: none !important; padding-top: 20px !important; }}
            div[data-testid="stExpander"] summary {{ height: 72px !important; color: transparent !important; list-style: none !important; padding: 0 !important; }}
            div[data-testid="stExpander"] summary::-webkit-details-marker {{ display: none !important; }}
            </style>
            
            <div style="background-color: white; padding: 18px 25px; border-radius: 15px; border: 1px solid #E2E8F0; box-shadow: 0 4px 12px rgba(0,0,0,0.05); display: flex; justify-content: space-between; align-items: center; position: relative; z-index: 10; pointer-events: none;">
                <div style="font-size: 1.25rem; font-weight: 800; color: #1E293B; display: flex; align-items: center;">📂 {cat}</div>
                <div style="background-color: {bg_color}; color: {text_color}; padding: 5px 16px; border-radius: 50px; font-size: 0.95rem; font-weight: 800; border: 1px solid {border_color}44;">{icon} {status_label}</div>
            </div>
            """, unsafe_allow_html=True)

        # 항목 리스트 (Expander 안에 배치)
        with st.expander("", expanded=False):
            st.markdown("<div style='height: 15px;'></div>", unsafe_allow_html=True)
            for i, row in cat_items.iterrows():
                # 상태 확인 (양호/취약)
                is_pass = row['status'] == 'PASS'
                card_cls = "border-pass" if is_pass else "border-vulnerable"
                
                # 표시할 텍스트 결정 (조치로그 > 증적 > 기본값 순)
                action_result = row.get('action_result', '')
                action_log = row.get('action_log', '')
                evidence = row.get('evidence', '')

                if action_result == 'SUCCESS' and action_log:
                    display_text = action_log
                elif evidence:
                    display_text = evidence
                else:
                    display_text = "상세 데이터가 없습니다."

                # [수정] 점검 결과 포맷팅: 단순 정직하게 ". " 기준으로 분리
                if display_text and display_text != "상세 데이터가 없습니다.":
                    sentences = display_text.split(". ")
                    formatted_text = ""
                    count = 1
                    for s in sentences:
                        s = s.strip()
                        if not s: continue 
                            
                        # 마침표가 없다면 복구
                        if not s.endswith("."):
                            s += "."
                        
                        if count == 1:
                            formatted_text += f"{count}.&nbsp; {s}<br>"
                        else:
                            formatted_text += f"{count}. {s}<br>"
                        count += 1
                        
                    if formatted_text:
                        display_text = formatted_text

                
                # 가이드 박스 HTML 생성
                guide_html = ""
                if not is_pass: # 취약한 경우
                    guide_html = f'<div style="background:#FFF5F5; padding:18px; border-radius:12px; border:1px solid #FED7D7; margin-top:15px; color:#C53030;">💡 <b>조치 가이드:</b> {row["guide"]}</div>'
                elif row.get('action_result') == 'SUCCESS': # 조치 성공한 경우
                    guide_html = f'<div style="background:#F0FDF4; padding:18px; border-radius:12px; border:1px solid #BBF7D0; margin-top:15px; color:#15803D;">✅ <b>조치 완료:</b> {row["guide"]}</div>'

                # 메인 아이템 카드 출력
                st.markdown(f"""
                    <div class="item-card {card_cls}">
                        <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                            <div>
                                <span class="badge">중요도: {row['importance']}</span>
                                <span class="badge">ISMS-P 2.1.2</span>
                                <h2 style="margin: 15px 0; font-size: 1.6rem; letter-spacing:-0.5px;">
                                    {row['check_id']} {row['title']}
                                </h2>
                                <p style="font-size: 1.1rem; color: #475569; line-height: 1.6;">
                                    🔍 <b>점검 결과:</b><br>
                                    <span style="display: block; margin-top: 5px;">{display_text}</span>
                                </p>
                            </div>
                            <div class="{'status-secure' if is_pass else 'status-vulnerable'}">
                                ● {'양호' if is_pass else '취약'}
                            </div>
                        </div>
                        {guide_html}
                    </div>
                """, unsafe_allow_html=True)
                
                # 취약 항목에 대한 조치 UI (버튼 등)
                if not is_pass:
                    # 현재 항목이 조치 승인 대기 상태인지 확인
                    is_fixing = st.session_state.get(f"confirm_{row['check_id']}", False)

                    if not is_fixing:
                        # 1단계: [조치 프로세스 시작] 버튼
                        if st.button(f"⚡ {row['check_id']} 조치 프로세스 시작", key=f"pre_fix_{row['check_id']}", use_container_width=True):
                            st.session_state[f"confirm_{row['check_id']}"] = True # 상태값 변경
                            st.rerun() # 새로고침하여 UI 갱신
                    else:
                        # 2단계: 승인 및 실행 UI 표시
                        # 스크립트에서 설정된 영향도 정보 가져오기
                        impact_text = row.get('action_impact', '일반적인 경우 영향이 없습니다.')
                        impact_level = row.get('impact_level', 'LOW')

                        # 영향도 수준에 따른 경고창 색상/아이콘 구분
                        if impact_level == "LOW":
                            st.markdown(f"""
                                <div style="background-color: #F0FDF4; padding: 16px; border-radius: 8px; border: 1px solid #BBF7D0; margin-bottom: 20px;">
                                    <div style="display: flex; align-items: center; margin-bottom: 8px;">
                                        <span style="background-color: #22C55E; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; margin-right: 10px;">SAFE</span>
                                        <b style="color: #166534; font-size: 1.05rem;">🛡️ 안전한 조치 안내</b>
                                    </div>
                                    <p style="margin: 0; color: #166534; line-height: 1.6;">{impact_text}</p>
                                </div>
                            """, unsafe_allow_html=True)
                        else:
                            st.markdown(f"""
                                <div style="background-color: #FFFBEB; padding: 16px; border-radius: 8px; border: 1px solid #FDE68A; margin-bottom: 20px;">
                                    <div style="display: flex; align-items: center; margin-bottom: 8px;">
                                        <span style="background-color: #F59E0B; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; margin-right: 10px;">CAUTION</span>
                                        <b style="color: #92400E; font-size: 1.05rem;">⚠️ 조치 시 주의사항</b>
                                    </div>
                                    <p style="margin: 0; color: #92400E; line-height: 1.6;">{impact_text}</p>
                                </div>
                            """, unsafe_allow_html=True)

                        # 최종 승인 확인 메시지
                        st.info("💡 **운영 영향도 검토 및 보안 담당자의 최종 승인**을 완료하셨습니까?")
                        
                        c1, c2 = st.columns(2)
                        with c1:
                            # [승인 완료] 버튼 클릭 시
                            if st.button("✅ 승인 완료 (실행)", key=f"final_fix_{row['check_id']}", type="primary", use_container_width=True):
                                with st.spinner(f"🛠️ {row['check_id']} 조치 중..."):
                                    # 앤서블 플레이북 실행 (run_fix.yml) - 특정 항목(target_id)만 실행
                                    subprocess.run(["ansible-playbook", "-i", "hosts", "run_fix.yml", "-e", f"target_id={row['check_id'].replace('-','')}", "--limit", selected_target])
                                    time.sleep(1)
                                st.success(f"✔️ {row['check_id']} 조치 완료!")
                                st.session_state[f"confirm_{row['check_id']}"] = False # 상태 복구
                                st.rerun() # 새로고침
                        with c2:
                            # [취소] 버튼
                            if st.button("❌ 취소", key=f"cancel_{row['check_id']}", use_container_width=True):
                                st.session_state[f"confirm_{row['check_id']}"] = False # 상태 복구
                                st.rerun()
                    st.markdown('</div>', unsafe_allow_html=True)

# OS 탭 컨텐츠 렌더링
with tab_os:
    st.markdown(f"### 💻 {selected_target} 보안 점검 결과")
    # OS 타입인 항목만 필터링하여 카드 그리기
    draw_security_cards(target_df[target_df['db_type'] == "OS"])

# DB 탭 컨텐츠 렌더링
with tab_db:
    # 호스트에 따라 DB 라벨 동적 변경
    if "Rocky9" in selected_target:
        db_label = "MySQL"
    elif "Rocky10" in selected_target:
        db_label = "PostgreSQL"
    else:
        db_label = "Database"

    st.markdown(f"### 🗄️ {db_label} 보안 점검 결과")
    
    # DB 타입인 항목만 필터링 (MySQL/PostgreSQL)
    db_items = target_df[target_df['db_type'].isin(["MySQL", "PostgreSQL"])]
    
    if db_items.empty:
        st.info("💡 해당하는 점검 항목이 없습니다.")
    else:
        # DB 점검 항목 카드 그리기
        draw_security_cards(db_items)
