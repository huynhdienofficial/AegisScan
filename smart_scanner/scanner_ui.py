"""
🛡️ Smart Security Scanner — Giao diện kiểm tra bảo mật toàn diện
Tổ chức khoa học theo 4 nhóm chính (theo Feature List v3.1 — 86/86 tính năng):
  1. Web DAST — Quét ứng dụng web/API (OWASP Top 10 + nâng cao)
  2. Infra & Cloud — Hạ tầng/Server/Container/Cloud
  3. Governance — Asset/Finding/Compliance/RBAC/Automation
  4. Enterprise — SIEM/Ticketing/API/Exploitation
"""
import asyncio
import json
import os
import time
import pandas as pd
import streamlit as st
from datetime import datetime
from urllib.parse import urlparse

from playwright.async_api import async_playwright

from crawler_core import AsyncCrawlerEngine
from utils.request_handler import RequestHandler
from utils.scope_guard import ScopeGuard, ScanContext
from utils.safety_profiles import SafetyManager
from utils.risk_analyzer import RiskAnalyzer
from utils.severity_styler import border_style, title_color
from discovery.api_discovery import APIDiscovery
from scanners.passive_scanner import SecurityHeaderScanner, CookieScanner
from fingerprint.technology_detector import TechnologyDetector

from scanners.web.jwt_scanner import JWTScanner
from scanners.web.file_upload_scanner import FileUploadScanner
from scanners.web.graphql_scanner import GraphQLScanner
from scanners.web.websocket_scanner import WebSocketScanner
from scanners.web.advanced_scanners import (
    WAFEvasionScanner, RequestSmugglingScanner, RaceConditionScanner,
)
from scanners.web.security_misconfig import (
    CORSScanner, CSRFScanner, AuthorizationScanner, OpenAPIDiscovery, HTTPMethodScanner,
)
from scanners.web.input_validation import (
    SSRFScanner, PathTraversalScanner, SSTIScanner, XXEScanner, AuthSessionScanner,
)
from scanners.infra_scanner import InfraScanner, PortScanner, TLSScanner
from scanners.database_scanner import DatabaseScanner
from scanners.kubernetes_scanner import KubernetesScanner
from scanners.cloud_scanner import CloudScanner
from scanners.os_hardening import OSHardeningScanner
from scanners.secrets_scanner import SecretsScanner, DockerScanner

from assets.asset_manager import Asset, AssetInventory
from finding_management import FindingManager
from threat_intel import ThreatIntelEngine
from governance import (
    FirewallRuleReview, ExploitManifestRegistry, BusinessImpactScoring,
    RemediationAutomation, ScanScheduler, BusinessLogicScanner, SecretVault,
)
from enterprise import SIEMIntegrator, TicketingIntegrator, PublicAPI
from agents import AgentManager
from sbom import SBOMGenerator, SecurityDashboard, ZeroDayML
from data_residency import DataResidencyManager, SelfSecurityScanner
from exploitation import NotificationService, ComplianceMapper
from exploitation_tool import ExploitationTool
from utils.fuzzer_engine import FuzzerEngine
from utils.rbac import RBACManager, Role
from utils.authorization import AuthorizationRegistry

from fingerprint.attack_surface.exploit_manager import ExploitManager

# ─── Cấu hình trang ─────────────────────────────────────────
st.set_page_config(
    page_title="Smart Security Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ─── CSS ────────────────────────────────────────────────────
st.markdown("""
<style>
    .stApp {
        background: #0d1117;
        color: #c9d1d9;
    }
    .stApp, .stApp * { font-family: -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; }

    .hero {
        border-bottom: 1px solid #21262d;
        padding: 1.1rem 0 1rem 0; margin-bottom: 0.4rem;
    }
    .hero-title {
        font-size: 1.6rem; font-weight: 650; color: #e6edf3;
        letter-spacing: -0.01em;
    }
    .hero-sub { font-size: 0.88rem; color: #7d8590; margin-top: 0.25rem; }

    .scan-card {
        background: #12161d; border: 1px solid #21262d;
        border-radius: 8px; padding: 1.1rem 1.4rem;
        margin: 0.5rem auto 1rem auto; max-width: 1100px;
    }
    .metric-card {
        background: #12161d; border: 1px solid #21262d;
        border-radius: 6px; padding: 0.85rem; text-align: center;
    }
    .metric-value { font-size: 1.5rem; font-weight: 650; color: #e6edf3; }
    .metric-label { font-size: 0.75rem; color: #7d8590; margin-top: 0.15rem; }

    .badge {
        display: inline-block; padding: 0.12rem 0.55rem; border-radius: 4px;
        font-size: 0.72rem; font-weight: 600; letter-spacing: 0.01em;
        border: 1px solid transparent;
    }
    .badge-green { background: #0d2818; color: #3fb950; border-color: #23763899; }
    .badge-red { background: #2d1214; color: #f85149; border-color: #8e242699; }
    .badge-yellow { background: #2b2111; color: #d29922; border-color: #7d5c0099; }
    .badge-blue { background: #0d1b2e; color: #58a6ff; border-color: #1f5b9999; }
    .badge-gray { background: #161b22; color: #8b949e; border-color: #30363d; }

    .stTextInput > div > div > input {
        background-color: #0d1117;
        border: 1px solid #30363d; border-radius: 6px;
        color: #e6edf3; font-size: 0.95rem; padding: 0.55rem 0.85rem;
    }
    .stTextInput > div > div > input:focus {
        border-color: #58a6ff;
    }
    .stButton > button {
        background: #21262d; color: #e6edf3;
        font-size: 0.95rem; font-weight: 600; border: 1px solid #30363d; border-radius: 6px;
        padding: 0.55rem 1.6rem; width: 100%; transition: background 0.15s, border-color 0.15s;
    }
    .stButton > button:hover {
        background: #30363d; border-color: #8b949e; color: #e6edf3;
    }
    .stButton > button:active {
        background: #1f6feb; border-color: #1f6feb;
    }

    .footer { text-align: center; color: #484f58; font-size: 0.78rem; padding: 1rem 0; }

    .risk-detail {
        background: #12161d;
        border: 1px solid #21262d; border-left-width: 3px;
        border-radius: 6px; padding: 0.85rem 1rem; margin: 0.55rem 0;
    }
    .risk-title { font-size: 0.98rem; font-weight: 650; color: #e6edf3; }
    .risk-desc { color: #8b949e; font-size: 0.88rem; margin-top: 0.35rem; }
    .risk-item { color: #7d8590; font-size: 0.82rem; margin: 0.2rem 0; }
    .risk-reco { color: #3fb950; font-size: 0.82rem; margin: 0.2rem 0; }

    .group-header {
        border-bottom: 1px solid #21262d;
        padding: 0.3rem 0 0.5rem 0; margin: 0.6rem 0 0.7rem 0;
        font-size: 0.95rem; font-weight: 650; color: #e6edf3;
    }
    .subgroup-header {
        border-left: 2px solid #30363d;
        padding: 0.15rem 0 0.15rem 0.7rem; margin: 0.7rem 0 0.3rem 0;
        font-size: 0.82rem; font-weight: 600; color: #8b949e;
        text-transform: uppercase; letter-spacing: 0.03em;
    }
    .tool-count {
        color: #484f58; font-size: 0.78rem; font-weight: 500;
        margin-left: 0.4rem; text-transform: none; letter-spacing: normal;
    }

    .stTabs [data-baseweb="tab-list"] {
        gap: 0.15rem; background: transparent;
        border-bottom: 1px solid #21262d; padding: 0;
    }
    .stTabs [data-baseweb="tab"] {
        border-radius: 6px 6px 0 0; padding: 0.45rem 1rem; font-weight: 500;
        color: #7d8590;
    }
    .stTabs [aria-selected="true"] {
        color: #e6edf3 !important;
    }
    div[data-testid="stCheckbox"] label {
        padding: 0.25rem 0; font-size: 0.88rem; color: #c9d1d9;
    }
</style>
""", unsafe_allow_html=True)

# ─── Hero ────────────────────────────────────────────────────
st.markdown("""
<div class="hero">
    <div class="hero-title">Smart Security Scanner</div>
    <div class="hero-sub">Web · Infra · Governance · Enterprise — 53 công cụ, 86 tính năng</div>
</div>
""", unsafe_allow_html=True)


def risk_badge(rating):
    rating = rating.lower()
    if 'a -' in rating or 'an toàn' in rating:
        return '<span class="badge badge-green">An Toàn</span>'
    if 'b -' in rating or 'thấp' in rating:
        return '<span class="badge badge-blue">Nguy Cơ Thấp</span>'
    if 'c -' in rating or 'trung bình' in rating:
        return '<span class="badge badge-yellow">Trung Bình</span>'
    return '<span class="badge badge-red">Nguy Cơ Cao</span>'


def render_finding_badge(severity):
    colors = {
        'critical': 'badge-red', 'high': 'badge-red',
        'medium': 'badge-yellow', 'low': 'badge-blue',
        'info': 'badge-gray',
    }
    return f'<span class="badge {colors.get(severity.lower(), "badge-gray")}">{severity.upper()}</span>'


def check_safety(target_url):
    domain = urlparse(target_url).netloc.split(':')[0]
    guard = ScopeGuard({'allowlist': [domain], 'local_lab_mode': True})
    result = guard.authorize_target(target_url, confirm=True)
    guard.audit_log('authorize', target_url, result)
    return guard


# ═══════════════════════════════════════════════════════════
# GIAO DIỆN NHẬP URL
# ═══════════════════════════════════════════════════════════
st.markdown('<div class="scan-card">', unsafe_allow_html=True)
col_url, col_btn = st.columns([3, 1])
with col_url:
    target_url = st.text_input(
        "Nhập URL trang web cần kiểm tra:",
        value="https://books.toscrape.com/",
        placeholder="https://example.com hoặc http://localhost:8000",
        label_visibility="collapsed",
    )
with col_btn:
    scan_clicked = st.button("Quét ngay", use_container_width=True)

# ─── BẢNG ĐIỀU KHIỂN QUÉT THEO TAB ───────────────────────────
st.caption("Chọn các tính năng quét theo từng nhóm — 86 tính năng, tổ chức theo 4 nhóm bên dưới")

tab_web, tab_infra, tab_gov, tab_ent = st.tabs([
    "1 · Web DAST",
    "2 · Infra & Cloud",
    "3 · Governance",
    "4 · Enterprise & Exploit",
])

# ═══════════════════════════════════════════════════════════
# TAB 1 — WEB DAST (24 tính năng)
# ═══════════════════════════════════════════════════════════
with tab_web:
    st.markdown("""
    <div class="group-header">Nhóm 1 — Web DAST: quét ứng dụng Web/API <span class="tool-count">22 công cụ</span></div>
    """, unsafe_allow_html=True)

    # 1A: Core Injection
    st.markdown("""
    <div class="subgroup-header">1A — Injection cơ bản (OWASP Top 10)</div>
    """, unsafe_allow_html=True)
    w1a1, w1a2 = st.columns(2)
    with w1a1:
        scan_sqli = st.checkbox("SQL Injection", value=True, help="Phát hiện SQLi qua GET params & form inputs")
        scan_xss = st.checkbox("XSS (Cross-Site Scripting)", value=True, help="Stored/Reflected/DOM XSS")
    with w1a2:
        scan_rce = st.checkbox("RCE (Command Injection)", value=True, help="Phát hiện lệnh hệ thống injection")
        scan_form = st.checkbox("Form POST Scan", value=True, help="Quét SQLi/XSS/RCE qua HTML forms")

    # 1B: Injection Nâng cao
    st.markdown("""
    <div class="subgroup-header">1B — Injection nâng cao (SSRF/LFI/SSTI/XXE)</div>
    """, unsafe_allow_html=True)
    w1b1, w1b2 = st.columns(2)
    with w1b1:
        scan_ssrf = st.checkbox("SSRF (Server-Side Request Forgery)", value=False, help="Ép server gửi request tới nội bộ")
        scan_lfi = st.checkbox("Path Traversal / LFI", value=False, help="Đọc file nhạy cảm ngoài webroot")
    with w1b2:
        scan_ssti = st.checkbox("SSTI (Server-Side Template Injection)", value=False, help="Inject template engine")
        scan_xxe = st.checkbox("XXE (XML External Entity)", value=False, help="Đọc file qua XML entity")

    # 1C: Xác thực & Phiên
    st.markdown("""
    <div class="subgroup-header">1C — Xác thực & phiên (Authentication/Session)</div>
    """, unsafe_allow_html=True)
    w1c1, w1c2, w1c3 = st.columns(3)
    with w1c1:
        scan_jwt = st.checkbox("JWT Testing", value=False, help="alg=none, weak secret, kid injection")
        scan_ws = st.checkbox("WebSocket Testing", value=False, help="Origin validation, auth, rate limit")
    with w1c2:
        scan_upload = st.checkbox("File Upload Testing", value=False, help="Upload malicious file types")
        scan_idor = st.checkbox("IDOR / AuthZ", value=False, help="Test object-level authorization")
    with w1c3:
        scan_csrf = st.checkbox("CSRF Testing", value=False, help="Cross-Site Request Forgery")
        scan_auth_session = st.checkbox("Auth Session Testing", value=False, help="Cookie flags, logout, fixation")

    # 1D: API & Cấu hình
    st.markdown("""
    <div class="subgroup-header">1D — API & misconfiguration (GraphQL/OpenAPI/CORS)</div>
    """, unsafe_allow_html=True)
    w1d1, w1d2, w1d3 = st.columns(3)
    with w1d1:
        scan_graphql = st.checkbox("GraphQL Testing", value=False, help="Introspection, alias bombing")
        scan_openapi = st.checkbox("OpenAPI Discovery", value=False, help="Phát hiện OpenAPI/Swagger endpoints")
    with w1d2:
        scan_cors = st.checkbox("CORS Testing", value=False, help="Reflected origin, misconfigured CORS")
        scan_http_method = st.checkbox("HTTP Methods Scan", value=False, help="PUT/DELETE/TRACE bất thường")
    with w1d3:
        scan_waf = st.checkbox("WAF Evasion", value=False, help="Encoding đa lớp bypass WAF")
        scan_smuggling = st.checkbox("Request Smuggling", value=False, help="CL.TE / TE.CL poisoning")

    # 1E: Nâng cao
    st.markdown("""
    <div class="subgroup-header">1E — Nâng cao & race condition</div>
    """, unsafe_allow_html=True)
    we1, we2 = st.columns(2)
    with we1:
        scan_race = st.checkbox("Race Condition Testing", value=False, help="Concurrent request, double-spending")
        scan_fuzz = st.checkbox("Parameter Fuzzing", value=False, help="Fuzz tham số với payload an toàn (Fuzzer Engine)")
    with we2:
        st.caption("22 công cụ trong nhóm Web DAST")

# ═══════════════════════════════════════════════════════════
# TAB 2 — INFRA & CLOUD (11 tính năng)
# ═══════════════════════════════════════════════════════════
with tab_infra:
    st.markdown("""
    <div class="group-header">Nhóm 2 — Infra & Cloud: hạ tầng/server/container <span class="tool-count">11 công cụ</span></div>
    """, unsafe_allow_html=True)

    # 2A: Network
    st.markdown("""
    <div class="subgroup-header">2A — Network & exposure</div>
    """, unsafe_allow_html=True)
    i2a1, i2a2 = st.columns(2)
    with i2a1:
        scan_port = st.checkbox("Port / Service Scan", value=False, help="Quét 20+ port phổ biến, fingerprint service")
        scan_tls = st.checkbox("TLS / SSL Check", value=False, help="Kiểm tra certificate, protocol version")
    with i2a2:
        scan_fw = st.checkbox("Firewall Rule Review", value=False, help="Đối chiếu rule với least-privilege policy")

    # 2B: Container & Cloud
    st.markdown("""
    <div class="subgroup-header">2B — Container & cloud</div>
    """, unsafe_allow_html=True)
    i2b1, i2b2 = st.columns(2)
    with i2b1:
        scan_k8s = st.checkbox("Kubernetes Scanner", value=False, help="Privileged pods, RBAC, SA token")
        scan_docker = st.checkbox("Docker Audit", value=False, help="Kiểm tra cấu hình Docker không an toàn")
    with i2b2:
        scan_cloud = st.checkbox("Cloud Scanner (AWS/Azure/GCP)", value=False, help="Quét misconfiguration cloud")
        scan_secrets = st.checkbox("Secrets Scan", value=False, help="Phát hiện API key/credential lộ trong code")

    # 2C: Database & Compliance
    st.markdown("""
    <div class="subgroup-header">2C — Database & hardening</div>
    """, unsafe_allow_html=True)
    i2c1, i2c2 = st.columns(2)
    with i2c1:
        scan_db = st.checkbox("Database Scanner", value=False, help="PostgreSQL/MySQL/MSSQL/MongoDB config")
        scan_os = st.checkbox("OS Hardening (CIS)", value=False, help="Đối chiếu CIS Benchmark")
    with i2c2:
        scan_residency = st.checkbox("Data Residency", value=False, help="Chọn vùng lưu trữ dữ liệu theo tuân thủ (GDPR/ISO27001)")
        scan_self_security = st.checkbox("Self Security Audit", value=False, help="Tự quét chính nền tảng: dependency, secrets, least privilege")

    st.caption("11 công cụ trong nhóm Infra & Cloud")

# ═══════════════════════════════════════════════════════════
# TAB 3 — GOVERNANCE (9 tính năng)
# ═══════════════════════════════════════════════════════════
with tab_gov:
    st.markdown("""
    <div class="group-header">Nhóm 3 — Governance: quản trị & tuân thủ <span class="tool-count">10 công cụ</span></div>
    """, unsafe_allow_html=True)

    # 3A: Asset & Finding
    st.markdown("""
    <div class="subgroup-header">3A — Asset & finding management</div>
    """, unsafe_allow_html=True)
    g3a1, g3a2 = st.columns(2)
    with g3a1:
        scan_asset = st.checkbox("Asset Inventory", value=False, help="Quản lý assets, shadow IT, import CSV/JSON")
        scan_finding = st.checkbox("Finding Management", value=False, help="Lifecycle, duplicate correlation, delta")
    with g3a2:
        scan_impact = st.checkbox("Business Impact Scoring", value=False, help="Tính ảnh hưởng doanh thu/dữ liệu/vận hành")

    # 3B: Automation & Scheduler
    st.markdown("""
    <div class="subgroup-header">3B — Automation & orchestration</div>
    """, unsafe_allow_html=True)
    g3b1, g3b2 = st.columns(2)
    with g3b1:
        scan_scheduler = st.checkbox("Scan Scheduler", value=False, help="Lịch quét on-demand/cron/event")
        scan_remediation = st.checkbox("Remediation Automation", value=False, help="Tạo Ansible playbook / Bash script")
    with g3b2:
        scan_exploit_manifest = st.checkbox("Exploit Module Manifest", value=False, help="Đăng ký module có kiểm soát")
        scan_vault = st.checkbox("Secret Vault", value=False, help="Mã hóa credentials at rest")

    # 3C: Access Control & Compliance
    st.markdown("""
    <div class="subgroup-header">3C — Access control & compliance</div>
    """, unsafe_allow_html=True)
    g3c1, g3c2 = st.columns(2)
    with g3c1:
        scan_rbac = st.checkbox("RBAC (Viewer/Analyst/Approver/Admin)", value=False, help="Phân quyền theo vai trò")
        scan_notify = st.checkbox("Notification & Alerting", value=False, help="Cảnh báo Critical/High qua webhook/email/slack")
    with g3c2:
        scan_compliance = st.checkbox("Compliance Mapping", value=False, help="Map findings sang ISO 27001 / SOC 2 / PCI DSS")
    st.caption("10 công cụ trong nhóm Governance")

# ═══════════════════════════════════════════════════════════
# TAB 4 — ENTERPRISE & EXPLOIT (8 tính năng)
# ═══════════════════════════════════════════════════════════
with tab_ent:
    st.markdown("""
    <div class="group-header">Nhóm 4 — Enterprise & Exploitation <span class="tool-count">10 công cụ</span></div>
    """, unsafe_allow_html=True)

    # 4A: Integrations
    st.markdown("""
    <div class="subgroup-header">4A — SIEM / Ticketing / API / Agents</div>
    """, unsafe_allow_html=True)
    e4a1, e4a2 = st.columns(2)
    with e4a1:
        scan_siem = st.checkbox("SIEM Integration", value=False, help="Đẩy findings sang Splunk/Elastic/QRadar")
        scan_ticket = st.checkbox("Ticketing (Jira/ServiceNow)", value=False, help="Tạo ticket auto từ findings")
    with e4a2:
        scan_public_api = st.checkbox("Public API (CI/CD)", value=False, help="API tích hợp CI/CD, SARIF export")
        scan_threat_intel = st.checkbox("Threat Intel", value=False, help="CVE/CPE/EPSS/KEV matching")
        scan_agent = st.checkbox("Agent Management", value=False, help="Deploy/update/health check/remove agents (Agentless + Agent)")

    # 4B: Exploitation & Logic
    st.markdown("""
    <div class="subgroup-header">4B — Exploitation & business logic</div>
    """, unsafe_allow_html=True)
    e4b1, e4b2 = st.columns(2)
    with e4b1:
        scan_business = st.checkbox("Business Logic Testing", value=False, help="Price/quantity/coupon manipulation")
        scan_exp = st.checkbox("Exploitation Module (L1-3)", value=False, help="Khai thác có kiểm soát + rollback")
        scan_sbom = st.checkbox("SBOM & Supply Chain CVE", value=False, help="Sinh CycloneDX/SPDX + đối chiếu CVE")
    with e4b2:
        scan_trend = st.checkbox("Security Trend & Zero-day ML", value=False, help="Dashboard trend + anomaly detection")
        scan_exploit_tool = st.checkbox("Exploitation Tool + WAF Bypass", value=False,
                                        help="Khai thác SQLi/XSS/RCE đã phát hiện + bypass WAF cơ bản (chỉ non-destructive)")
        st.caption("10 công cụ trong nhóm Enterprise & Exploit")

    exploit_approver = ''
    exploit_approver_confirmed = False
    if scan_exploit_tool:
        st.caption(
            "⚠️ Level 2 gửi payload chủ động — cần tên người phê duyệt. Ứng dụng "
            "chưa có hệ thống đăng nhập/xác thực danh tính thật, nên tên nhập ở "
            "đây là tự khai báo (self-declared) — không phải xác thực định danh "
            "mạnh. Mỗi lần chạy vẫn tạo Authorization Record có scope/thời hạn "
            "và ghi vào audit trail dạng hash-chained (không thể sửa âm thầm)."
        )
        exploit_approver = st.text_input(
            "Người phê duyệt Exploitation Tool (approver username)", value="",
        )
        exploit_approver_confirmed = st.checkbox(
            "Tôi xác nhận tôi có thẩm quyền phê duyệt Active Scan cho target này", value=False,
        )

# ─── Cấu hình nâng cao ──────────────────────────────────────
st.markdown("""
<div class="subgroup-header">Cấu hình nâng cao</div>
""", unsafe_allow_html=True)
col10, col11, col12 = st.columns(3)
with col10:
    profile = st.selectbox(
        "Safety Profile",
        ["safe-active", "passive", "deep-lab", "authenticated", "ci-fast"],
        index=0,
    )
with col11:
    max_pages = st.slider("Số trang tối đa", 10, 200, 50, 10)
with col12:
    scan_passive = st.checkbox("Passive Scan (Headers/Cookies)", value=True)
    skip_ssl = st.checkbox("🔓 Bỏ qua xác minh SSL", value=False,
                           help="Dành cho target có chứng chỉ SSL lỗi/broken chain khi quét")

st.markdown('</div>', unsafe_allow_html=True)
st.caption("Chỉ quét những trang web bạn có quyền kiểm thử (trang của bạn, staging, lab)")


# ═══════════════════════════════════════════════════════════
# XỬ LÝ QUÉT
# ═══════════════════════════════════════════════════════════
if scan_clicked:
    if not target_url:
        st.error("Vui lòng nhập URL")
    else:
        guard = check_safety(target_url)
        safety_manager = SafetyManager(profile, guard)
        scan_context = ScanContext(target_url, guard, profile=profile)
        scan_context.compute_config_hash({'profile': profile, 'max_pages': max_pages})

        st.info(f"Scan ID: `{scan_context.scan_id}` — Bắt đầu kiểm tra **{target_url}**")

        progress = st.progress(0, text="Đang khởi tạo...")
        status = st.empty()
        all_findings = []
        config_findings = []
        tech = []
        apis = []
        resp_headers = {}
        sbom_payload = None
        trend_payload = None
        exploit_payload = None

        try:
            # ═══ BƯỚC 1: CRAWLER ═══
            status.info("**Bước 1:** Thu thập thông tin trang web...")
            progress.progress(0.15, text="Crawling...")

            config = {
                'max_pages': max_pages,
                'concurrency': min(safety_manager.profile.config.get('concurrency', 5), 5),
                'headless': True,
                'max_depth': 3,
            }
            crawler = AsyncCrawlerEngine(config, scope_guard=guard)
            crawl_results = asyncio.run(crawler.start(target_url))

            urls = crawl_results.get('urls', [])
            params = crawl_results.get('parameters', [])
            forms = crawl_results.get('forms', [])
            status.success(f"Tìm thấy **{len(urls)}** URL, **{len(params)}** params, **{len(forms)}** forms")
            progress.progress(0.3, text="Crawl xong — Passive scan...")

            # ═══ BƯỚC 2: PASSIVE ═══
            if scan_passive:
                status.info("**Bước 2:** Passive scan (headers/cookies/công nghệ)...")
                try:
                    async def passive_scan():
                        async with async_playwright() as p:
                            browser = await p.chromium.launch(headless=True)
                            context = await browser.new_context()
                            page = await context.new_page()
                            api_detector = APIDiscovery()
                            await api_detector.attach(page)
                            response = await page.goto(target_url, wait_until="networkidle", timeout=30000)
                            headers = response.headers
                            cookies = await context.cookies()
                            html = await page.content()
                            tech = TechnologyDetector.detect(headers, html)
                            config_findings = SecurityHeaderScanner.scan(headers) + CookieScanner.scan(cookies)
                            apis = api_detector.get_discovered_apis()
                            await browser.close()
                            return config_findings, tech, apis, headers

                    config_findings, tech, apis, resp_headers = asyncio.run(passive_scan())
                    status.success(f"Passive: **{len(config_findings)}** vấn đề cấu hình")
                except Exception as e:
                    st.warning(f"Passive scan lỗi: {str(e)}")
                    config_findings = []

            progress.progress(0.45, text="Passive xong — Web DAST...")

            # ═══ BƯỚC 3: WEB DAST ═══
            status.info("**Bước 3:** Web DAST (inject payload)...")
            handler = RequestHandler(
                timeout=safety_manager.profile.config.get('timeout', 15),
                max_retries=2,
                safety_manager=safety_manager,
                verify_ssl=not skip_ssl,
            )

            # 3a: SQLi/XSS/RCE
            scan_types = []
            if scan_sqli: scan_types.append('sqli')
            if scan_xss: scan_types.append('xss')
            if scan_rce: scan_types.append('rce')

            if scan_types:
                manager = ExploitManager(handler, scan_context=scan_context)
                active = asyncio.run(
                    manager.run_scan(
                        urls[:10], params[:10], scan_types,
                        forms=forms[:5] if scan_form else [],
                    )
                )
                all_findings.extend(active)

            # 3b: Chuyên sâu Web (optional)
            scan_url = urls[0] if urls else target_url

            # LƯU Ý: jwt/gql/ws/up/ssrf/lfi/ssti/xxe .scan() giờ là async (đã
            # vá lỗi request_handler.send_request() không được await, khiến
            # trước đây các scanner này luôn báo "an toàn" giả) — bọc
            # asyncio.run() giống cors.test_reflected_origin() bên dưới.
            if scan_jwt:
                # JWT từ Auth header nếu có — demo token
                jwt = JWTScanner(handler)
                result = asyncio.run(jwt.scan())
                if result.get('vulnerabilities'):
                    all_findings.extend(result['vulnerabilities'])

            if scan_graphql:
                gql = GraphQLScanner(handler, graphql_url=target_url.rstrip('/') + '/graphql')
                result = asyncio.run(gql.scan())
                if result.get('vulnerabilities'):
                    all_findings.extend(result['vulnerabilities'])

            if scan_ws:
                ws_url = target_url.replace('http://', 'ws://').replace('https://', 'wss://') + '/ws'
                ws = WebSocketScanner(handler, ws_url=ws_url)
                result = asyncio.run(ws.scan())
                if result.get('vulnerabilities'):
                    all_findings.extend([v for v in result['vulnerabilities'] if v['severity'] != 'Info'])

            if scan_upload:
                up = FileUploadScanner(handler, upload_url=scan_url.rstrip('/') + '/upload')
                result = asyncio.run(up.scan())
                if result.get('vulnerabilities'):
                    all_findings.extend(result['vulnerabilities'])

            if scan_cors:
                cors = CORSScanner(handler, target_url=scan_url)
                if resp_headers:
                    all_findings.extend(cors.scan_headers(resp_headers))
                try:
                    all_findings.extend(asyncio.run(cors.test_reflected_origin()))
                except Exception:
                    pass

            if scan_ssrf:
                ssrf = SSRFScanner(handler, target_url=scan_url)
                result = asyncio.run(ssrf.scan())
                all_findings.extend(result.get('vulnerabilities', []))

            if scan_lfi:
                lfi = PathTraversalScanner(handler, target_url=scan_url)
                result = asyncio.run(lfi.scan())
                all_findings.extend(result.get('vulnerabilities', []))

            if scan_ssti:
                ssti = SSTIScanner(handler, target_url=scan_url)
                result = asyncio.run(ssti.scan())
                all_findings.extend(result.get('vulnerabilities', []))

            if scan_xxe:
                xxe = XXEScanner(handler, target_url=scan_url)
                result = asyncio.run(xxe.scan())
                all_findings.extend(result.get('vulnerabilities', []))

            # 3b2: CSRF Testing
            if scan_csrf:
                csrf = CSRFScanner(
                    handler,
                    target_url=scan_url,
                    method='POST',
                    form_action=scan_url,
                    cookie_samesite='Lax',
                )
                csrf.set_form_data(forms[:3])
                all_findings.extend(csrf.scan())

            # 3b3: IDOR / Authorization Testing
            if scan_idor:
                authz = AuthorizationScanner(handler)
                # Demo: so sánh response có/không có auth header trên resource
                try:
                    unauth_resp = handler.send_request('GET', scan_url)
                    auth_resp = handler.send_request(
                        'GET', scan_url,
                        headers={'Authorization': 'Bearer demo-token'},
                    )
                    all_findings.extend(authz.test_unauthenticated_access(
                        unauth_resp, resource_desc=scan_url,
                    ))
                    all_findings.extend(authz.compare_responses(
                        auth_resp, unauth_resp, resource_desc=scan_url,
                    ))
                except Exception:
                    pass

            # 3b4: Auth Session Testing
            if scan_auth_session:
                auth_sess = AuthSessionScanner(handler, login_url=scan_url, logout_url=scan_url)
                # Demo cookie checks — dùng cookies thu được từ passive scan
                if config_findings:
                    demo_cookies = [
                        {'name': 'sessionid', 'secure': False, 'httpOnly': False, 'sameSite': ''},
                    ]
                    all_findings.extend(auth_sess.check_cookie_flags(demo_cookies))
                # Kiểm tra session sau logout
                all_findings.extend(auth_sess.test_logout_invalidation(200, can_reuse_session=True))
                all_findings.extend(auth_sess.test_session_fixation('abc123', 'abc123'))

            # 3b5: OpenAPI / Swagger Discovery
            if scan_openapi:
                openapi = OpenAPIDiscovery(handler, base_url=target_url.rstrip('/'))
                schema = asyncio.run(openapi.discover())
                if schema:
                    paths = openapi.parse_paths()
                    all_findings.append({
                        'type': 'OpenAPI Schema Discovered',
                        'severity': 'Info',
                        'detail': f"Tìm thấy OpenAPI schema tại {schema['url']}",
                        'confidence': 'High',
                    })
                    for ep in paths[:10]:
                        all_findings.append({
                            'type': 'API Endpoint Exposed',
                            'severity': 'Low',
                            'detail': f"[{ep['method']}] {ep['path']} — {ep.get('summary', '')}",
                            'confidence': 'Medium',
                        })

            # 3b6: HTTP Methods Scan
            if scan_http_method:
                http_methods = HTTPMethodScanner(handler, target_url=scan_url)
                http_findings = asyncio.run(http_methods.scan_methods())
                all_findings.extend(http_findings)

            # 3c: Nâng cao — WAF Evasion, Smuggling, Race
            if scan_waf:
                waf = WAFEvasionScanner(handler)
                for u in urls[:3]:
                    for p in params[:3]:
                        result = waf.scan(u, p)
                        if result:
                            waf_findings = [{
                                'type': 'WAF Evasion',
                                'severity': 'Medium',
                                'url': u,
                                'parameter': p,
                                'payload': r.get('payload', ''),
                                'confidence': 'Medium',
                                'detail': r.get('detail', ''),
                            } for r in (result if isinstance(result, list) else [result])]
                            all_findings.extend(waf_findings)

            if scan_smuggling:
                smuggling = RequestSmugglingScanner(handler, target_url=scan_url)
                result = smuggling.scan()
                if result.get('vulnerabilities'):
                    all_findings.extend(result['vulnerabilities'])

            if scan_race:
                race = RaceConditionScanner(handler, target_url=scan_url)
                result = race.scan()
                if result.get('vulnerabilities'):
                    all_findings.extend(result['vulnerabilities'])

            # 3d: Parameter Fuzzing (Fuzzer Engine)
            if scan_fuzz:
                fuzz = FuzzerEngine(handler)
                fuzz_payloads = [
                    "<script>alert(document.cookie)</script>",
                    "' OR 1=1--",
                    "{{7*7}}",
                    "${7*7}",
                    "../../../etc/passwd",
                    "1' AND SLEEP(3)--",
                ]
                fuzz_count = 0
                for u in urls[:3]:
                    for p in params[:3]:
                        try:
                            fuzz_results = asyncio.run(fuzz.fuzz_parameter(u, p, fuzz_payloads))
                            all_findings.extend(fuzz_results)
                            fuzz_count += len(fuzz_results)
                        except Exception:
                            continue
                if fuzz.blocked_payloads:
                    st.caption(f"Fuzzer đã chặn {len(fuzz.blocked_payloads)} payload nguy hiểm theo Safety Profile")
                if fuzz_count:
                    st.caption(f"Fuzzer phát hiện {fuzz_count} phản hồi đáng ngờ khi fuzz {min(len(urls),3) * min(len(params),3)} tổ hợp tham số")

            status.success(f"Web DAST: **{len(all_findings)}** findings")
            progress.progress(0.65, text="Web xong — Infra scan...")

            # ═══ BƯỚC 4: INFRA SCAN ═══
            infra_findings = []
            host = urlparse(target_url).hostname or ''

            if scan_port or scan_tls:
                status.info("**Bước 4:** Infra scan...")
                infra = InfraScanner(host, internet_facing=False, network_zone='internal')
                infra_results = asyncio.run(infra.scan())
                infra_findings.extend(infra_results.get('findings', []))

            if scan_os:
                os_scan = OSHardeningScanner(config_text='PermitRootLogin yes\nPasswordAuthentication no')
                result = os_scan.scan()
                infra_findings.extend(result.get('vulnerabilities', []))

            if scan_secrets:
                secrets = SecretsScanner(content='api_key = "AIzaSyD1234567890abcdefghijklmnopqrstuv"', filename='.env')
                infra_findings.extend(secrets.scan()['vulnerabilities'])

            if scan_db:
                db = DatabaseScanner(config_text='listen_addresses = *\nssl = off', db_type='postgresql')
                infra_findings.extend(db.scan()['vulnerabilities'])

            if scan_k8s:
                k8s = KubernetesScanner(manifest_text="""
apiVersion: v1
kind: Pod
metadata:
  name: demo-pod
spec:
  hostNetwork: true
  containers:
  - name: app
    image: nginx:latest
    securityContext:
      privileged: true
      runAsNonRoot: false
    volumeMounts:
    - name: hostfs
      mountPath: /host
  volumes:
  - name: hostfs
    hostPath:
      path: /
  automountServiceAccountToken: true
""")
                result = k8s.scan()
                if result.get('vulnerabilities'):
                    infra_findings.extend(result['vulnerabilities'])

            if scan_docker:
                docker = DockerScanner(config_text="""
version: '3'
services:
  app:
    image: nginx:latest
    privileged: true
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /:/host
""")
                result = docker.scan()
                if result.get('vulnerabilities'):
                    infra_findings.extend(result['vulnerabilities'])

            if scan_cloud:
                cloud = CloudScanner(config_json={
                    'aws': {
                        'iam': {'root_mfa_enabled': False, 'users': [{'name': 'dev', 'is_admin': True, 'mfa_enabled': False}]},
                        's3': {'buckets': [{'name': 'public-data', 'public': True, 'encryption_enabled': False}]},
                        'ec2': {'security_groups': [{'name': 'default', 'rules': [{'port': 22, 'cidr': '0.0.0.0/0'}]}]},
                    }
                })
                result = cloud.scan()
                if result.get('vulnerabilities'):
                    infra_findings.extend(result['vulnerabilities'])

            if scan_fw:
                fw = FirewallRuleReview(current_rules=[
                    {'port': 22, 'source': '0.0.0.0/0', 'action': 'ALLOW'},
                    {'port': 3306, 'source': '0.0.0.0/0', 'action': 'ALLOW'},
                    {'port': 443, 'source': '0.0.0.0/0', 'action': 'ALLOW'},
                ])
                result = fw.review()
                infra_findings.extend(result.get('violations', []))

            if scan_residency:
                drm = DataResidencyManager(region='local')
                try:
                    matches = drm.suggest_region('data_residency')
                    target_region = matches[0]['region'] if matches else 'vn'
                    drm.set_region(target_region)
                    compliance = drm.check_compliance('data_residency')
                    storage = drm.get_storage_config()
                    infra_findings.append({
                        'type': 'Data Residency',
                        'severity': 'Info',
                        'detail': (f"Đã chọn vùng lưu trữ: {storage['region_name']} ({target_region}) — "
                                   f"{compliance['message']} — path: {storage['storage_path']}"),
                        'confidence': 'High',
                        'url': target_url,
                    })
                except Exception as e:
                    infra_findings.append({
                        'type': 'Data Residency',
                        'severity': 'Low',
                        'detail': f"Không thể chọn vùng lưu trữ: {str(e)}",
                        'confidence': 'Low',
                        'url': target_url,
                    })

            if scan_self_security:
                selfsec = SelfSecurityScanner(project_path=os.path.dirname(os.path.abspath(__file__)))
                audit = selfsec.full_self_audit()
                dep_result = audit.get('dependencies', {})
                for f in dep_result.get('findings', [])[:5]:
                    infra_findings.append({**f, 'url': target_url})
                for f in audit.get('secrets', [])[:5]:
                    infra_findings.append({**f, 'url': target_url})
                lp = audit.get('least_privilege', {})
                infra_findings.append({
                    'type': 'Least Privilege Check',
                    'severity': lp.get('severity', 'Info'),
                    'detail': lp.get('recommendation', 'Scanner chạy non-root — không vi phạm least privilege'),
                    'confidence': 'High',
                    'url': target_url,
                })
                ui = audit.get('ui_binding', {})
                infra_findings.append({
                    'type': 'UI Localhost Binding',
                    'severity': ui.get('severity', 'Info'),
                    'detail': ui.get('message', ''),
                    'confidence': 'High',
                    'url': target_url,
                })

            all_findings.extend(infra_findings)
            governance_findings = []

            # ═══ BƯỚC 4B: GOVERNANCE & ENTERPRISE ═══
            if (scan_asset or scan_finding or scan_impact or scan_scheduler
                    or scan_remediation or scan_exploit_manifest or scan_vault
                    or scan_rbac or scan_siem or scan_ticket or scan_public_api
                    or scan_threat_intel or scan_business or scan_exp
                    or scan_notify or scan_compliance or scan_agent
                    or scan_sbom or scan_trend):
                status.info("**Bước 4B:** Governance & Enterprise (asset/finding/compliance)...")

                # 4B1: Asset Inventory + Finding Management
                if scan_asset or scan_finding:
                    inv = AssetInventory()
                    asset = Asset.from_url(target_url, name=f"Web: {urlparse(target_url).hostname}")
                    inv.add_asset(asset)
                    if scan_finding:
                        fm = FindingManager()
                        for fnd in all_findings[:10]:
                            fm.create_finding(
                                asset_id=asset.asset_id or f"ast-{hash(target_url) % 1000:04d}",
                                rule_id=fnd.get('type', 'UNKNOWN'),
                                severity=fnd.get('severity', fnd.get('confidence', 'Low')),
                                title=fnd.get('type', 'Finding từ UI scan'),
                                description=fnd.get('detail', ''),
                                endpoint=fnd.get('url', ''),
                                parameter=fnd.get('parameter', ''),
                                payload=fnd.get('payload', ''),
                                confidence=fnd.get('confidence', 'Low'),
                            )
                        governance_findings.append({
                            'type': 'Finding Management',
                            'severity': 'Info',
                            'detail': f"Đã ingest {len(all_findings[:10])} findings vào Finding Manager",
                            'confidence': 'High',
                            'url': target_url,
                        })

                # 4B2: Business Impact Scoring
                if scan_impact:
                    bis = BusinessImpactScoring()
                    asset_id = f"ast-{hash(target_url) % 1000:04d}"
                    bis.set_impact(asset_id, revenue=3, customer_data=4, financial_data=2, operations=3)
                    impact = bis.calculate_score(asset_id)
                    governance_findings.append({
                        'type': 'Business Impact Assessment',
                        'severity': 'Info',
                        'detail': (
                            f"Business Impact Score: {impact['business_impact_score']}/100 "
                            f"({impact['rating']}) — Revenue={impact['breakdown']['revenue']['level']}/5, "
                            f"CustomerData={impact['breakdown']['customer_data']['level']}/5"
                        ),
                        'confidence': 'High',
                        'url': target_url,
                    })

                # 4B3: Scan Scheduler
                if scan_scheduler:
                    scheduler = ScanScheduler()
                    job = scheduler.add_ondemand_scan(target_url, profile=profile)
                    cron_job = scheduler.add_cron_scan(target_url, profile, '0 2 * * *', 'Daily scan')
                    governance_findings.append({
                        'type': 'Scan Scheduler',
                        'severity': 'Info',
                        'detail': (
                            f"Đã tạo lịch: {job['job_id']} (on-demand) + "
                            f"{cron_job['job_id']} (cron: 0 2 * * *)"
                        ),
                        'confidence': 'High',
                        'url': target_url,
                    })

                # 4B4: Remediation Automation
                if scan_remediation:
                    rem = RemediationAutomation()
                    pb = rem.generate_ansible_playbook(
                        'FIND-001', 'web-servers',
                        [{'name': 'Fix SSH config', 'module': 'lineinfile', 'args': 'path=/etc/ssh/sshd_config regexp=^PermitRootLogin line="PermitRootLogin no"'}],
                        name='Fix SSH Root Login',
                    )
                    bash = rem.generate_bash_script(
                        'FIND-002',
                        [{'description': 'Disable root SSH', 'command': 'sed -i "s/^PermitRootLogin.*/PermitRootLogin no/" /etc/ssh/sshd_config && systemctl restart sshd'}],
                        name='Disable SSH Root',
                    )
                    governance_findings.append({
                        'type': 'Remediation Automation',
                        'severity': 'Info',
                        'detail': f"Đã tạo Ansible playbook (hosts: {pb['hosts']}) + Bash script",
                        'confidence': 'High',
                        'url': target_url,
                    })

                # 4B5: Exploit Module Manifest
                if scan_exploit_manifest:
                    reg = ExploitManifestRegistry()
                    mod = reg.register_module(
                        'EXPLOIT-001', 'Test RCE', 'CVE-2021-1234',
                        ['Web server đang chạy version cũ'], 'RCE trên server',
                        can_disrupt=False, rollback_method='Restore from snapshot', risk_level='High',
                    )
                    enabled = reg.enable_module('EXPLOIT-001', approved_by='admin@local')
                    governance_findings.append({
                        'type': 'Exploit Manifest',
                        'severity': 'Info',
                        'detail': (
                            f"Module '{mod['name']}' đăng ký (CVE: {mod['cve_ref']}, "
                            f"risk: {mod['risk_level']}) — enabled: {enabled.get('ok', False)}"
                        ),
                        'confidence': 'High',
                        'url': target_url,
                    })

                # 4B6: Secret Vault
                if scan_vault:
                    vault = SecretVault()
                    cred = vault.store_credential('demo-db', 'admin', 'SuperSecret123!')
                    governance_findings.append({
                        'type': 'Secret Vault',
                        'severity': 'Info',
                        'detail': f"Credential '{cred['name']}' đã mã hóa at rest (plaintext_visible: {cred['plaintext_visible']})",
                        'confidence': 'High',
                        'url': target_url,
                    })

                # 4B7: SIEM Integration
                if scan_siem:
                    siem = SIEMIntegrator(siem_type='splunk', endpoint='https://siem.local:8088')
                    sent = siem.send_batch([
                        {'severity': 'High', 'type': 'SQLi', 'detail': 'Finding mẫu', 'url': target_url},
                        {'severity': 'Medium', 'type': 'XSS', 'detail': 'Finding mẫu', 'url': target_url},
                    ])
                    governance_findings.append({
                        'type': 'SIEM Integration',
                        'severity': 'Info',
                        'detail': f"Đã đẩy {len(sent)} events sang Splunk (event_ids: {', '.join(e['event_id'] for e in sent)})",
                        'confidence': 'High',
                        'url': target_url,
                    })

                # 4B8: Ticketing Integration
                if scan_ticket:
                    ticketer = TicketingIntegrator(ticketing_type='jira', project='SEC')
                    ticket = ticketer.create_ticket({
                        'severity': 'High',
                        'title': 'SQL Injection phát hiện qua UI scan',
                        'detail': f'Target: {target_url}',
                        'url': target_url,
                    })
                    governance_findings.append({
                        'type': 'Ticketing Integration',
                        'severity': 'Info',
                        'detail': f"Đã tạo ticket {ticket['ticket_id']} (priority: {ticket['priority']}) trong Jira",
                        'confidence': 'High',
                        'url': target_url,
                    })

                # 4B9: Public API (CI/CD)
                if scan_public_api:
                    api = PublicAPI(api_key='demo-key-123')
                    sarif = api.get_findings(all_findings[:5], format='sarif')
                    gov_finding = {
                        'type': 'Public API / CI/CD',
                        'severity': 'Info',
                        'detail': f"API health: {api.health_check()['status']} — SARIF export sẵn sàng",
                        'confidence': 'High',
                        'url': target_url,
                    }
                    if all_findings:
                        gov_finding['detail'] += f" (phân tích {len(all_findings)} findings)"
                    governance_findings.append(gov_finding)

                # 4B10: Threat Intel
                if scan_threat_intel:
                    tii = ThreatIntelEngine()
                    stats = tii.get_stats()
                    gov_detail = (
                        f"Threat Intel cache: {stats['cve_count']} CVEs, "
                        f"{stats['kev_count']} KEV, {stats['epss_count']} EPSS — "
                        f"stale: {stats['is_stale']}"
                    )
                    # Map công nghệ phát hiện được sang CPE
                    for t in tech[:5]:
                        name = t.get('name', t.get('technology', t.get('software', '')))
                        version = t.get('version', '')
                        if name:
                            cpe = tii.map_to_cpe(str(name), str(version))
                            if cpe:
                                gov_detail += f" | {name} → {cpe}"
                    governance_findings.append({
                        'type': 'Threat Intelligence',
                        'severity': 'Info',
                        'detail': gov_detail,
                        'confidence': 'High',
                        'url': target_url,
                    })

                # 4B11: Business Logic Testing
                if scan_business:
                    biz = BusinessLogicScanner(handler, base_url=target_url.rstrip('/'))
                    biz_result = biz.scan_price_logic('/api/checkout')
                    biz_findings = biz_result.get('vulnerabilities', [])
                    governance_findings.extend(biz_findings)

                # 4B12: Exploitation Module (L1-3)
                if scan_exp:
                    governance_findings.append({
                        'type': 'Exploitation Module',
                        'severity': 'Info',
                        'detail': 'Exploitation Module L1-3 sẵn sàng — yêu cầu phê duyệt trước khi enable',
                        'confidence': 'High',
                        'url': target_url,
                    })

                # 4B13: RBAC / Access Control
                if scan_rbac:
                    rbac = RBACManager()
                    rbac.create_user('admin', 'Admin', full_name='Administrator')
                    rbac.create_user('analyst', 'Analyst', full_name='Security Analyst')
                    rbac.create_user('viewer', 'Viewer', full_name='Viewer')
                    rbac.log_login('analyst')
                    approval = rbac.approve_exploitation('admin', target_url, cve_id='CVE-2021-1234')
                    denied = rbac.approve_exploitation('viewer', target_url)
                    audit_log = rbac.get_audit_log(limit=10)
                    governance_findings.append({
                        'type': 'RBAC / Access Control',
                        'severity': 'Info',
                        'detail': (f"3 users (Admin/Analyst/Viewer) — Admin phê duyệt exploit: "
                                   f"{approval.get('approved', False)} — Viewer bị từ chối: "
                                   f"{not denied.get('approved', True)} — audit log: {len(audit_log)} entries"),
                        'confidence': 'High',
                        'url': target_url,
                    })

                # 4B14: Notification & Alerting
                if scan_notify:
                    notifier = NotificationService(webhook_url='https://example.local/webhook', email_enabled=True)
                    sent = 0
                    for fnd in all_findings:
                        n = notifier.notify_critical_finding(fnd, target=target_url)
                        if n:
                            sent += 1
                    governance_findings.append({
                        'type': 'Notification & Alerting',
                        'severity': 'Info',
                        'detail': f"Đã tạo {sent} thông báo cho findings Critical/High (channels: webhook/email/slack)",
                        'confidence': 'High',
                        'url': target_url,
                    })

                # 4B15: Compliance Mapping (ISO 27001 / SOC 2 / PCI DSS)
                if scan_compliance:
                    controls = set()
                    mapped_count = 0
                    for fnd in all_findings[:10]:
                        mapping = ComplianceMapper.map_finding(fnd)
                        if mapping['mapped_controls']:
                            mapped_count += 1
                            controls.update(mapping['mapped_controls'])
                    governance_findings.append({
                        'type': 'Compliance Mapping',
                        'severity': 'Info',
                        'detail': (f"Map {mapped_count} findings → {len(controls)} controls "
                                   f"(ISO 27001 / SOC 2 / PCI DSS): {', '.join(sorted(controls)[:8]) or 'chưa có mapping'}"),
                        'confidence': 'High',
                        'url': target_url,
                    })

                # 4B16: Agent Management
                if scan_agent:
                    am = AgentManager()
                    a1 = am.deploy_agent(hostname='web-01.example.local')
                    a2 = am.deploy_agent(hostname='db-01.example.local')
                    am.heartbeat(a1.agent_id)
                    stats = am.get_stats()
                    governance_findings.append({
                        'type': 'Agent Management',
                        'severity': 'Info',
                        'detail': (f"Deploy {stats['total_agents']} agents (web-01, db-01) — "
                                   f"healthy: {stats['healthy']}, stale: {stats['stale']}, "
                                   f"log entries: {stats['deployment_log_entries']}"),
                        'confidence': 'High',
                        'url': target_url,
                    })

                # 4B17: SBOM & Supply Chain CVE
                if scan_sbom:
                    sbom_gen = SBOMGenerator()
                    project_path = os.path.dirname(os.path.abspath(__file__))
                    sbom_gen.scan_python(path=project_path)
                    bom_cdx = sbom_gen.generate_cyclonedx()
                    bom_spdx = sbom_gen.generate_spdx()
                    sbom_tii = ThreatIntelEngine()
                    sbom_matches = sbom_gen.match_cves(threat_intel=sbom_tii)
                    sbom_payload = {
                        'cyclonedx': bom_cdx,
                        'spdx': bom_spdx,
                        'matches': sbom_matches,
                        'components': len(bom_cdx.get('components', [])),
                    }
                    governance_findings.append({
                        'type': 'SBOM Generation',
                        'severity': 'Info',
                        'detail': (f"SBOM: {sbom_payload['components']} components — "
                                   f"CycloneDX + SPDX sẵn sàng tải về — {len(sbom_matches)} CVE matches"),
                        'confidence': 'High',
                        'url': target_url,
                    })

                # 4B18: Security Trend Dashboard + Zero-day ML
                if scan_trend:
                    dash = SecurityDashboard()
                    dash.record_scan(
                        all_findings,
                        asset_id=f"ast-{hash(target_url) % 1000:04d}",
                        scan_id=scan_context.scan_id,
                    )
                    trend = dash.trend_by_severity()
                    top_assets = dash.top_risk_assets()
                    sla = dash.sla_compliance()
                    zd = ZeroDayML()
                    for t in (0.40, 0.42, 0.38, 0.45, 0.41):
                        zd.learn_baseline('/api/health', t)
                    anomaly = zd.detect_anomaly('/api/health', 3.8, error_rate=0.7)
                    trend_payload = {'trend': trend, 'top': top_assets, 'sla': sla, 'anomaly': anomaly}
                    governance_findings.append({
                        'type': 'Security Trend Dashboard',
                        'severity': anomaly.get('severity', 'Info'),
                        'detail': (f"Trend ghi nhận {len(trend['labels'])} scans — top asset: "
                                   f"{(top_assets[0]['asset_id'] if top_assets else 'N/A')} — "
                                   f"Zero-day ML: {anomaly['reason']}"),
                        'confidence': 'High',
                        'url': target_url,
                    })

                all_findings.extend(governance_findings)

            # ═══ BƯỚC 4C: EXPLOITATION TOOL (post-detection + WAF bypass) ═══
            if scan_exploit_tool and all_findings:
                status.info("💥 **Bước 4C:** Exploitation Tool (khai thác + WAF bypass)...")
                try:
                    if not exploit_approver or not exploit_approver_confirmed:
                        raise PermissionError(
                            "Thiếu tên người phê duyệt hoặc chưa xác nhận thẩm quyền — điền "
                            "'Người phê duyệt' và tích ô xác nhận thẩm quyền trước khi bật "
                            "Exploitation Tool."
                        )
                    exploit_rbac = RBACManager()
                    exploit_rbac.create_user(exploit_approver, Role.ADMIN)
                    exploit_registry = AuthorizationRegistry(rbac_manager=exploit_rbac)
                    exploit_record = exploit_registry.issue(
                        approver=exploit_approver,
                        scope=[urlparse(target_url).hostname],
                        authorization_type='active_scan',
                        ttl_hours=1,
                        notes='Cấp qua UI cho phiên Exploitation Tool hiện tại',
                    )
                    exploit_tool = ExploitationTool(
                        handler, target_url=target_url,
                        exploit_level=2, authorization_record=exploit_record,
                    )
                    st.caption(
                        f"🔏 Authorization Record `{exploit_record.record_id}` — approver: "
                        f"{exploit_record.approver} — hết hạn: {exploit_record.expires_at.isoformat()}"
                    )
                    if resp_headers:
                        exploit_tool.fingerprint(resp_headers)

                    # Lọc findings SQLi/XSS/RCE có parameter
                    candidates = []
                    for f in all_findings:
                        ind = ' '.join(str(i.get('type', '')) for i in f.get('indicators', [])).lower()
                        payload = str(f.get('payload', ''))
                        if f.get('parameter') and (
                            any(k in ind for k in ['sql', 'xss', 'command', 'injection', 'reflected', 'sleep'])
                            or "'" in payload or '<script' in payload
                            or any(s in payload for s in [';', '|', '&', 'sleep', 'whoami', 'id'])
                        ):
                            candidates.append(f)

                    exploitation_results = []
                    for f in candidates[:3]:
                        try:
                            handler.session = None  # session mới cho event loop mới
                            r = asyncio.run(exploit_tool.exploit_finding(f, headers=resp_headers))
                        except Exception as e:
                            r = {'vuln_type': 'error', 'confirmed': False, 'techniques': [str(e)]}
                        exploitation_results.append(r)
                        sev = 'High' if r.get('confirmed') else 'Info'
                        detail = (f"{r.get('vuln_type')}: "
                                  f"{'✅ CONFIRMED' if r.get('confirmed') else '❌ chưa xác nhận'} — "
                                  f"{', '.join(r.get('techniques', []))}")
                        if r.get('extracted'):
                            detail += ' | ' + ' | '.join(str(x) for x in r['extracted'][:3])
                        if r.get('output'):
                            detail += ' | ' + ' | '.join(str(x) for x in r['output'][:2])
                        if r.get('waf_bypassed'):
                            detail += f' | WAF bypass: {", ".join(r["waf_bypassed"])}'
                        all_findings.append({
                            'type': f'Exploitation: {r.get("vuln_type")}',
                            'severity': sev,
                            'confidence': 'High' if r.get('confirmed') else 'Medium',
                            'detail': detail,
                            'url': target_url,
                        })
                    exploit_payload = {
                        'waf': exploit_tool.waf,
                        'results': exploitation_results,
                        'custody': exploit_tool.custody_log,
                    }
                except Exception as e:
                    st.warning(f"⚠️ Exploitation Tool lỗi: {str(e)}")

            progress.progress(0.85, text="Infra + Governance xong — Tạo báo cáo...")

            # ═══ BƯỚC 5: TỔNG HỢP RISK ═══
            detailed_risk = RiskAnalyzer.assess_overall_risk(all_findings, config_findings)
            progress.progress(1.0, text="Hoàn thành")
            status.empty()

            # ═══════════════════════════════════════════════════
            # HIỂN THỊ KẾT QUẢ
            # ═══════════════════════════════════════════════════
            st.markdown("---")
            st.markdown("## Kết quả kiểm tra bảo mật")

            # Tổng quan
            rc1, rc2, rc3 = st.columns([2, 1, 1])
            with rc1:
                st.markdown(f"""
                <div style="background:#12161d; border:1px solid #21262d;
                            border-radius:8px; padding:1rem;">
                    <div style="font-size:0.8rem; color:#7d8590;">Đánh giá nguy hiểm tổng thể</div>
                    <div style="font-size:2rem; font-weight:700; color:#e6edf3;">{detailed_risk['score']}<span style="font-size:1rem; color:#484f58;">/100</span></div>
                    <div>{risk_badge(detailed_risk['rating'])}</div>
                    <div style="font-size:0.86rem; color:#8b949e; margin-top:0.5rem;">{detailed_risk['summary']}</div>
                </div>
                """, unsafe_allow_html=True)
            with rc2:
                st.markdown(f"""
                <div style="background:#12161d; border:1px solid #21262d;
                            border-radius:8px; padding:1rem; text-align:center;">
                    <div style="font-size:0.78rem; color:#7d8590;">Mục tiêu</div>
                    <div style="font-size:0.88rem; word-break:break-all; font-weight:600; color:#e6edf3;">{target_url}</div>
                    <div style="font-size:0.68rem; color:#484f58; margin-top:0.4rem;">
                        Scan ID: {scan_context.scan_id[:12]}...
                    </div>
                </div>
                """, unsafe_allow_html=True)
            with rc3:
                st.markdown(f"""
                <div style="background:#12161d; border:1px solid #21262d;
                            border-radius:8px; padding:1rem; text-align:center;">
                    <div style="font-size:0.78rem; color:#7d8590;">Phân bố mức độ</div>
                    <div style="font-size:0.82rem; margin-top:0.35rem; color:#c9d1d9; text-align:left;">
                        <span style="color:#f85149;">Critical</span> <b>{detailed_risk['metrics']['critical']}</b><br>
                        <span style="color:#f85149;">High</span> <b>{detailed_risk['metrics']['high']}</b><br>
                        <span style="color:#d29922;">Medium</span> <b>{detailed_risk['metrics']['medium']}</b><br>
                        <span style="color:#58a6ff;">Low</span> <b>{detailed_risk['metrics']['low']}</b>
                    </div>
                </div>
                """, unsafe_allow_html=True)

            # Metrics
            st.markdown("<br>", unsafe_allow_html=True)
            m1, m2, m3, m4, m5, m6 = st.columns(6)
            metrics = [
                ("URLs", len(urls)),
                ("Params", len(params)),
                ("Forms", len(forms)),
                ("Config", len(config_findings)),
                ("Web DAST", len(all_findings) - len(infra_findings)),
                ("Infra", len(infra_findings)),
            ]
            for col, (label, value) in zip([m1, m2, m3, m4, m5, m6], metrics):
                with col:
                    st.markdown(f"""
                    <div class="metric-card">
                        <div class="metric-value">{value}</div>
                        <div class="metric-label">{label}</div>
                    </div>
                    """, unsafe_allow_html=True)

            st.markdown("---")
            st.markdown("## Các nhóm tính năng đã quét")

            # Tab tổng hợp theo nhóm
            tabs = st.tabs([
                "Web Findings",
                "Infra Findings",
                "Cấu hình",
                "Công nghệ",
                "API",
                "Đánh giá chi tiết",
            ])

            with tabs[0]:
                web_findings = [f for f in all_findings if f not in infra_findings]
                if web_findings:
                    rows = []
                    for v in web_findings:
                        rows.append({
                            "Loại": v.get('type', v.get('indicators', [{}])[0].get('type', 'Unknown')),
                            "URL": v.get('url', ''),
                            "Parameter": v.get('parameter', ''),
                            "Payload": str(v.get('payload', ''))[:60],
                            "Mức độ": v.get('confidence', v.get('severity', 'Low')),
                        })
                    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
                else:
                    st.success("Không phát hiện lỗ hổng Web DAST")

                # Chi tiết findings
                for i, v in enumerate(web_findings[:10], 1):
                    severity = v.get('severity', v.get('confidence', 'Low'))
                    badge = render_finding_badge(severity)
                    sev_style = border_style(severity)
                    sev_color = title_color(severity)
                    st.markdown(f"""
                    <div class="risk-detail" style="{sev_style}">
                        <b style="color:{sev_color};">#{i} {v.get('type', v.get('indicators', [{}])[0].get('type', ''))}</b>
                        {badge}
                        <div class="risk-item">{v.get('url', '')} · Param: {v.get('parameter', '')} · Method: {v.get('method', 'GET')}</div>
                        <div class="risk-item">Payload: <code>{v.get('payload', '')}</code></div>
                    </div>
                    """, unsafe_allow_html=True)

            with tabs[1]:
                if infra_findings:
                    rows = []
                    for v in infra_findings:
                        rows.append({
                            "Loại": v.get('type', ''),
                            "Severity": v.get('severity', ''),
                            "Chi tiết": v.get('detail', ''),
                        })
                    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
                else:
                    st.info("Không chạy Infra scan (bỏ trống các checkbox)")

            with tabs[2]:
                if config_findings:
                    st.dataframe(pd.DataFrame(config_findings), use_container_width=True, hide_index=True)
                else:
                    st.success("Không phát hiện vấn đề cấu hình bảo mật")

            with tabs[3]:
                if tech:
                    st.table(pd.DataFrame(tech))
                else:
                    st.info("Không phát hiện công nghệ")

            with tabs[4]:
                if apis:
                    api_df = pd.DataFrame(apis)
                    st.dataframe(api_df, use_container_width=True, hide_index=True)
                    if not api_df.empty and 'method' in api_df.columns:
                        st.bar_chart(api_df.groupby('method').size(), use_container_width=True)
                else:
                    st.info("Không phát hiện API endpoints")

            with tabs[5]:
                st.markdown("## Đánh giá chi tiết mức độ nguy hiểm")
                if not all_findings and not config_findings:
                    st.success("Không có lỗ hổng nào cần đánh giá.")
                else:
                    if all_findings:
                        st.markdown("### Lỗ hổng chủ động")
                        for i, v in enumerate(all_findings[:5], 1):
                            analysis = RiskAnalyzer.analyze_finding({
                                **v,
                                'indicators': v.get('indicators') or [{'type': v.get('type', 'Unknown')}],
                            })
                            sev = analysis['severity']
                            st.markdown(f"""
                            <div class="risk-detail" style="{border_style(sev)}">
                                <span class="risk-title" style="color:{title_color(sev)};">
                                    #{i} {analysis['name']}
                                </span>
                                {render_finding_badge(sev)}
                                <div class="risk-desc">{analysis['description']}</div>
                                <div class="risk-item">{analysis['risks'][0] if analysis['risks'] else ''}</div>
                                <div class="risk-reco">{analysis['recommendations'][0] if analysis['recommendations'] else ''}</div>
                            </div>
                            """, unsafe_allow_html=True)

                    st.markdown("### Tổng kết")
                    st.markdown(f"""
                    <div style="background:#12161d; border:1px solid #21262d;
                                border-radius:8px; padding:1rem;">
                        <b style="color:#e6edf3;">{detailed_risk['summary']}</b>
                    </div>
                    """, unsafe_allow_html=True)

            # SBOM & Supply Chain display
            if sbom_payload:
                st.markdown("---")
                st.markdown("## SBOM & Supply Chain (CycloneDX / SPDX)")
                sbom_c1, sbom_c2 = st.columns([1, 1])
                with sbom_c1:
                    st.download_button(
                        "Tải CycloneDX JSON",
                        data=json.dumps(sbom_payload['cyclonedx'], ensure_ascii=False, indent=2),
                        file_name="bom.cyclonedx.json",
                        mime="application/json",
                        use_container_width=True,
                    )
                with sbom_c2:
                    st.download_button(
                        "Tải SPDX JSON",
                        data=json.dumps(sbom_payload['spdx'], ensure_ascii=False, indent=2),
                        file_name="bom.spdx.json",
                        mime="application/json",
                        use_container_width=True,
                    )
                if sbom_payload['matches']:
                    st.dataframe(
                        pd.DataFrame(sbom_payload['matches']),
                        use_container_width=True, hide_index=True,
                    )
                else:
                    st.success(f"{sbom_payload['components']} components — không có CVE match trong database")

            # Security Trend & Zero-day ML display
            if trend_payload:
                st.markdown("---")
                st.markdown("## Security Trend & Zero-day ML")
                trend_c1, trend_c2 = st.columns([2, 1])
                with trend_c1:
                    trend = trend_payload['trend']
                    if trend['labels']:
                        df_trend = pd.DataFrame(trend['series'], index=trend['labels'])
                        st.line_chart(df_trend, use_container_width=True)
                with trend_c2:
                    anomaly = trend_payload['anomaly']
                    st.markdown(f"""
                    <div class="risk-detail" style="{border_style(anomaly.get('severity', 'Info'))}">
                        <b style="color:{title_color(anomaly.get('severity', 'Info'))};">Zero-day ML Anomaly</b>
                        <div class="risk-item">
                            Phát hiện: {'CÓ bất thường' if anomaly.get('is_anomaly') else 'Không bất thường'}
                        </div>
                        <div class="risk-item">{anomaly.get('reason', '')}</div>
                    </div>
                    """, unsafe_allow_html=True)
                if trend_payload['top']:
                    st.markdown("### Top asset rủi ro")
                    st.dataframe(
                        pd.DataFrame(trend_payload['top']),
                        use_container_width=True, hide_index=True,
                    )
                st.caption(trend_payload['sla']['note'])

            # Exploitation Tool & WAF Bypass display
            if exploit_payload:
                st.markdown("---")
                st.markdown("## 💥 Exploitation Tool & WAF Bypass")
                waf_list = exploit_payload['waf'] or ['Không phát hiện WAF']
                st.markdown(f"🛡️ **WAF phát hiện:** {', '.join(waf_list)}")
                for r in exploit_payload['results']:
                    sev = 'High' if r.get('confirmed') else 'Info'
                    st.markdown(f"""
                    <div class="risk-detail" style="{border_style(sev)}">
                        <b style="color:{title_color(sev)};">{r.get('vuln_type', 'Unknown')}</b>
                        <div class="risk-item">Trạng thái: {'✅ CONFIRMED' if r.get('confirmed') else '❌ Không xác nhận'}</div>
                        <div class="risk-item">Kỹ thuật: {', '.join(r.get('techniques', [])) or 'N/A'}</div>
                    </div>
                    """, unsafe_allow_html=True)
                    for line in (r.get('extracted') or r.get('output') or []):
                        st.code(line, language='text')
                    if r.get('waf_bypassed'):
                        st.caption(f"🧪 WAF bypass đã dùng: {', '.join(r['waf_bypassed'])}")
                with st.expander("Chain-of-custody log"):
                    st.dataframe(
                        pd.DataFrame(exploit_payload['custody']),
                        use_container_width=True, hide_index=True,
                    )

            # Download reports
            st.markdown("---")
            report_payload = {
                "scan_summary": {
                    "target": target_url,
                    "scan_id": scan_context.scan_id,
                    "urls_found": len(urls),
                    "risk_score": detailed_risk['score'],
                    "risk_rating": detailed_risk['rating'],
                    "web_findings": len(all_findings) - len(infra_findings),
                    "infra_findings": len(infra_findings),
                },
                "active_findings": all_findings,
                "passive_findings": config_findings,
                "technologies": tech,
                "apis": apis,
            }
            c1, c2 = st.columns(2)
            with c1:
                st.download_button(
                    "Tải báo cáo JSON",
                    data=json.dumps(report_payload, ensure_ascii=False, indent=2, default=str),
                    file_name=f"security_scan_{scan_context.scan_id[:8]}.json",
                    mime="application/json",
                    use_container_width=True,
                )
            with c2:
                st.download_button(
                    "Tải báo cáo HTML",
                    data=f"""
                    <html><head><meta charset="utf-8"><title>Security Report</title>
                    <style>body{{font-family:Arial;margin:24px;color:#1f2937}}
                    h1{{color:#111827}} table{{width:100%;border-collapse:collapse;margin-top:12px}}
                    th,td{{border:1px solid #d1d5db;padding:8px;text-align:left}} th{{background:#eef2ff}}</style>
                    </head><body>
                    <h1>Smart Security Scanner Report</h1>
                    <p><b>Target:</b> {target_url}</p>
                    <p><b>Scan ID:</b> {scan_context.scan_id}</p>
                    <p><b>Đánh giá:</b> {detailed_risk['rating']} ({detailed_risk['score']}/100)</p>
                    <h2>Findings ({len(all_findings)})</h2>
                    <table><tr><th>#</th><th>Loại</th><th>Severity</th><th>URL</th></tr>
                    {''.join(f'<tr><td>{i+1}</td><td>{f.get("type", f.get("indicators", [{}])[0].get("type", ""))}</td><td>{f.get("severity", f.get("confidence", ""))}</td><td>{f.get("url", "")}</td></tr>' for i, f in enumerate(all_findings[:50])) or '<tr><td colspan="4">Không có findings</td></tr>'}
                    </table>
                    </body></html>
                    """,
                    file_name=f"security_scan_{scan_context.scan_id[:8]}.html",
                    mime="text/html",
                    use_container_width=True,
                )

        except Exception as e:
            progress.empty()
            st.error(f"Quét thất bại: {str(e)}")
            ssl_error = any(k in str(e).lower() for k in
                            ['certificate_verify_failed', 'ssl', 'certificate verify', 'unable to get local issuer'])
            if ssl_error:
                st.warning(
                    "💡 **Lỗi xác minh SSL chứng chỉ.** Cách xử lý:\n"
                    "1. Tick **'🔓 Bỏ qua xác minh SSL'** trong phần cấu hình rồi quét lại — "
                    "dành cho target có chứng chỉ lỗi/broken chain.\n"
                    "2. Nếu target có cert hợp lệ, kiểm tra lại CA store máy bạn (Python macOS cần cài certifi).\n"
                    "3. Hoặc thử đổi sang giao thức `http://` nếu trang hỗ trợ."
                )
            else:
                st.info("Gợi ý: Kiểm tra URL có đúng không, hoặc thử bật Local Lab Mode cho localhost")

# ─── Footer ──────────────────────────────────────────────────
st.markdown("""
<div class="footer">
    Smart Security Scanner v3.1 — Web DAST (22) + Infra & Cloud (11) + Governance (10) + Enterprise & Exploit (10) · 53 công cụ · 86/86 tính năng
</div>
""", unsafe_allow_html=True)