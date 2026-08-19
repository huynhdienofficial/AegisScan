import streamlit as st
import asyncio
import pandas as pd
import json
from playwright.async_api import async_playwright

from discovery.api_discovery import APIDiscovery
from scanners.passive_scanner import SecurityHeaderScanner, CookieScanner
from scanners.active_scanner import ActiveScanner
from fingerprint.technology_detector import TechnologyDetector

from fingerprint.attack_surface.risk_engine import RiskEngine
from fingerprint.attack_surface.exploit_manager import ExploitManager

from utils.request_handler import RequestHandler
from utils.scope_guard import ScopeGuard, ScanContext
from utils.safety_profiles import SafetyManager
from crawler_core import AsyncCrawlerEngine


st.set_page_config(page_title="Smart Security Scanner", layout="wide")
st.title("🛡️ Smart Security Scanner")


def build_report_payload(urls, params, passive_findings, active_findings, tech, apis, risk):
    return {
        "summary": {
            "target": target_url,
            "urls_found": len(urls),
            "parameters_found": len(params),
            "passive_issues": len(passive_findings),
            "active_vulns": len(active_findings),
            "risk_score": risk.get("score", 0),
            "risk_rating": risk.get("rating", "Unknown"),
        },
        "passive_findings": passive_findings,
        "active_findings": active_findings,
        "technologies": tech,
        "apis": apis,
    }


def render_html_report(report_payload):
    passive_rows = "".join(
        f"<tr><td>{item.get('type', 'N/A')}</td><td>{item.get('severity', 'N/A')}</td><td>{item.get('detail', 'N/A')}</td></tr>"
        for item in report_payload.get("passive_findings", [])
    ) or '<tr><td colspan="3">No passive findings</td></tr>'

    active_rows = "".join(
        f"<tr><td>{item.get('url', 'N/A')}</td><td>{item.get('parameter', 'N/A')}</td><td>{item.get('payload', 'N/A')}</td><td>{item.get('confidence', 'Low')}</td></tr>"
        for item in report_payload.get("active_findings", [])
    ) or '<tr><td colspan="4">No active vulnerabilities</td></tr>'

    api_rows = "".join(
        f"<tr><td>{item.get('method', 'GET')}</td><td>{item.get('url', 'N/A')}</td></tr>"
        for item in report_payload.get("apis", [])
    ) or '<tr><td colspan="2">No API endpoints discovered</td></tr>'

    html = f"""
    <html>
    <head>
        <meta charset="utf-8" />
        <title>Smart Security Scanner Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 24px; color: #1f2937; }}
            h1 {{ color: #111827; }}
            .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin: 16px 0; }}
            .card {{ background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 8px; padding: 12px; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
            th, td {{ border: 1px solid #d1d5db; padding: 8px; text-align: left; vertical-align: top; }}
            th {{ background: #eef2ff; }}
        </style>
    </head>
    <body>
        <h1>Smart Security Scanner Report</h1>
        <div class="grid">
            <div class="card"><strong>Target</strong><br>{report_payload['summary']['target']}</div>
            <div class="card"><strong>URLs Found</strong><br>{report_payload['summary']['urls_found']}</div>
            <div class="card"><strong>Parameters</strong><br>{report_payload['summary']['parameters_found']}</div>
            <div class="card"><strong>Risk Score</strong><br>{report_payload['summary']['risk_score']}</div>
            <div class="card"><strong>Risk Rating</strong><br>{report_payload['summary']['risk_rating']}</div>
        </div>

        <h2>Passive Findings</h2>
        <table>
            <tr><th>Type</th><th>Severity</th><th>Detail</th></tr>
            {passive_rows}
        </table>

        <h2>Active Findings</h2>
        <table>
            <tr><th>URL</th><th>Parameter</th><th>Payload</th><th>Confidence</th></tr>
            {active_rows}
        </table>

        <h2>Discovered APIs</h2>
        <table>
            <tr><th>Method</th><th>URL</th></tr>
            {api_rows}
        </table>
    </body>
    </html>
    """
    return html


# ───────────── Sidebar: Cấu hình ─────────────
target_url = st.sidebar.text_input("Target URL", "https://books.toscrape.com/")
st.sidebar.markdown("---")

# Bước 7: Safety Profile
profile = st.sidebar.selectbox(
    "Safety Profile",
    ["safe-active", "passive", "authenticated", "deep-lab", "ci-fast"],
    index=0,
    help="passive: không inject | safe-active: mặc định | authenticated: có session | deep-lab: lab cô lập | ci-fast: regression nhanh"
)
st.sidebar.caption("🔒 Profile: an toàn mặc định")

scan_sqli = st.sidebar.checkbox("SQL Injection", value=True)
scan_xss = st.sidebar.checkbox("XSS", value=True)
scan_rce = st.sidebar.checkbox("RCE", value=True)
concurrency = st.sidebar.slider("Concurrency", 1, 10, 3)

# Bước 7: Scope Guard
local_lab = st.sidebar.checkbox("Local Lab Mode", value=False,
                                 help="Cho phép quét localhost/LAN")
allowlist_input = st.sidebar.text_input("Allowlist (phân cách bằng phẩy)", "",
                                        help="VD: example.com, *.staging.com, 192.168.1.0/24")
confirm_authorization = st.sidebar.checkbox("Tôi có quyền kiểm thử target này", value=False)

st.sidebar.markdown("---")
st.sidebar.info("🛡️ **Safety Check:** Chỉ quét target bạn có quyền kiểm thử. Mặc định chặn localhost/LAN.")


# ───────────── Main: Bắt đầu scan ─────────────
if st.sidebar.button("🚀 Start Scan"):
    # ─── Scope Guard ─────────────────────────────────────────────
    allowlist = [item.strip() for item in allowlist_input.split(',')] if allowlist_input else []
    scope_guard = ScopeGuard({
        'allowlist': allowlist,
        'local_lab_mode': local_lab,
    })

    # Kiểm tra quyền truy cập
    auth_result = scope_guard.authorize_target(target_url, confirm=confirm_authorization)
    scope_guard.audit_log('authorize', target_url, auth_result)

    if not auth_result['allowed']:
        st.error(f"🚫 {auth_result.get('reason', 'Target bị chặn')}")
        st.info("Gợi ý: Bật Local Lab Mode để quét localhost/LAN, hoặc thêm vào allowlist, hoặc xác nhận quyền kiểm thử.")
        st.stop()

    if auth_result.get('requires_confirmation'):
        st.warning(f"⚠️ {auth_result.get('reason')}")
        st.info("Hãy đánh dấu checkbox 'Tôi có quyền kiểm thử target này' và quét lại.")
        st.stop()

    # ─── Safety Manager ──────────────────────────────────────────
    safety_manager = SafetyManager(profile, scope_guard)
    scan_context = ScanContext(target_url, scope_guard, profile=profile)
    scan_context.compute_config_hash({
        'profile': profile,
        'concurrency': concurrency,
    })

    st.info(f"Scanning: {target_url}")
    st.caption(f"📋 Scan ID: {scan_context.scan_id} | Profile: {profile}")

    progress_bar = st.progress(0)
    status_text = st.empty()

    # Crawl
    status_text.text("📡 Crawling target...")
    progress_bar.progress(0.2)

    profile_cfg = safety_manager.profile.config
    config = {
        'max_pages': profile_cfg.get('max_pages', 50),
        'concurrency': concurrency,
        'headless': True,
        'max_depth': profile_cfg.get('max_depth', 3),
    }
    crawler = AsyncCrawlerEngine(config, scope_guard=scope_guard)

    try:
        crawl_results = asyncio.run(crawler.start(target_url))
        urls = crawl_results['urls']
        parameters = crawl_results['parameters']
        forms = crawl_results.get('forms', [])
        scope_blocked = crawl_results.get('scope_blocked', 0)
        st.success(f"✅ Found {len(urls)} URLs, {len(parameters)} parameters, {len(forms)} forms")
        if scope_blocked:
            st.warning(f"🚫 {scope_blocked} URL bị chặn bởi scope guard")
    except Exception as e:
        st.error(f"❌ Crawl error: {str(e)}")
        st.stop()

    # Passive Scan
    status_text.text("🛡️ Running passive scan...")
    progress_bar.progress(0.4)

    passive_findings = []

    async def passive_scan():
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            page = await context.new_page()

            api_detector = APIDiscovery()
            await api_detector.attach(page)

            response = await page.goto(target_url, wait_until="networkidle")
            headers = response.headers
            cookies = await context.cookies()
            html = await page.content()

            tech = TechnologyDetector.detect(headers, html)
            header_findings = SecurityHeaderScanner.scan(headers)
            cookie_findings = CookieScanner.scan(cookies)
            apis = api_detector.get_discovered_apis()

            await browser.close()
            return header_findings + cookie_findings, tech, apis

    try:
        passive_findings, tech, apis = asyncio.run(passive_scan())
        risk = RiskEngine.calculate(passive_findings)
    except Exception as e:
        st.error(f"❌ Passive scan error: {str(e)}")
        passive_findings = []
        tech = []
        apis = []
        risk = {'score': 0, 'rating': 'Unknown', 'metrics': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}}

    # Active Scan
    status_text.text("⚡ Running active scan...")
    progress_bar.progress(0.6)

    active_findings = []
    if scan_sqli or scan_xss or scan_rce:
        try:
            handler = RequestHandler(
                timeout=profile_cfg.get('timeout', 15),
                max_retries=3,
                safety_manager=safety_manager,
            )
            manager = ExploitManager(handler, scan_context=scan_context)

            scan_types = []
            if scan_sqli: scan_types.append('sqli')
            if scan_xss: scan_types.append('xss')
            if scan_rce: scan_types.append('rce')

            active_findings = asyncio.run(manager.run_scan(urls[:5], parameters[:5], scan_types, forms=forms[:5]))
        except Exception as e:
            st.error(f"❌ Active scan error: {str(e)}")

    progress_bar.progress(0.9)
    status_text.text("📊 Generating report...")

    report_payload = build_report_payload(urls, parameters, passive_findings, active_findings, tech, apis, risk)

    # Summary metrics
    col1, col2, col3, col4, col5, col6 = st.columns(6)
    col1.metric("URLs Found", len(urls))
    col2.metric("Parameters", len(parameters))
    col3.metric("Forms", len(forms))
    col4.metric("Passive Issues", len(passive_findings))
    col5.metric("Active Vulns", len(active_findings))
    col6.metric("Risk Score", risk.get("score", 0))

    st.markdown("---")
    st.subheader("📈 Risk Overview")
    risk_metrics = risk.get("metrics", {"critical": 0, "high": 0, "medium": 0, "low": 0})
    chart_df = pd.DataFrame({
        "Severity": ["Critical", "High", "Medium", "Low"],
        "Count": [
            risk_metrics.get("critical", 0),
            risk_metrics.get("high", 0),
            risk_metrics.get("medium", 0),
            risk_metrics.get("low", 0),
        ],
    })
    st.bar_chart(chart_df.set_index("Severity"), use_container_width=True)

    st.markdown("---")
    st.subheader("📋 Scan Results")

    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs(
        ["Passive Scan", "Active Scan", "Technologies", "APIs", "Safety Log", "Reports"]
    )

    with tab1:
        if passive_findings:
            st.dataframe(pd.DataFrame(passive_findings))
        else:
            st.success("✅ No passive issues found")

    with tab2:
        if active_findings:
            vuln_data = []
            for v in active_findings:
                vuln_data.append({
                    'URL': v.get('url', ''),
                    'Parameter': v.get('parameter', ''),
                    'Payload': v.get('payload', '')[:50] + '...',
                    'Confidence': v.get('confidence', 'Low'),
                    'Method': v.get('method', 'GET'),
                })
            st.dataframe(pd.DataFrame(vuln_data))
        else:
            st.success("✅ No active vulnerabilities found")

    with tab3:
        if tech:
            st.table(pd.DataFrame(tech))
        else:
            st.info("No technologies detected")

    with tab4:
        if apis:
            api_df = pd.DataFrame(apis)
            method_summary = api_df.groupby("method").size().reset_index(name="count")
            st.dataframe(api_df)
            st.caption("API method distribution")
            st.bar_chart(method_summary.set_index("method"), use_container_width=True)
        else:
            st.info("No APIs discovered")

    with tab5:
        # Hiển thị Safety Log
        safety_stats = safety_manager.get_stats()
        st.write(f"**Safety Profile:** {safety_stats['profile']['name']}")
        st.write(f"**Mô tả:** {safety_stats['profile']['description']}")
        st.write(f"**RPS Limit:** {safety_stats['rate_limiter']['rps_limit']}")
        st.write(f"**Requests sent:** {safety_stats['rate_limiter']['total_requests']}")
        st.write(f"**Requests throttled:** {safety_stats['rate_limiter']['blocked_requests']}")
        st.write(f"**Circuit breaker state:** {safety_stats['circuit_breaker']['state']}")
        st.write(f"**Payloads blocked by safety:** {safety_stats['total_blocked']}")
        if safety_stats['block_log']:
            st.write("**Block log:**")
            st.dataframe(pd.DataFrame(safety_stats['block_log']))

    with tab6:
        st.write(f"**Overall risk rating:** {risk.get('rating', 'Unknown')}")
        st.write(f"**Risk score:** {risk.get('score', 0)}")
        st.write(f"**Scan ID:** {scan_context.scan_id}")
        st.write(f"**Safety Profile:** {profile}")
        st.download_button(
            label="⬇️ Download JSON report",
            data=json.dumps(report_payload, ensure_ascii=False, indent=2),
            file_name="smart_security_scan_report.json",
            mime="application/json",
        )
        st.download_button(
            label="⬇️ Download HTML report",
            data=render_html_report(report_payload),
            file_name="smart_security_scan_report.html",
            mime="text/html",
        )

    progress_bar.progress(1.0)
    status_text.text("✅ Scan completed!")
    st.balloons()