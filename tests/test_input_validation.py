import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SMART = ROOT / 'smart_scanner'
sys.path.insert(0, str(SMART))

from scanners.web.input_validation import (
    SSRFScanner,
    PathTraversalScanner,
    SSTIScanner,
    XXEScanner,
    AuthSessionScanner,
)


def test_ssrf_generates_canary_payloads():
    """SSRFScanner sinh payload canary nội bộ."""
    scanner = SSRFScanner(request_handler=None)
    payloads = scanner.build_payloads()
    assert len(payloads) >= 4
    assert any('127.0.0.1' in p for p in payloads)
    assert any('169.254.169.254' in p for p in payloads)  # AWS metadata


def test_ssrf_no_handler():
    """SSRFScanner không có handler → trả về trống."""
    scanner = SSRFScanner(request_handler=None, target_url='https://x.com/fetch')
    result = scanner.scan()
    assert 'note' in result
    assert result['vulnerabilities'] == []


def test_path_traversal_payloads():
    """PathTraversalScanner sinh payload đa dạng."""
    payloads = PathTraversalScanner.generate_payloads()
    assert len(payloads) >= 7
    assert '../../../etc/passwd' in payloads
    assert '..%2F..%2F..%2Fetc%2Fpasswd' in payloads


def test_path_traversal_no_handler():
    """PathTraversalScanner không có handler."""
    scanner = PathTraversalScanner(request_handler=None, target_url='https://x.com/read')
    result = scanner.scan()
    assert 'note' in result


def test_ssti_payloads():
    """SSTIScanner sinh payload cho các template engines."""
    scanner = SSTIScanner(request_handler=None)
    payloads = scanner.generate_payloads()
    assert '{{7*7}}' in payloads  # Jinja2/Twig
    assert '${7*7}' in payloads   # Freemarker
    assert '#{7*7}' in payloads   # Thymeleaf


def test_ssti_no_handler():
    """SSTIScanner không có handler."""
    scanner = SSTIScanner(request_handler=None, target_url='https://x.com/hello')
    result = scanner.scan()
    assert 'note' in result


def test_xxe_payloads():
    """XXEScanner sinh XML payload."""
    scanner = XXEScanner(request_handler=None)
    payloads = scanner.generate_payloads()
    assert len(payloads) >= 2
    assert 'DOCTYPE' in payloads[0]
    assert 'xxe' in payloads[0]


def test_xxe_no_handler():
    """XXEScanner không có handler."""
    scanner = XXEScanner(request_handler=None, target_url='https://x.com/upload')
    result = scanner.scan()
    assert 'note' in result


def test_auth_session_cookie_flags():
    """AuthSessionScanner phát hiện cookie thiếu flags."""
    scanner = AuthSessionScanner()
    cookies = [
        {'name': 'sessionid', 'secure': False, 'httpOnly': False, 'sameSite': 'None'},
        {'name': 'csrf', 'secure': True, 'httpOnly': True, 'sameSite': 'Strict'},
    ]
    findings = scanner.check_cookie_flags(cookies)
    assert len(findings) >= 1
    assert findings[0]['severity'] == 'High'


def test_auth_session_logout_invalidation():
    """AuthSessionScanner phát hiện session không invalidate khi logout."""
    scanner = AuthSessionScanner()
    findings = scanner.test_logout_invalidation(200, can_reuse_session=True)
    assert len(findings) == 1
    assert findings[0]['type'] == 'Session Not Invalidated On Logout'