import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SMART = ROOT / 'smart_scanner'
sys.path.insert(0, str(SMART))

from scanners.web.security_misconfig import (
    CORSScanner,
    CSRFScanner,
    AuthorizationScanner,
    OpenAPIDiscovery,
    HTTPMethodScanner,
)


def test_cors_scanner_detects_wildcard():
    """CORSScanner phát hiện wildcard origin."""
    scanner = CORSScanner()
    findings = scanner.scan_headers({
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Credentials': 'true',
    })

    types = [f['type'] for f in findings]
    assert 'CORS Wildcard Origin' in types
    assert 'CORS Wildcard With Credentials' in types
    # Wildcard with credentials = Critical
    critical = [f for f in findings if f['severity'] == 'Critical']
    assert len(critical) >= 1


def test_cors_scanner_clean_headers():
    """CORSScanner không báo lỗi với headers an toàn."""
    scanner = CORSScanner()
    findings = scanner.scan_headers({
        'Access-Control-Allow-Origin': 'https://trusted.com',
        'Access-Control-Allow-Credentials': 'true',
    })
    # Không có wildcard → không báo Critical
    assert not any(f['severity'] == 'Critical' for f in findings)


def test_csrf_scanner_missing_token():
    """CSRFScanner phát hiện form thiếu CSRF token."""
    scanner = CSRFScanner(
        target_url='https://x.com/login',
        method='POST',
        cookie_samesite='None',
    )
    scanner.set_form_data([
        {'name': 'username', 'type': 'text'},
        {'name': 'password', 'type': 'password'},
    ])

    findings = scanner.scan()
    types = [f['type'] for f in findings]
    assert 'Missing CSRF Token' in types
    assert 'Cookie SameSite=None' in types


def test_csrf_scanner_with_token():
    """CSRFScanner không báo lỗi khi form có CSRF token."""
    scanner = CSRFScanner(
        target_url='https://x.com/login',
        method='POST',
        cookie_samesite='Strict',
    )
    scanner.set_form_data([
        {'name': 'username', 'type': 'text'},
        {'name': 'csrf_token', 'type': 'hidden'},
    ])

    findings = scanner.scan()
    assert not any(f['type'] == 'Missing CSRF Token' for f in findings)


def test_authorization_idor_detection():
    """AuthorizationScanner phát hiện IDOR."""
    scanner = AuthorizationScanner()

    class FakeResponse:
        def __init__(self, status, text):
            self.status_code = status
            self.text = text

    # User B truy cập cùng dữ liệu với User A → IDOR
    findings = scanner.compare_responses(
        FakeResponse(200, '{"name": "user_a", "email": "a@x.com"}'),
        FakeResponse(200, '{"name": "user_a", "email": "a@x.com"}'),
        resource_desc='Profile user A',
    )
    assert any(f['type'] == 'IDOR - Horizontal Access' for f in findings)

    # User B bị chặn → an toàn
    findings_safe = scanner.compare_responses(
        FakeResponse(200, '{"name": "user_a"}'),
        FakeResponse(403, 'Forbidden'),
    )
    assert len(findings_safe) == 0


def test_authorization_unauthenticated():
    """AuthorizationScanner phát hiện truy cập không auth."""
    scanner = AuthorizationScanner()

    class FakeResponse:
        status_code = 200
        text = '{"data": "sensitive"}'

    findings = scanner.test_unauthenticated_access(FakeResponse(), resource_desc='/admin')
    assert len(findings) == 1
    assert findings[0]['severity'] == 'High'


def test_openapi_discovery_parse():
    """OpenAPIDiscovery parse schema hữu ích."""
    schema = {
        'openapi': '3.0.0',
        'paths': {
            '/users/{id}': {
                'get': {'operationId': 'getUser', 'summary': 'Get user'},
                'delete': {'operationId': 'deleteUser'},
            },
            '/login': {
                'post': {'operationId': 'login'},
            },
        },
    }
    discovery = OpenAPIDiscovery()
    discovery.schema = {'url': 'https://x.com/openapi.json', 'schema': schema}

    paths = discovery.parse_paths()
    assert len(paths) == 3
    methods = [p['method'] for p in paths]
    assert 'GET' in methods
    assert 'POST' in methods
    assert 'DELETE' in methods


def test_http_method_scanner_no_handler():
    """HTTPMethodScanner không có handler → trả về rỗng."""
    scanner = HTTPMethodScanner(request_handler=None, target_url=None)
    import asyncio
    findings = asyncio.run(scanner.scan_methods())
    assert findings == []