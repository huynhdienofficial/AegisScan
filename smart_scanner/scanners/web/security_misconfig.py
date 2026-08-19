"""
Security Misconfiguration Scanners — theo đặc tả v3.1 (Feature List #14, #16-19).

- CORS Misconfiguration Check (#18): wildcard origin, reflected Origin, credentialed CORS
- CSRF Detection (#17): anti-CSRF token, SameSite
- Authorization/IDOR Testing (#16): so sánh response giữa các role
- OpenAPI/Swagger Discovery (#14): import schema + parse paths/methods
- HTTP Security Methods (#19): TRACE/OPTIONS abuse
"""
import json


class CORSScanner:
    """Phát hiện CORS misconfiguration."""

    def __init__(self, request_handler=None, target_url=None):
        self.request_handler = request_handler
        self.target_url = target_url

    def scan_headers(self, response_headers):
        """Phân tích CORS headers từ response."""
        headers = {k.lower(): v for k, v in (response_headers or {}).items()}
        findings = []

        acao = headers.get('access-control-allow-origin', '')
        acac = headers.get('access-control-allow-credentials', '')

        # 1. Wildcard origin
        if acao == '*':
            findings.append({
                'type': 'CORS Wildcard Origin',
                'severity': 'Medium',
                'detail': "Access-Control-Allow-Origin: * — mọi origin có thể đọc response",
                'confidence': 'High',
            })

        # 2. Wildcard + credentials
        if acao == '*' and acac.lower() == 'true':
            findings.append({
                'type': 'CORS Wildcard With Credentials',
                'severity': 'Critical',
                'detail': "CORS cho phép * + credentials — attacker có thể đọc response chứa session",
                'confidence': 'High',
            })

        # 3. Credentials without explicit origin
        if acac.lower() == 'true' and acao and acao != '*':
            findings.append({
                'type': 'CORS Reflected Origin Risk',
                'severity': 'Low',
                'detail': f"CORS cho phép credentials với origin: {acao} — kiểm tra allowlist origin",
                'confidence': 'Low',
            })

        return findings

    async def test_reflected_origin(self):
        """Gửi request với Origin lạ → kiểm tra response có phản chiếu không."""
        if not self.request_handler or not self.target_url:
            return []

        try:
            resp = await self.request_handler.send_request(
                'GET', self.target_url,
                headers={'Origin': 'https://evil.attacker.com'},
            )
            headers = getattr(resp, 'headers', {}) or {}
            acao = headers.get('Access-Control-Allow-Origin', '')
            acac = headers.get('Access-Control-Allow-Credentials', '')

            # Nếu server phản chiếu Origin lạ + cho phép credentials → lỗ hổng
            if 'evil.attacker.com' in acao and acac.lower() == 'true':
                return [{
                    'type': 'CORS Reflected Origin With Credentials',
                    'severity': 'High',
                    'detail': f"Server phản chiếu Origin lạ '{acao}' + Allow-Credentials: true",
                    'confidence': 'High',
                }]
        except Exception:
            pass
        return []

    def async_scan(self):
        """Wrapper async scan."""
        import asyncio
        return asyncio.run(self.test_reflected_origin())


class CSRFScanner:
    """Phát hiện CSRF vulnerability."""

    def __init__(self, request_handler=None, target_url=None, method='POST',
                 form_action=None, cookie_samesite=None):
        self.request_handler = request_handler
        self.target_url = target_url
        self.method = method.upper()
        self.form_action = form_action or target_url
        self.cookie_samesite = cookie_samesite
        self.form_inputs = []

    def set_form_data(self, inputs):
        """Ghi nhận các inputs của form."""
        self.form_inputs = inputs

    def scan(self):
        """Kiểm tra form có anti-CSRF token không."""
        findings = []

        # 1. Form không có CSRF token
        if self.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
            has_csrf = any(
                'csrf' in i.get('name', '').lower()
                or 'token' in i.get('name', '').lower()
                or 'authenticity' in i.get('name', '').lower()
                for i in self.form_inputs
            )

            if not has_csrf:
                findings.append({
                    'type': 'Missing CSRF Token',
                    'severity': 'High',
                    'detail': f"Form {self.method} tại {self.form_action} không có anti-CSRF token",
                    'confidence': 'High',
                    'url': self.form_action,
                })

        # 2. Cookie SameSite thiếu
        if self.cookie_samesite is not None:
            if self.cookie_samesite.lower() == 'none':
                findings.append({
                    'type': 'Cookie SameSite=None',
                    'severity': 'Medium',
                    'detail': 'Cookie dùng SameSite=None — không chặn CSRF cross-site',
                    'confidence': 'High',
                })
            elif self.cookie_samesite.lower() not in ('strict', 'lax'):
                findings.append({
                    'type': 'Cookie Missing SameSite',
                    'severity': 'Low',
                    'detail': 'Cookie không thiết lập SameSite — nên dùng Strict/Lax',
                    'confidence': 'Medium',
                })

        return findings


class AuthorizationScanner:
    """Authorization/IDOR Testing — so sánh response giữa các user."""

    def __init__(self, request_handler=None):
        self.request_handler = request_handler

    def compare_responses(self, response_a, response_b, resource_desc=''):
        """
        So sánh response của 2 users trên cùng resource.
        response_a: user thuộc quyền (owner)
        response_b: user khác (không thuộc quyền — kiểm tra có bị truy cập không)
        """
        findings = []

        if response_a is None or response_b is None:
            return findings

        status_a = getattr(response_a, 'status_code', 0)
        status_b = getattr(response_b, 'status_code', 0)
        text_a = getattr(response_a, 'text', '')
        text_b = getattr(response_b, 'text', '')

        # Nếu user B cũng nhận được data như user A → IDOR
        if status_a in (200, 201) and status_b in (200, 201):
            if text_a == text_b:
                findings.append({
                    'type': 'IDOR - Horizontal Access',
                    'severity': 'High',
                    'detail': (
                        f"User B truy cập được resource của User A "
                        f"({resource_desc}) — dữ liệu giống hệt user A"
                    ),
                    'confidence': 'High',
                })
            elif len(text_b) > 100:  # Có dữ liệu nhưng khác — kiểm tra thêm
                findings.append({
                    'type': 'IDOR - Partial Access',
                    'severity': 'Medium',
                    'detail': (
                        f"User B nhận được data từ resource của User A "
                        f"({resource_desc}) — có thể rò rỉ một phần"
                    ),
                    'confidence': 'Low',
                })

        # Nếu user B không được phép → an toàn
        elif status_b in (401, 403):
            pass  # OK — authorization hoạt động

        return findings

    def test_unauthenticated_access(self, response_no_auth, resource_desc=''):
        """Replay request không có credential."""
        if response_no_auth is None:
            return []
        status = getattr(response_no_auth, 'status_code', 0)
        if status == 200:
            return [{
                'type': 'Unauthenticated Access',
                'severity': 'High',
                'detail': f"Resource '{resource_desc}' truy cập được KHÔNG cần authentication",
                'confidence': 'High',
            }]
        return []


class OpenAPIDiscovery:
    """Tìm và parse OpenAPI/Swagger schema."""

    OPENAPI_PATHS = [
        '/openapi.json', '/v1/openapi.json', '/api/openapi.json',
        '/swagger.json', '/v1/swagger.json', '/api/swagger.json',
        '/swagger/v1/swagger.json', '/api-docs', '/v2/api-docs',
    ]

    def __init__(self, request_handler=None, base_url=None):
        self.request_handler = request_handler
        self.base_url = base_url
        self.schema = None

    async def discover(self):
        """Tìm OpenAPI schema."""
        import asyncio
        from urllib.parse import urljoin

        if not self.request_handler or not self.base_url:
            return None

        for path in self.OPENAPI_PATHS:
            try:
                url = urljoin(self.base_url, path)
                resp = await self.request_handler.send_request('GET', url)
                status = getattr(resp, 'status_code', 0)
                text = getattr(resp, 'text', '')

                if status == 200 and text.strip().startswith('{'):
                    try:
                        schema = json.loads(text)
                        if 'openapi' in schema or 'swagger' in schema or 'paths' in schema:
                            self.schema = {
                                'url': url,
                                'schema': schema,
                            }
                            return self.schema
                    except json.JSONDecodeError:
                        continue
            except Exception:
                continue
        return None

    def parse_paths(self):
        """Đọc paths + methods từ schema."""
        if not self.schema:
            return []

        schema = self.schema['schema']
        paths = schema.get('paths', {})
        results = []

        for path, methods in paths.items():
            for method in methods.keys():
                if method.lower() in ('get', 'post', 'put', 'patch', 'delete', 'head', 'options'):
                    results.append({
                        'path': path,
                        'method': method.upper(),
                        'operation_id': methods.get(method, {}).get('operationId', ''),
                        'summary': methods.get(method, {}).get('summary', ''),
                        'parameters': methods.get(method, {}).get('parameters', []),
                    })
        return results


class HTTPMethodScanner:
    """Kiểm tra HTTP methods bất an toàn (TRACE/OPTIONS)."""

    UNSAFE_METHODS = ['TRACE', 'CONNECT', 'PATCH', 'DELETE']

    def __init__(self, request_handler=None, target_url=None):
        self.request_handler = request_handler
        self.target_url = target_url

    async def scan_methods(self):
        """Kiểm tra các method bất an toàn."""
        import asyncio
        findings = []

        if not self.request_handler or not self.target_url:
            return findings

        for method in self.UNSAFE_METHODS:
            try:
                resp = await self.request_handler.send_request(method, self.target_url)
                status = getattr(resp, 'status_code', 0)
                allow = getattr(resp, 'headers', {}).get('Allow', '')

                if status not in (400, 404, 405, 501):  # Server xử lý method
                    findings.append({
                        'type': f'Enabled HTTP Method: {method}',
                        'severity': 'Medium' if method == 'TRACE' else 'Low',
                        'detail': f"Server xử lý method {method} (status {status}){f' — Allow: {allow}' if allow else ''}",
                        'confidence': 'High',
                        'method': method,
                    })
            except Exception:
                continue

        return findings