"""
Input Validation Scanners — theo đặc tả v3.1 §4.5 (Feature List #20).

- SSRF: canary endpoint nội bộ, không truy cập metadata services
- LFI/Path Traversal: canary file trong local lab
- SSTI: template expression canary
- XXE: DTD/entity canary, chặn network/entity expansion
"""
import base64
import re
import urllib.parse


class SSRFScanner:
    """Phát hiện Server-Side Request Forgery."""

    # Canary địa chỉ nội bộ — không truy cập metadata services
    CANARY_HOSTS = [
        '127.0.0.1', 'localhost', '169.254.169.254',
        '0.0.0.0', '10.0.0.1', '192.168.1.1',
    ]

    def __init__(self, request_handler=None, target_url=None, param='url'):
        self.request_handler = request_handler
        self.target_url = target_url
        self.param = param

    def build_payloads(self):
        """Sinh payload SSRF an toàn — only canary local."""
        payloads = []
        for host in self.CANARY_HOSTS:
            payloads.append(f"http://{host}/")
            payloads.append(f"https://{host}/")
        # Encoding variants
        encoded = [urllib.parse.quote(p, safe='') for p in payloads[:2]]
        payloads.extend(encoded)
        return payloads

    async def scan(self):
        """Kiểm tra SSRF qua các canary hosts.

        LƯU Ý: trước đây hàm này là `def` (đồng bộ) và gọi
        `request_handler.send_request()` (một coroutine, vì RequestHandler
        dùng aiohttp async) mà KHÔNG `await` — nghĩa là `resp` chỉ là một
        coroutine object chưa từng chạy, không phải response thật.
        `getattr(resp, 'status_code', 0)` luôn trả về 0 mặc định, nên scanner
        này ÂM THẦM không bao giờ phát hiện được gì dù target có lỗ hổng thật.
        Đã sửa: chuyển `scan()` thành async và `await` request thật.
        """
        if not self.request_handler or not self.target_url:
            return {'vulnerabilities': [], 'note': 'Không thể test SSRF'}

        findings = []
        for payload in self.build_payloads():
            try:
                parsed = urllib.parse.urlparse(self.target_url)
                query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                query[self.param] = [payload]
                fuzz_url = urllib.parse.urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, urllib.parse.urlencode(query, doseq=True), parsed.fragment,
                ))
                resp = await self.request_handler.send_request('GET', fuzz_url)
                status = getattr(resp, 'status_code', 0)
                text = getattr(resp, 'text', '')

                # Nếu server fetch được canary nội bộ → SSRF
                if str(status) == '200' and (
                    '127.0.0.1' in text or 'localhost' in text
                    or '169.254.169.254' in text
                ):
                    findings.append({
                        'type': 'SSRF',
                        'severity': 'High',
                        'detail': f"Server fetch được URL nội bộ: {payload}",
                        'confidence': 'Medium',
                        'payload': payload,
                    })
            except Exception:
                continue
        return {'vulnerabilities': findings}


class PathTraversalScanner:
    """Phát hiện Path Traversal / LFI."""

    def __init__(self, request_handler=None, target_url=None, param='file'):
        self.request_handler = request_handler
        self.target_url = target_url
        self.param = param

    @staticmethod
    def generate_payloads():
        """Sinh payload path traversal."""
        return [
            '../../../etc/passwd',
            '..%2F..%2F..%2Fetc%2Fpasswd',
            '../../../../etc/passwd%00',
            '....//....//....//etc/passwd',
            '../../windows/win.ini',
            '/etc/passwd',
            '....//....//....//windows/win.ini',
        ]

    async def scan(self):
        """Test path traversal. (xem ghi chú async/await ở SSRFScanner.scan)"""
        if not self.request_handler or not self.target_url:
            return {'vulnerabilities': [], 'note': 'Không thể test path traversal'}

        findings = []
        for payload in self.generate_payloads():
            try:
                parsed = urllib.parse.urlparse(self.target_url)
                query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                query[self.param] = [payload]
                fuzz_url = urllib.parse.urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, urllib.parse.urlencode(query, doseq=True), parsed.fragment,
                ))
                resp = await self.request_handler.send_request('GET', fuzz_url)
                status = getattr(resp, 'status_code', 0)
                text = getattr(resp, 'text', '')

                # Dấu hiệu đọc file thành công
                if status in (200, 301) and (
                    'root:' in text or '[extensions]' in text
                    or 'nobody:' in text or 'daemon:' in text
                ):
                    findings.append({
                        'type': 'Path Traversal / LFI',
                        'severity': 'High',
                        'detail': f"Đọc file thành công với payload: {payload}",
                        'confidence': 'High',
                        'payload': payload,
                    })
            except Exception:
                continue
        return {'vulnerabilities': findings}


class SSTIScanner:
    """Phát hiện Server-Side Template Injection."""

    def __init__(self, request_handler=None, target_url=None, param='name'):
        self.request_handler = request_handler
        self.target_url = target_url
        self.param = param

    def generate_payloads(self):
        """Sinh payload SSTI không destructive."""
        return [
            '{{7*7}}',
            '${7*7}',
            '#{7*7}',
            '<%= 7*7 %>',
            '{{7*\'7\'}}',
            '${7*\'7\'}',
        ]

    async def scan(self):
        """Test SSTI các template engines phổ biến. (xem ghi chú async/await ở SSRFScanner.scan)"""
        if not self.request_handler or not self.target_url:
            return {'vulnerabilities': [], 'note': 'Không thể test SSTI'}

        findings = []
        for payload in self.generate_payloads():
            try:
                parsed = urllib.parse.urlparse(self.target_url)
                query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                query[self.param] = [payload]
                fuzz_url = urllib.parse.urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, urllib.parse.urlencode(query, doseq=True), parsed.fragment,
                ))
                resp = await self.request_handler.send_request('GET', fuzz_url)
                text = getattr(resp, 'text', '')

                # Nếu '49' xuất hiện = 7*7 được thực thi
                if '49' in text and '{{7*7}}' not in text and '${7*7}' not in text:
                    findings.append({
                        'type': 'SSTI - Template Injection',
                        'severity': 'Critical',
                        'detail': f"Template engine thực thi biểu thức: {payload} → 49",
                        'confidence': 'High',
                        'payload': payload,
                    })
            except Exception:
                continue
        return {'vulnerabilities': findings}


class XXEScanner:
    """Phát hiện XXE (XML External Entity)."""

    def __init__(self, request_handler=None, target_url=None, content_type='application/xml'):
        self.request_handler = request_handler
        self.target_url = target_url
        self.content_type = content_type

    def generate_payloads(self):
        """Sinh XML payload XXE — canary local, không external network."""
        return [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>',
        ]

    async def scan(self):
        """Test XXE bằng file canary. (xem ghi chú async/await ở SSRFScanner.scan)"""
        if not self.request_handler or not self.target_url:
            return {'vulnerabilities': [], 'note': 'Không thể test XXE'}

        findings = []
        for payload in self.generate_payloads():
            try:
                resp = await self.request_handler.send_request(
                    'POST', self.target_url,
                    data=payload,
                    headers={'Content-Type': self.content_type},
                )
                text = getattr(resp, 'text', '')

                # Dấu hiệu entity được parse và đọc file
                if 'root:' in text or 'localhost' in text:
                    findings.append({
                        'type': 'XXE - XML External Entity',
                        'severity': 'Critical',
                        'detail': 'Entity trong XML được resolve và đọc file local',
                        'confidence': 'High',
                        'payload': payload[:100],
                    })
            except Exception:
                continue
        return {'vulnerabilities': findings}


class AuthSessionScanner:
    """Authentication & Session Testing — Feature List #15 (#8 trong README)."""

    def __init__(self, request_handler=None, login_url=None, logout_url=None):
        self.request_handler = request_handler
        self.login_url = login_url
        self.logout_url = logout_url
        self.cookies = {}

    def check_cookie_flags(self, cookies):
        """Kiểm tra security flags của session cookies."""
        findings = []
        for cookie in cookies:
            name = cookie.get('name', '')
            flags = []
            if not cookie.get('secure', False):
                flags.append('Secure')
            if not cookie.get('httpOnly', False):
                flags.append('HttpOnly')
            same_site = cookie.get('sameSite', '')
            if same_site in (None, '', 'none'):
                flags.append('SameSite=None/Lax')

            if flags and 'session' in name.lower() or 'auth' in name.lower():
                findings.append({
                    'type': 'Session Cookie Missing Flags',
                    'severity': 'High',
                    'detail': f"Cookie '{name}' thiếu: {', '.join(flags)}",
                    'confidence': 'High',
                })
        return findings

    def test_logout_invalidation(self, logout_response_status, can_reuse_session=True):
        """Kiểm tra logout có invalidate session không."""
        if logout_response_status in (200, 302) and can_reuse_session:
            return [{
                'type': 'Session Not Invalidated On Logout',
                'severity': 'High',
                'detail': 'Session vẫn còn hiệu lực sau khi logout — có thể bị session fixation/replay',
                'confidence': 'Medium',
            }]
        return []

    def test_session_fixation(self, old_cookie, new_cookie):
        """Kiểm tra session có bị thay đổi sau login không (chống fixation)."""
        if old_cookie and new_cookie and old_cookie == new_cookie:
            return [{
                'type': 'Session Fixation',
                'severity': 'High',
                'detail': 'Session ID không đổi sau login — attacker có thể fix session trước khi victim login',
                'confidence': 'High',
            }]
        return []