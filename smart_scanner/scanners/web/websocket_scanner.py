"""
WebSocket Security Testing — theo đặc tả v3.1 §19.3 (Feature List #77).

- Origin Validation: kiểm tra xác thực Origin header khi handshake
- Rate Limiting: kiểm tra giới hạn message/connection
- CSWSH (Cross-Site WebSocket Hijacking)
"""
import json


class WebSocketScanner:
    """Quét lỗ hổng WebSocket (phân tích cấu hình, không connect thật qua network)."""

    def __init__(self, request_handler, ws_url=None):
        self.request_handler = request_handler
        self.ws_url = ws_url
        self.findings = []

    def test_origin_validation(self):
        """
        Kiểm tra origin validation qua HTTP request thử (GET upgrade).
        Không thực sự mở WebSocket — chỉ kiểm tra bằng probe request.
        """
        if not self.ws_url:
            return []

        # Chuyển ws:// → http:// để test handshake HTTP
        http_url = self.ws_url.replace('ws://', 'http://').replace('wss://', 'https://')

        findings = []
        # Test với nhiều Origin khác nhau
        malicious_origins = [
            'https://evil.com',
            'https://attacker.example.com',
            'null',  # sandboxed iframe
        ]

        for origin in malicious_origins:
            try:
                resp = self.request_handler.send_request(
                    'GET',
                    http_url,
                    headers={
                        'Origin': origin,
                        'Connection': 'Upgrade',
                        'Upgrade': 'websocket',
                        'Sec-WebSocket-Version': '13',
                        'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                    },
                )
                status = getattr(resp, 'status_code', 0)
                headers = getattr(resp, 'headers', {}) or {}
                upgrade_header = headers.get('Upgrade', headers.get('upgrade', ''))

                # Nếu server chấp nhận upgrade từ origin lạ → lỗ hổng
                if status in (101, 200) and 'websocket' in str(upgrade_header).lower():
                    findings.append({
                        'type': 'WebSocket Origin Not Validated',
                        'severity': 'High',
                        'detail': (
                            f'WebSocket handshake chấp nhận Origin={origin} — '
                            'có thể bị Cross-Site WebSocket Hijacking (CSWSH)'
                        ),
                        'confidence': 'High',
                    })
            except Exception:
                continue

        return findings

    def test_authentication(self):
        """Kiểm tra WebSocket có yêu cầu xác thực không."""
        if not self.ws_url:
            return []

        http_url = self.ws_url.replace('ws://', 'http://').replace('wss://', 'https://')
        try:
            # Gửi upgrade request KHÔNG có cookie/token
            resp = self.request_handler.send_request(
                'GET',
                http_url,
                headers={
                    'Connection': 'Upgrade',
                    'Upgrade': 'websocket',
                    'Sec-WebSocket-Version': '13',
                    'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                },
            )
            status = getattr(resp, 'status_code', 0)
            headers = getattr(resp, 'headers', {}) or {}
            upgrade_header = headers.get('Upgrade', headers.get('upgrade', ''))

            if status in (101, 200) and 'websocket' in str(upgrade_header).lower():
                return [{
                    'type': 'WebSocket No Authentication',
                    'severity': 'High',
                    'detail': 'WebSocket chấp nhận kết nối KHÔNG cần authentication — attacker có thể truy cập trực tiếp',
                    'confidence': 'Medium',
                }]
        except Exception:
            pass
        return []

    def test_rate_limiting(self):
        """Đánh giá cấu hình — không gửi nhiều request thật."""
        return [{
            'type': 'WebSocket Rate Limit',
            'severity': 'Info',
            'detail': 'Khuyến nghị kiểm tra thủ công giới hạn message/connection WebSocket để phát hiện DoS',
            'confidence': 'Low',
        }]

    def scan(self):
        """Chạy toàn bộ WebSocket scan."""
        if not self.ws_url:
            return {'vulnerabilities': [], 'note': 'Không có WebSocket URL để test'}

        all_findings = []
        all_findings.extend(self.test_origin_validation())
        all_findings.extend(self.test_authentication())
        all_findings.extend(self.test_rate_limiting())

        return {'vulnerabilities': all_findings}