"""
GraphQL Deep Scanner — theo đặc tả v3.1 §19.2 (Feature List #76-77).

- Introspection Detection: kiểm tra __schema có bị bật công khai không
- Alias Bombing: phát hiện DoS qua lặp alias
- Field Injection & Depth Attack
"""
import json


class GraphQLScanner:
    """Quét lỗ hổng GraphQL."""

    def __init__(self, request_handler, graphql_url=None):
        self.request_handler = request_handler
        self.graphql_url = graphql_url
        self.findings = []

    async def _send_query(self, query):
        """Gửi GraphQL query.

        LƯU Ý: `request_handler.send_request()` là async (aiohttp) — trước
        đây hàm này KHÔNG `await`, nên `resp` chỉ là coroutine chưa chạy;
        mọi test dựa vào `resp` (introspection/alias-bombing/field-injection)
        vì vậy luôn thất bại âm thầm. Đã sửa: chuyển sang async/await.
        """
        if not self.request_handler or not self.graphql_url:
            return None
        try:
            resp = await self.request_handler.send_request(
                'POST',
                self.graphql_url,
                data=json.dumps({'query': query}),
                headers={'Content-Type': 'application/json'},
            )
            return resp
        except Exception:
            return None

    async def test_introspection(self):
        """Kiểm tra Introspection có bật không."""
        query = """
        query {
          __schema {
            types { name }
          }
        }
        """
        resp = await self._send_query(query)
        if resp is None:
            return []

        try:
            data = json.loads(getattr(resp, 'text', '{}'))
            if '__schema' in data.get('data', {}):
                return [{
                    'type': 'GraphQL Introspection Enabled',
                    'severity': 'Medium',
                    'detail': 'GraphQL introspection __schema đang bật công khai — attacker có thể đọc toàn bộ schema',
                    'confidence': 'High',
                }]
        except Exception:
            pass
        return []

    async def test_alias_bombing(self):
        """Kiểm tra Alias Bombing (DoS)."""
        query = """
        query {
          __typename
          f0: __typename
          f1: __typename
          f2: __typename
          f3: __typename
          f4: __typename
          f5: __typename
          f6: __typename
          f7: __typename
          f8: __typename
          f9: __typename
        }
        """
        resp = await self._send_query(query)
        if resp is None:
            return []

        status = getattr(resp, 'status_code', 0)
        text = getattr(resp, 'text', '')

        # Nếu server thực thi (200) → có thể bị alias bombing
        if status == 200 and '__typename' in text:
            return [{
                'type': 'GraphQL Alias Bombing',
                'severity': 'Medium',
                'detail': ('GraphQL chấp nhận nhiều alias trong một query — '
                           'có thể bị Alias Bombing DoS nếu không giới hạn số alias'),
                'confidence': 'Low',
            }]
        return []

    async def test_field_injection(self):
        """Kiểm tra Field Injection qua introspection metadata."""
        query = """
        query {
          __schema {
            queryType {
              fields {
                name
                isDeprecated
              }
            }
          }
        }
        """
        resp = await self._send_query(query)
        if resp is None:
            return []

        try:
            data = json.loads(getattr(resp, 'text', '{}'))
            fields = data.get('data', {}).get('__schema', {}).get('queryType', {}).get('fields', [])
            if len(fields) > 20:
                return [{
                    'type': 'GraphQL Field Exposure',
                    'severity': 'Low',
                    'detail': f'API GraphQL expose {len(fields)} fields — kiểm tra field nội bộ bị lộ',
                    'confidence': 'Low',
                }]
        except Exception:
            pass
        return []

    async def scan(self):
        """Chạy toàn bộ GraphQL scan."""
        if not self.graphql_url:
            return {'vulnerabilities': [], 'note': 'Không có GraphQL URL để test'}

        all_findings = []
        all_findings.extend(await self.test_introspection())
        all_findings.extend(await self.test_alias_bombing())
        all_findings.extend(await self.test_field_injection())

        return {'vulnerabilities': all_findings}