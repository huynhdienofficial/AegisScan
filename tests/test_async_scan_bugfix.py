"""
Regression test cho lỗi async/await bị thiếu ở 5 scanner file
(input_validation.py, jwt_scanner.py, graphql_scanner.py, websocket_scanner.py,
file_upload_scanner.py).

Bug gốc: `request_handler.send_request()` là `async def` (RequestHandler dùng
aiohttp), nhưng các hàm `scan()`/helper bên trong các file trên là `def`
đồng bộ và gọi `send_request(...)` KHÔNG `await`. Kết quả: biến `resp` chỉ
là một coroutine object CHƯA TỪNG CHẠY — không phải response thật.
`getattr(resp, 'status_code', 0)` luôn trả về giá trị mặc định vì coroutine
không có attribute đó, nên các scanner này ÂM THẦM không bao giờ phát hiện
được lỗ hổng, kể cả khi target thực sự có lỗ hổng.

Test cũ trong repo chỉ test nhánh "không có handler" (request_handler=None)
nên chưa bao giờ phát hiện ra bug này. Test dưới đây dùng một fake async
handler trả lời "có lỗ hổng" để xác nhận scanner bây giờ THỰC SỰ phát hiện
được — nếu vô tình có ai gỡ `await` ra lần nữa, test này sẽ fail.
"""
import asyncio
import json
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SMART = ROOT / 'smart_scanner'
sys.path.insert(0, str(SMART))

from scanners.web.input_validation import SSRFScanner, PathTraversalScanner, SSTIScanner, XXEScanner
from scanners.web.jwt_scanner import JWTScanner
from scanners.web.graphql_scanner import GraphQLScanner
from scanners.web.websocket_scanner import WebSocketScanner
from scanners.web.file_upload_scanner import FileUploadScanner
from scanners.web.advanced_scanners import WAFEvasionScanner, RequestSmugglingScanner
from governance import BusinessLogicScanner


class FakeAsyncHandler:
    """Giả lập RequestHandler — send_request là async, trả về response cấu
    hình sẵn để mô phỏng một target thực sự dễ tổn thương."""

    def __init__(self, status_code=200, text='', headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}

    async def send_request(self, method, url, params=None, data=None, headers=None):
        await asyncio.sleep(0)  # đảm bảo thực sự đi qua event loop, không phải no-op
        return SimpleNamespace(status_code=self.status_code, text=self.text, headers=self.headers)


def test_ssrf_scanner_detects_with_real_async_handler():
    handler = FakeAsyncHandler(status_code=200, text='connected to 127.0.0.1 internal service')
    scanner = SSRFScanner(request_handler=handler, target_url='https://x.com/fetch?url=x')
    result = asyncio.run(scanner.scan())
    assert len(result['vulnerabilities']) > 0, (
        "SSRFScanner phải phát hiện được khi response chứa dấu hiệu SSRF thật "
        "— nếu rỗng nghĩa là await đã bị gỡ và bug đã quay lại"
    )


def test_path_traversal_scanner_detects_with_real_async_handler():
    handler = FakeAsyncHandler(status_code=200, text='root:x:0:0:root:/root:/bin/bash\nnobody:x:99:99::')
    scanner = PathTraversalScanner(request_handler=handler, target_url='https://x.com/read?file=x')
    result = asyncio.run(scanner.scan())
    assert len(result['vulnerabilities']) > 0


def test_ssti_scanner_detects_with_real_async_handler():
    handler = FakeAsyncHandler(status_code=200, text='Result: 49')
    scanner = SSTIScanner(request_handler=handler, target_url='https://x.com/hello?name=x')
    result = asyncio.run(scanner.scan())
    assert len(result['vulnerabilities']) > 0


def test_xxe_scanner_detects_with_real_async_handler():
    handler = FakeAsyncHandler(status_code=200, text='root:x:0:0:root:/root:/bin/bash')
    scanner = XXEScanner(request_handler=handler, target_url='https://x.com/upload')
    result = asyncio.run(scanner.scan())
    assert len(result['vulnerabilities']) > 0


def test_jwt_scanner_alg_none_detects_with_real_async_handler():
    token = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.sig'
    handler = FakeAsyncHandler(status_code=200, text='{"data": "authenticated"}')
    scanner = JWTScanner(
        request_handler=handler, jwt_token=token,
        jwt_header={'url': 'https://x.com/api/me'},
    )
    result = asyncio.run(scanner.scan())
    assert len(result['vulnerabilities']) > 0, (
        "JWTScanner phải phát hiện alg:none được server chấp nhận (status != 401)"
    )


def test_graphql_scanner_introspection_detects_with_real_async_handler():
    handler = FakeAsyncHandler(
        status_code=200,
        text=json.dumps({'data': {'__schema': {'types': [{'name': 'Query'}]}}}),
    )
    scanner = GraphQLScanner(request_handler=handler, graphql_url='https://x.com/graphql')
    result = asyncio.run(scanner.scan())
    assert any(v['type'] == 'GraphQL Introspection Enabled' for v in result['vulnerabilities'])


def test_websocket_scanner_origin_detects_with_real_async_handler():
    handler = FakeAsyncHandler(status_code=101, text='', headers={'Upgrade': 'websocket'})
    scanner = WebSocketScanner(request_handler=handler, ws_url='wss://x.com/ws')
    result = asyncio.run(scanner.scan())
    assert any(v['type'] == 'WebSocket Origin Not Validated' for v in result['vulnerabilities'])


def test_file_upload_scanner_detects_with_real_async_handler():
    handler = FakeAsyncHandler(status_code=200, text='upload successful')
    scanner = FileUploadScanner(request_handler=handler, upload_url='https://x.com/upload')
    result = asyncio.run(scanner.scan())
    assert any(v['type'] == 'File Upload Bypass' for v in result['vulnerabilities'])


def test_waf_evasion_scanner_detects_with_real_async_handler():
    handler = FakeAsyncHandler(status_code=200, text="' OR 1=1--")
    scanner = WAFEvasionScanner(request_handler=handler)
    result = asyncio.run(scanner.scan('https://x.com/search?q=1', 'q', payloads=["' OR 1=1--"]))
    assert len(result) > 0, (
        "WAFEvasionScanner phải phát hiện được khi payload encoded được phản chiếu trong response"
    )


def test_request_smuggling_scanner_detects_with_real_async_handler():
    handler = FakeAsyncHandler(status_code=200, text='ok')
    scanner = RequestSmugglingScanner(request_handler=handler, target_url='https://x.com/')
    result = asyncio.run(scanner.scan())
    assert len(result['vulnerabilities']) > 0


def test_business_logic_scanner_detects_with_real_async_handler():
    handler = FakeAsyncHandler(status_code=200, text='{"status": "ok"}')
    scanner = BusinessLogicScanner(request_handler=handler, base_url='https://x.com')
    result = asyncio.run(scanner.scan_price_logic('/checkout'))
    assert len(result['vulnerabilities']) > 0, (
        "BusinessLogicScanner phải phát hiện khi server chấp nhận giá trị "
        "price/quantity bất thường (status 200, không có 'error' trong response)"
    )
