import aiohttp
import asyncio
import ssl

from .safety_profiles import SafetyManager

# Ưu tiên certifi CA bundle — sửa lỗi "unable to get local issuer certificate"
# khi CA store mặc định của hệ thống (đặc biệt Python trên macOS) thiếu/không đầy đủ
try:
    import certifi
    _CA_BUNDLE = certifi.where()
except ImportError:
    _CA_BUNDLE = None


class RequestHandler:
    def __init__(self, timeout=10, max_retries=3, safety_manager=None, max_response_mb=10, verify_ssl=True):
        self.timeout = timeout
        self.max_retries = max_retries
        self.safety_manager = safety_manager or SafetyManager('safe-active')
        self.max_response_mb = max_response_mb
        self.verify_ssl = verify_ssl
        self.session = None
        self.session_cookies = {}
        self.session_headers = {}

    def set_session_cookie(self, name, value):
        self.session_cookies[name] = value

    def set_session_header(self, name, value):
        self.session_headers[name] = value

    def cookie_header(self):
        return '; '.join(f'{k}={v}' for k, v in self.session_cookies.items())

    async def get_session(self):
        if not self.session:
            try:
                self.session = aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=self._build_ssl_context())
                )
            except TypeError:
                # Fallback nếu aiohttp version không hỗ trợ tham số
                self.session = aiohttp.ClientSession()
        return self.session

    def _build_ssl_context(self):
        """Tạo SSL context:
        - verify_ssl=True  → dùng certifi CA bundle (sửa lỗi CA store hệ thống thiếu)
        - verify_ssl=False → bỏ xác minh (dành cho target cert lỗi/broken chain khi scan)
        """
        if not self.verify_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx
        if _CA_BUNDLE:
            try:
                return ssl.create_default_context(cafile=_CA_BUNDLE)
            except Exception:
                pass
        return ssl.create_default_context()

    async def send_request(self, method, url, params=None, data=None, headers=None):
        # Kiểm tra safety manager (scope, method, payload)
        payload = None
        if data:
            if isinstance(data, dict):
                payload = str(data)
            else:
                payload = str(data)
        elif params:
            payload = str(params)

        check = self.safety_manager.check_request(method, url, payload)
        if not check['allowed']:
            return type('Response', (), {
                'status_code': 0,
                'text': f"BLOCKED: {check.get('reason', 'Safety policy denied')}",
                'headers': {},
                'blocked': True,
                'blocked_reason': check.get('reason', 'Unknown'),
            })()

        # Dry-run mode — không gửi request thật
        if self.safety_manager.profile.name == 'passive' and method not in ('GET', 'HEAD', 'OPTIONS'):
            # passive profile chỉ cho phép GET/HEAD/OPTIONS qua được check_request
            pass

        session = await self.get_session()

        request_headers = dict(self.session_headers)
        if headers:
            request_headers.update(headers)
        if self.session_cookies:
            request_headers.setdefault('Cookie', self.cookie_header())

        for attempt in range(self.max_retries):
            # Rate limiter trước khi gửi
            await self.safety_manager.wait_if_needed()

            try:
                async with session.request(
                    method=method,
                    url=url,
                    params=params,
                    data=data,
                    headers=request_headers or {},
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as response:
                    text = await response.text()
                    # Kiểm tra kích thước response
                    if len(text.encode('utf-8', errors='ignore')) > self.max_response_mb * 1024 * 1024:
                        self.safety_manager.on_failure()
                        return type('Response', (), {
                            'status_code': response.status,
                            'text': f"[RESPONSE TOO LARGE - over {self.max_response_mb}MB]",
                            'headers': dict(response.headers),
                            'truncated': True,
                        })()

                    for cookie_name, cookie_value in response.cookies.items():
                        self.session_cookies[cookie_name] = cookie_value.value

                    self.safety_manager.on_success()
                    return type('Response', (), {
                        'status_code': response.status,
                        'text': text,
                        'headers': dict(response.headers)
                    })()
            except aiohttp.TooManyRedirects:
                # Redirect loop — trả response giả lập, không làm chết scan
                self.safety_manager.on_failure()
                return type('Response', (), {
                    'status_code': 0,
                    'text': '[TOO MANY REDIRECTS — redirect loop]',
                    'headers': {},
                    'redirect_loop': True,
                })()
            except (aiohttp.ClientError, asyncio.TimeoutError, TimeoutError) as e:
                self.safety_manager.on_failure()
                if attempt == self.max_retries - 1:
                    # Không raise — trả response giả lập để scan tiếp tục các URL khác
                    return type('Response', (), {
                        'status_code': 0,
                        'text': f'[REQUEST FAILED: {type(e).__name__}]',
                        'headers': {},
                        'error': str(e),
                        'error_type': type(e).__name__,
                    })()
                await asyncio.sleep(1 * (attempt + 1))
            except Exception as e:
                self.safety_manager.on_failure()
                if attempt == self.max_retries - 1:
                    return type('Response', (), {
                        'status_code': 0,
                        'text': f'[REQUEST FAILED: {type(e).__name__}]',
                        'headers': {},
                        'error': str(e),
                        'error_type': type(e).__name__,
                    })()
                await asyncio.sleep(1 * (attempt + 1))

        return None

    async def close(self):
        if self.session:
            await self.session.close()
            self.session = None