import asyncio
import time
from collections import deque


class SafetyProfile:
    """Định nghĩa các Safety Profile theo đặc tả v2.0 §6.

    - passive: Inventory/configuration — không inject
    - safe_active: Staging/local verification — canary, differential, time-based nhẹ
    - authenticated: Ứng dụng có test account — có session; authorization checks
    - deep_lab: Chỉ lab được cô lập — cho phép test fixtures/canary
    - ci_fast: Regression security — subset deterministic, giới hạn thời gian
    """

    PROFILES = {
        'passive': {
            'description': 'Chỉ thu thập thông tin, không inject payload',
            'inject_payloads': False,
            'default_scan_types': ['discovery', 'passive'],
            'allowed_methods': ['GET', 'HEAD', 'OPTIONS'],
            'concurrency': 3,
            'rps': 3,
            'timeout': 15,
            'max_pages': 50,
            'max_depth': 2,
            'destructive_payloads': False,
            'require_confirmation': False,
        },
        'safe-active': {
            'description': 'Quét chủ động an toàn cho staging/local',
            'inject_payloads': True,
            'default_scan_types': ['discovery', 'passive', 'sqli', 'xss', 'rce'],
            'allowed_methods': ['GET', 'POST', 'HEAD', 'OPTIONS'],
            'concurrency': 5,
            'rps': 5,
            'timeout': 20,
            'max_pages': 100,
            'max_depth': 4,
            'destructive_payloads': False,
            'require_confirmation': True,
        },
        'authenticated': {
            'description': 'Quét với session đăng nhập, kiểm tra authorization',
            'inject_payloads': True,
            'default_scan_types': ['discovery', 'passive', 'sqli', 'xss', 'authz', 'csrf', 'cors'],
            'allowed_methods': ['GET', 'POST', 'PUT', 'PATCH', 'HEAD', 'OPTIONS'],
            'concurrency': 5,
            'rps': 5,
            'timeout': 20,
            'max_pages': 150,
            'max_depth': 5,
            'destructive_payloads': False,
            'require_confirmation': True,
        },
        'deep-lab': {
            'description': 'Chỉ dùng trong lab cô lập — cho phép fixtures/canary',
            'inject_payloads': True,
            'default_scan_types': ['discovery', 'passive', 'sqli', 'xss', 'rce', 'ssrf', 'lfi', 'path_traversal', 'ssti', 'xxe'],
            'allowed_methods': ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'],
            'concurrency': 10,
            'rps': 10,
            'timeout': 30,
            'max_pages': 500,
            'max_depth': 8,
            'destructive_payloads': False,  # vẫn không cho phép destructive
            'require_confirmation': True,
        },
        'ci-fast': {
            'description': 'Regression security nhanh cho CI/CD',
            'inject_payloads': True,
            'default_scan_types': ['passive', 'sqli', 'xss'],
            'allowed_methods': ['GET', 'POST', 'HEAD'],
            'concurrency': 3,
            'rps': 5,
            'timeout': 10,
            'max_pages': 30,
            'max_depth': 2,
            'destructive_payloads': False,
            'require_confirmation': False,
        },
    }

    def __init__(self, name='safe-active'):
        if name not in self.PROFILES:
            raise ValueError(f"Profile không hợp lệ: {name}. "
                             f"Chọn: {', '.join(self.PROFILES.keys())}")
        self.name = name
        self.config = dict(self.PROFILES[name])

    def update(self, **kwargs):
        """Cập nhật cấu hình profile."""
        for key, value in kwargs.items():
            if key in self.config:
                self.config[key] = value

    @property
    def inject_payloads(self):
        return self.config['inject_payloads']

    @property
    def destructive_payloads(self):
        return self.config['destructive_payloads']

    @property
    def require_confirmation(self):
        return self.config['require_confirmation']

    def to_dict(self):
        return {
            'name': self.name,
            'description': self.config['description'],
            'config': dict(self.config),
        }


class RateLimiter:
    """Giới hạn Requests Per Second (RPS) theo đặc tả v2.0 §18."""

    def __init__(self, rps=5, burst=20):
        self.rps = max(1, rps)
        self.burst = max(self.rps, burst)
        self.timestamps = deque()
        self._lock = asyncio.Lock()
        self.total_requests = 0
        self.blocked_requests = 0

    async def acquire(self):
        """Chờ đến khi được phép gửi request."""
        async with self._lock:
            now = time.monotonic()
            # Xóa các timestamp quá cũ
            while self.timestamps and now - self.timestamps[0] > 1.0:
                self.timestamps.popleft()

            # Nếu đạt giới hạn RPS trong 1 giây
            if len(self.timestamps) >= self.rps:
                self.blocked_requests += 1
                wait_time = 1.0 - (now - self.timestamps[0])
                if wait_time > 0:
                    await asyncio.sleep(wait_time)
                # Sau khi chờ, thêm timestamp
                self.timestamps.append(time.monotonic())
            else:
                self.timestamps.append(now)

            self.total_requests += 1

    def get_stats(self):
        return {
            'rps_limit': self.rps,
            'total_requests': self.total_requests,
            'blocked_requests': self.blocked_requests,
        }


class CircuitBreaker:
    """Circuit Breaker — chặn khi quá tải/thất bại liên tục."""

    def __init__(self, failure_threshold=10, reset_timeout=30, max_consecutive_failures=5):
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self.max_consecutive_failures = max_consecutive_failures
        self.failures = 0
        self.consecutive_failures = 0
        self.last_failure_time = None
        self.is_open = False
        self.total_failures = 0
        self.total_successes = 0

    def record_success(self):
        """Ghi nhận thành công."""
        self.total_successes += 1
        self.consecutive_failures = 0
        if self.is_open:
            self.failures = 0
            self.is_open = False

    def record_failure(self):
        """Ghi nhận thất bại."""
        self.total_failures += 1
        self.consecutive_failures += 1
        self.failures += 1
        self.last_failure_time = time.monotonic()

        # Mở circuit breaker khi vượt ngưỡng
        if self.consecutive_failures >= self.max_consecutive_failures or \
           self.failures >= self.failure_threshold:
            self.is_open = True

    def can_proceed(self):
        """Kiểm tra có được phép gọi không."""
        if not self.is_open:
            return True

        # Kiểm tra reset_timeout
        if self.last_failure_time and \
           (time.monotonic() - self.last_failure_time) >= self.reset_timeout:
            self.is_open = False
            self.failures = 0
            self.consecutive_failures = 0
            return True

        return False

    def get_state(self):
        return {
            'is_open': self.is_open,
            'failures': self.failures,
            'consecutive_failures': self.consecutive_failures,
            'total_failures': self.total_failures,
            'total_successes': self.total_successes,
            'state': 'OPEN' if self.is_open else 'CLOSED',
        }


class SafetyManager:
    """Quản lý an toàn tổng hợp: profile + rate limiter + circuit breaker.

    Chặn:
    - Payload destructive/exfiltration (safety policy)
    - Request ra ngoài scope (scope guard)
    - External callbacks (no_external_callbacks)
    """

    DESTRUCTIVE_PATTERNS = [
        'DROP TABLE', 'DELETE FROM', 'TRUNCATE', 'UPDATE ... SET',
        'rm -rf', 'FORMAT C:', 'del /f /s', 'mkfs', 'dd if=',
        '> /dev/sda', ':(){:|:&};:', 'shutdown', 'reboot',
    ]

    EXTERNAL_CALLBACK_PATTERNS = [
        'webhook.site', 'requestbin', 'ngrok', 'burpcollaborator',
        'interact.sh', 'oast.fun', 'oast.pro', 'oast.online',
        'dnslog.cn', 'ceye.io',
    ]

    def __init__(self, profile_name='safe-active', scope_guard=None):
        self.profile = SafetyProfile(profile_name)
        self.scope_guard = scope_guard
        self.rate_limiter = RateLimiter(self.profile.config.get('rps', 5))
        self.circuit_breaker = CircuitBreaker()
        self.no_external_callbacks = True  # mặc định chặn external callbacks
        self.total_blocked = 0
        self.block_log = []

    def check_payload(self, payload):
        """Kiểm tra payload có vi phạm safety policy không."""
        if not self.profile.inject_payloads and payload:
            return {'allowed': False, 'reason': 'Profile này không cho phép inject payload'}

        if not payload:
            return {'allowed': True}

        payload_upper = payload.upper()

        # Chặn destructive payloads
        for pattern in self.DESTRUCTIVE_PATTERNS:
            if pattern.upper() in payload_upper:
                self._block('Destructive payload bị chặn', payload)
                return {'allowed': False, 'reason': f'Destructive payload bị chặn: {pattern}'}

        # Chặn external callbacks
        payload_lower = payload.lower()
        for pattern in self.EXTERNAL_CALLBACK_PATTERNS:
            if pattern in payload_lower:
                self._block('External callback bị chặn', payload)
                return {'allowed': False, 'reason': f'External callback bị chặn: {pattern}'}

        return {'allowed': True}

    def check_url(self, url):
        """Kiểm tra URL có nằm trong scope không."""
        if not self.scope_guard:
            return {'allowed': True}

        return {'allowed': self.scope_guard.is_allowed(url),
                'reason': '' if self.scope_guard.is_allowed(url) else f'URL ngoài scope: {url}'}

    def check_request(self, method, url, payload=None):
        """Kiểm tra tổng hợp trước khi gửi request."""
        # Kiểm tra circuit breaker
        if not self.circuit_breaker.can_proceed():
            return {'allowed': False, 'reason': 'Circuit breaker đang OPEN - tạm dừng request'}

        # Kiểm tra method cho phép
        allowed_methods = self.profile.config.get('allowed_methods', [])
        if method not in allowed_methods:
            self._block(f'Method {method} không nằm trong profile', url)
            return {'allowed': False, 'reason': f'Method {method} không được phép trong profile {self.profile.name}'}

        # Kiểm tra URL scope
        url_check = self.check_url(url)
        if not url_check['allowed']:
            self._block(url_check['reason'], url)
            return url_check

        # Kiểm tra payload
        if payload is not None:
            payload_check = self.check_payload(payload)
            if not payload_check['allowed']:
                return payload_check

        return {'allowed': True}

    async def wait_if_needed(self):
        """Chờ rate limiter trước khi gửi request."""
        await self.rate_limiter.acquire()

    def _block(self, reason, detail=''):
        """Ghi log khi chặn request."""
        self.total_blocked += 1
        self.block_log.append({
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
            'reason': reason,
            'detail': detail,
        })

    def on_success(self):
        self.circuit_breaker.record_success()

    def on_failure(self):
        self.circuit_breaker.record_failure()

    def get_stats(self):
        return {
            'profile': self.profile.to_dict(),
            'rate_limiter': self.rate_limiter.get_stats(),
            'circuit_breaker': self.circuit_breaker.get_state(),
            'total_blocked': self.total_blocked,
            'block_log': list(self.block_log),
        }