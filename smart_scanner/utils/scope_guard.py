import ipaddress
import re
from urllib.parse import urlparse


class ScopeGuard:
    """Kiểm soát phạm vi quét (Scope Guard / Authorization Gate).
    
    - Allowlist domain/IP/CIDR
    - Từ chối target ngoài allowlist
    - Chặn localhost/private target nếu chưa bật Local Lab Mode
    - Dry-run để xem request dự kiến
    """

    PRIVATE_PREFIXES = [
        '127.', '10.', '192.168.', '172.16.', '172.17.', '172.18.',
        '172.19.', '172.20.', '172.21.', '172.22.', '172.23.',
        '172.24.', '172.25.', '172.26.', '172.27.', '172.28.',
        '172.29.', '172.30.', '172.31.', '0.', '169.254.',
    ]

    LOCAL_HOSTNAMES = {'localhost', 'localtest.me', '*.local', '*.internal'}

    def __init__(self, config=None):
        self.config = config or {}
        self.allowlist = set(self.config.get('allowlist', []))
        self.denylist = set(self.config.get('denylist', []))
        self.local_lab_mode = self.config.get('local_lab_mode', False)
        self.dry_run = self.config.get('dry_run', False)
        self.authorized_targets = set()

    def add_to_allowlist(self, target):
        """Thêm target vào allowlist."""
        self.allowlist.add(target)

    def authorize_target(self, url, confirm=False):
        """Xác nhận quyền kiểm thử cho target."""
        parsed = urlparse(url)
        hostname = parsed.hostname or ''

        if not hostname:
            return {'allowed': False, 'reason': 'URL không hợp lệ - thiếu hostname'}

        # Kiểm tra denylist
        if self._matches_denylist(hostname):
            return {'allowed': False, 'reason': f'Target bị chặn trong denylist: {hostname}'}

        # Kiểm tra allowlist
        if self.allowlist and not self._matches_allowlist(hostname):
            return {
                'allowed': False,
                'reason': f'Target không nằm trong allowlist: {hostname}. '
                          f'Allowlist hiện tại: {", ".join(sorted(self.allowlist)) or "(trống)"}'
            }

        # Kiểm tra localhost/private
        is_local = self._is_private_or_local(hostname)
        if is_local and not self.local_lab_mode:
            return {
                'allowed': False,
                'reason': f'Target là địa chỉ local/private ({hostname}). '
                          f'Cần bật Local Lab Mode để quét localhost/LAN.'
            }

        # Yêu cầu xác nhận quyền cho active scan
        if not confirm:
            return {
                'allowed': True,
                'requires_confirmation': True,
                'reason': f'Cần xác nhận quyền kiểm thử cho: {url}'
            }

        self.authorized_targets.add(url)
        return {'allowed': True, 'reason': f'Đã xác nhận quyền cho: {url}'}

    def is_allowed(self, url):
        """Kiểm tra URL có được phép quét không."""
        parsed = urlparse(url)
        if not parsed.hostname:
            return False

        # Denylist luôn chặn
        if self._matches_denylist(parsed.hostname):
            return False

        # Allowlist nếu cấu hình
        if self.allowlist and not self._matches_allowlist(parsed.hostname):
            return False

        # Local target cần Local Lab Mode
        if self._is_private_or_local(parsed.hostname) and not self.local_lab_mode:
            return False

        return True

    def _matches_allowlist(self, hostname):
        for pattern in self.allowlist:
            if self._match_pattern(pattern, hostname):
                return True
        return False

    def _matches_denylist(self, hostname):
        for pattern in self.denylist:
            if self._match_pattern(pattern, hostname):
                return True
        return False

    def _match_pattern(self, pattern, hostname):
        """So khớp domain/IP/CIDR pattern với hostname."""
        # Wildcard domain: *.example.com
        if pattern.startswith('*.'):
            suffix = pattern[2:]
            return hostname == suffix or hostname.endswith('.' + suffix)

        # CIDR
        if '/' in pattern:
            try:
                return ipaddress.ip_address(hostname) in ipaddress.ip_network(pattern, strict=False)
            except ValueError:
                return False

        # Khớp chính xác
        return hostname.lower() == pattern.lower()

    def _is_private_or_local(self, hostname):
        """Kiểm tra hostname có phải local/private không."""
        hostname_lower = hostname.lower()

        # Local hostname
        if hostname_lower in {'localhost', 'localhost.localdomain'}:
            return True
        if hostname_lower.endswith('.local') or hostname_lower.endswith('.internal'):
            return True

        # IP private
        try:
            ip = ipaddress.ip_address(hostname)
            return (ip.is_private or ip.is_loopback or ip.is_link_local
                    or ip.is_reserved or ip.is_multicast)
        except ValueError:
            # Không phải IP — kiểm tra prefix
            return any(hostname_lower.startswith(p) for p in self.PRIVATE_PREFIXES)

    # ─── Audit Trail ─────────────────────────────────────────────

    def audit_log(self, action, url, result):
        """Ghi log kiểm soát phạm vi."""
        entry = {
            'action': action,
            'url': url,
            'allowed': result.get('allowed'),
            'reason': result.get('reason'),
        }
        self.config.setdefault('audit_trail', []).append(entry)
        return entry

    def get_audit_trail(self):
        return list(self.config.get('audit_trail', []))


class ScanContext:
    """Ngữ cảnh scan — tạo Scan ID, lưu cấu hình hash, audit trail."""

    def __init__(self, target_url, scope_guard, profile='safe-active'):
        import hashlib
        from datetime import datetime

        self.scan_id = hashlib.sha256(f"{target_url}:{datetime.now().isoformat()}".encode()).hexdigest()[:16]
        self.target_url = target_url
        self.scope_guard = scope_guard
        self.profile = profile
        self.started_at = datetime.now().isoformat()
        self.ended_at = None
        self.status = 'running'
        self.config_hash = None

    def compute_config_hash(self, config):
        import hashlib
        import json
        try:
            config_json = json.dumps(config, sort_keys=True, default=str)
            self.config_hash = hashlib.sha256(config_json.encode()).hexdigest()[:16]
        except Exception:
            self.config_hash = 'unknown'

    def end(self, status='completed'):
        from datetime import datetime
        self.ended_at = datetime.now().isoformat()
        self.status = status

    def to_dict(self):
        return {
            'scan_id': self.scan_id,
            'target': self.target_url,
            'profile': self.profile,
            'status': self.status,
            'started_at': self.started_at,
            'ended_at': self.ended_at,
            'config_hash': self.config_hash,
            'audit_trail': self.scope_guard.get_audit_trail(),
        }