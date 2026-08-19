"""
Authorization Record — theo đặc tả v3.3 §2.1.

Mọi scan/khai thác vượt mức "passive/signal-only" phải gắn với một
Authorization Record: ai phê duyệt (approver), phạm vi (scope), thời hạn
hiệu lực (expires_at), loại hình (authorization_type: scan / active_scan /
exploitation).

Đây là cơ chế phân biệt "pentest có kiểm soát" với "tấn công thật" — không
phải thủ tục hành chính trang trí. Vì vậy AuthorizationRegistry.issue()
bắt buộc xác thực approver qua RBACManager (không chấp nhận approver tự
xưng qua một chuỗi string bất kỳ), và mọi hành động cấp/thu hồi được ghi
vào audit trail dạng hash-chained (mỗi entry băm luôn cả entry trước đó)
để entry cũ không thể sửa/xoá âm thầm mà không làm gãy chain.
"""
import hashlib
import secrets
from datetime import datetime, timedelta
from urllib.parse import urlparse


# Thứ bậc loại uỷ quyền — level càng cao càng cần record "mạnh" hơn để bao phủ
AUTHORIZATION_TIERS = ('scan', 'active_scan', 'exploitation')


class HashChainedLog:
    """Audit trail append-only: mỗi entry băm gồm cả hash của entry trước.

    Sửa/xoá một entry ở giữa mà không cập nhật lại toàn bộ chain phía sau
    sẽ khiến `verify_chain()` phát hiện ngay — khác với list thường (có thể
    bị pop/mutate âm thầm mà không ai biết).
    """

    def __init__(self):
        self._entries = []

    def append(self, action, detail):
        prev_hash = self._entries[-1]['entry_hash'] if self._entries else '0' * 64
        entry = {
            'seq': len(self._entries),
            'timestamp': datetime.now().isoformat(),
            'action': action,
            'detail': detail,
            'prev_hash': prev_hash,
        }
        payload = f"{entry['seq']}|{entry['timestamp']}|{action}|{detail}|{prev_hash}"
        entry['entry_hash'] = hashlib.sha256(payload.encode()).hexdigest()
        self._entries.append(entry)
        return entry

    def verify_chain(self):
        """Trả về True nếu chain còn nguyên vẹn (chưa bị sửa/xoá âm thầm)."""
        prev_hash = '0' * 64
        for entry in self._entries:
            if entry['prev_hash'] != prev_hash:
                return False
            payload = (f"{entry['seq']}|{entry['timestamp']}|{entry['action']}|"
                       f"{entry['detail']}|{entry['prev_hash']}")
            if hashlib.sha256(payload.encode()).hexdigest() != entry['entry_hash']:
                return False
            prev_hash = entry['entry_hash']
        return True

    def entries(self):
        return list(self._entries)


class AuthorizationRecord:
    """Bản ghi uỷ quyền cho một phạm vi/loại hình quét-khai thác cụ thể."""

    def __init__(self, approver, scope, authorization_type, ttl_hours=24, notes=''):
        if authorization_type not in AUTHORIZATION_TIERS:
            raise ValueError(
                f"authorization_type phải thuộc {AUTHORIZATION_TIERS}, nhận: {authorization_type}"
            )
        if not approver:
            raise ValueError("Authorization Record bắt buộc phải có approver")

        self.record_id = secrets.token_hex(8)
        self.approver = approver
        self.scope = list(scope) if isinstance(scope, (list, tuple, set)) else [scope]
        self.authorization_type = authorization_type
        self.notes = notes
        self.issued_at = datetime.now()
        self.expires_at = self.issued_at + timedelta(hours=ttl_hours)
        self.revoked = False
        self.revoked_at = None

    def is_valid(self, now=None):
        now = now or datetime.now()
        return not self.revoked and self.issued_at <= now < self.expires_at

    def covers(self, target_url_or_host):
        """Kiểm tra target có nằm trong phạm vi (scope) của record không."""
        hostname = target_url_or_host
        if '://' in target_url_or_host or '/' in target_url_or_host:
            hostname = urlparse(target_url_or_host).hostname or target_url_or_host
        hostname = hostname.lower()

        for pattern in self.scope:
            pattern = pattern.lower()
            if pattern.startswith('*.'):
                suffix = pattern[2:]
                if hostname == suffix or hostname.endswith('.' + suffix):
                    return True
            elif pattern == hostname:
                return True
        return False

    def satisfies(self, required_tier, target_url_or_host):
        """True nếu record hợp lệ, đúng cấp độ (hoặc cao hơn) và bao phủ target."""
        if required_tier not in AUTHORIZATION_TIERS:
            return False
        if AUTHORIZATION_TIERS.index(self.authorization_type) < AUTHORIZATION_TIERS.index(required_tier):
            return False
        return self.is_valid() and self.covers(target_url_or_host)

    def revoke(self):
        self.revoked = True
        self.revoked_at = datetime.now()

    def to_dict(self):
        return {
            'record_id': self.record_id,
            'approver': self.approver,
            'scope': self.scope,
            'authorization_type': self.authorization_type,
            'notes': self.notes,
            'issued_at': self.issued_at.isoformat(),
            'expires_at': self.expires_at.isoformat(),
            'revoked': self.revoked,
            'revoked_at': self.revoked_at.isoformat() if self.revoked_at else None,
            'valid_now': self.is_valid(),
        }


class AuthorizationRegistry:
    """Quản lý vòng đời Authorization Record — cấp/thu hồi/tra cứu.

    Bắt buộc gắn với một RBACManager: chỉ user có role Admin/Approver
    (permission 'exploit.approve') mới cấp được record loại 'active_scan'
    hoặc 'exploitation'. Loại 'scan' (mức thấp nhất) có thể do bất kỳ user
    hợp lệ nào tự cấp cho chính họ.
    """

    def __init__(self, rbac_manager=None):
        self.rbac = rbac_manager
        self._records = {}
        self.audit = HashChainedLog()

    def issue(self, approver, scope, authorization_type, ttl_hours=24, notes=''):
        if authorization_type in ('active_scan', 'exploitation'):
            if not self.rbac:
                self.audit.append('issue.denied',
                                   f'{approver} thiếu RBAC manager để cấp {authorization_type}')
                raise PermissionError(
                    f"Cần RBACManager để cấp Authorization Record loại '{authorization_type}'"
                )
            user = self.rbac.get_user(approver)
            if not user or not user.can_use_exploitation():
                self.audit.append('issue.denied',
                                   f'{approver} không có quyền cấp record loại {authorization_type}')
                raise PermissionError(
                    f"User '{approver}' không có quyền cấp Authorization Record loại "
                    f"'{authorization_type}' (cần role Admin/Approver)"
                )

        record = AuthorizationRecord(approver, scope, authorization_type, ttl_hours, notes)
        self._records[record.record_id] = record
        self.audit.append(
            'issue.granted',
            f"record={record.record_id} approver={approver} type={authorization_type} "
            f"scope={record.scope} ttl_hours={ttl_hours}",
        )
        return record

    def revoke(self, record_id, revoked_by=''):
        record = self._records.get(record_id)
        if not record:
            return False
        record.revoke()
        self.audit.append('revoke', f"record={record_id} revoked_by={revoked_by}")
        return True

    def find_valid(self, target_url, required_tier):
        """Tìm record hợp lệ đầu tiên bao phủ target ở đúng cấp độ yêu cầu."""
        for record in self._records.values():
            if record.satisfies(required_tier, target_url):
                return record
        return None

    def get(self, record_id):
        return self._records.get(record_id)

    def list_records(self):
        return [r.to_dict() for r in self._records.values()]

    def get_audit_trail(self):
        return self.audit.entries()

    def verify_audit_integrity(self):
        return self.audit.verify_chain()
