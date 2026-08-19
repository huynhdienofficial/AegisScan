"""
RBAC — Phân quyền theo đặc tả v3.1 mục 14 (Feature List #13).

Roles: Viewer / Analyst / Approver / Admin
Exploitation Module chỉ Admin/Approver được kích hoạt.
"""
from datetime import datetime


class Role:
    """Định nghĩa roles và permissions."""

    VIEWER = 'viewer'
    ANALYST = 'analyst'
    APPROVER = 'approver'
    ADMIN = 'admin'

    PERMISSIONS = {
        VIEWER: ['scan.view', 'finding.view', 'report.view', 'asset.view'],
        ANALYST: [
            'scan.view', 'scan.run', 'finding.view', 'finding.update',
            'report.view', 'report.export', 'asset.view', 'asset.update',
        ],
        APPROVER: [
            'scan.view', 'scan.run', 'finding.view', 'finding.update',
            'finding.suppress', 'report.view', 'report.export',
            'asset.view', 'asset.update', 'exploit.approve',
        ],
        ADMIN: [
            'scan.view', 'scan.run', 'finding.view', 'finding.update',
            'finding.suppress', 'report.view', 'report.export',
            'asset.view', 'asset.update', 'asset.manage',
            'exploit.approve', 'exploit.run', 'user.manage', 'config.manage',
        ],
    }

    HIERARCHY = [VIEWER, ANALYST, APPROVER, ADMIN]

    @classmethod
    def has_permission(cls, role, permission):
        """Kiểm tra role có permission không."""
        perms = cls.PERMISSIONS.get(role, [])
        return permission in perms


class User:
    """Người dùng hệ thống."""

    def __init__(self, username, role, full_name='', email=''):
        self.username = username
        self.role = role
        self.full_name = full_name or username
        self.email = email
        self.created_at = datetime.now().isoformat()
        self.login_history = []

    def has_permission(self, permission):
        return Role.has_permission(self.role, permission)

    def can_use_exploitation(self):
        """Chỉ Admin/Approver được dùng Exploitation Module."""
        return self.role in (Role.ADMIN, Role.APPROVER)

    def to_dict(self):
        return {
            'username': self.username,
            'role': self.role,
            'full_name': self.full_name,
            'email': self.email,
            'created_at': self.created_at,
        }


class RBACManager:
    """Quản lý người dùng + phân quyền."""

    def __init__(self):
        self.users = {}
        self.audit_log = []  # Log ai thực hiện hành động gì

    def create_user(self, username, role, **kwargs):
        """Tạo user mới."""
        if username in self.users:
            raise ValueError(f"User {username} đã tồn tại")
        user = User(username, role, **kwargs)
        self.users[username] = user
        self._log('user.create', username, f"Tạo user {username} với role {role}")
        return user

    def get_user(self, username):
        return self.users.get(username)

    def check_permission(self, username, permission):
        """Kiểm tra user có quyền không."""
        user = self.get_user(username)
        if not user:
            return False
        return user.has_permission(permission)

    def require_permission(self, username, permission, action=''):
        """Yêu cầu quyền — ghi audit nếu bị từ chối."""
        user = self.get_user(username)
        if not user:
            self._log('permission.denied', username, f"{action}: user không tồn tại")
            return False

        if user.has_permission(permission):
            self._log('permission.granted', username, f"{action} ({permission})")
            return True

        self._log('permission.denied', username, f"{action}: thiếu {permission}")
        return False

    def approve_exploitation(self, approver_username, target, cve_id=None):
        """
        Phê duyệt khai thác có kiểm soát (Level 3).
        Chỉ Admin/Approver mới được.
        """
        user = self.get_user(approver_username)
        if not user or not user.can_use_exploitation():
            self._log('exploit.denied', approver_username, f"Không được phép khai thác {target}")
            return {
                'approved': False,
                'reason': 'Chỉ Admin/Approver mới được phê duyệt exploitation',
            }

        approval = {
            'approver': approver_username,
            'target': target,
            'cve_id': cve_id,
            'approved_at': datetime.now().isoformat(),
            'status': 'approved',
        }
        self._log('exploit.approved', approver_username, f"Phê duyệt khai thác {target} ({cve_id or 'N/A'})")
        return {'approved': True, 'approval': approval}

    def log_login(self, username):
        """Ghi log đăng nhập."""
        user = self.get_user(username)
        if user:
            user.login_history.append(datetime.now().isoformat())
            self._log('user.login', username, 'Đăng nhập thành công')

    def get_audit_log(self, limit=50):
        """Lấy log kiểm soát truy cập."""
        return list(self.audit_log[-limit:])

    def _log(self, action, username, detail):
        self.audit_log.append({
            'timestamp': datetime.now().isoformat(),
            'action': action,
            'username': username,
            'detail': detail,
        })

    def get_users(self):
        return [u.to_dict() for u in self.users.values()]

    def get_stats(self):
        """Thống kê user."""
        by_role = {}
        for u in self.users.values():
            by_role[u.role] = by_role.get(u.role, 0) + 1
        return {
            'total_users': len(self.users),
            'by_role': by_role,
            'audit_entries': len(self.audit_log),
        }