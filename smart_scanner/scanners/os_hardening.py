"""
OS Hardening / CIS Benchmark — theo đặc tả v3.1 §7.2 (Feature List #28).

Đối chiếu cấu hình OS với CIS Benchmark cơ bản.
Chấm điểm compliance %.
Hỗ trợ: Linux (SSH, users, sudo, cron), file config-based.
"""
import re


class OSHardeningScanner:
    """Quét cấu hình OS theo CIS Benchmark cơ bản."""

    # CIS Benchmark checks phổ biến cho Linux
    CHECKS = [
        # SSH Hardening
        {'id': 'CIS-1.1.1', 'item': 'PermitRootLogin no', 'severity': 'High',
         'desc': 'SSH cho phép root login', 'config_pattern': r'PermitRootLogin\s+yes'},
        {'id': 'CIS-1.1.2', 'item': 'PasswordAuthentication no', 'severity': 'High',
         'desc': 'SSH vẫn cho phép password authentication', 'config_pattern': r'PasswordAuthentication\s+yes'},
        {'id': 'CIS-1.1.3', 'item': 'Protocol 2', 'severity': 'Medium',
         'desc': 'SSH protocol 1 vẫn được bật (không an toàn)', 'config_pattern': r'Protocol\s+1'},
        {'id': 'CIS-1.1.4', 'item': 'X11Forwarding no', 'severity': 'Low',
         'desc': 'X11Forwarding bật — nguy cơ session hijack', 'config_pattern': r'X11Forwarding\s+yes'},
        {'id': 'CIS-1.1.5', 'item': 'MaxAuthTries 4', 'severity': 'Medium',
         'desc': 'MaxAuthTries quá cao — tăng nguy cơ brute-force', 'config_pattern': r'MaxAuthTries\s+([5-9]|\d{2,})'},

        # System Config
        {'id': 'CIS-2.1.1', 'item': 'Core Dumps Disabled', 'severity': 'Medium',
         'desc': 'Core dumps chưa bị disable — rò rỉ memory', 'config_pattern': r'core\s+-?\s*0|ulimit\s+-c\s+[^0]'},
        {'id': 'CIS-2.1.2', 'item': 'Unused Services Removed', 'severity': 'Low',
         'desc': 'Phát hiện service không cần thiết', 'config_pattern': r'(telnet|rsh|rexec|ftp)'},
        {'id': 'CIS-2.1.3', 'item': 'Kernel Security Patched', 'severity': 'High',
         'desc': 'Kernel chưa xác nhận patch an toàn', 'config_pattern': r'(uname\s+-r|kernel\s+version)'},

        # User/Group
        {'id': 'CIS-3.1.1', 'item': 'Empty Password No', 'severity': 'Critical',
         'desc': 'User có password rỗng', 'config_pattern': r'\w+::0:0:'},
        {'id': 'CIS-3.1.2', 'item': 'Duplicate UID No', 'severity': 'Medium',
         'desc': 'Trùng UID trong /etc/passwd', 'config_pattern': r'(\d{3,}):\d{3,}:.*\n.*:\1:'},
        {'id': 'CIS-3.1.3', 'item': 'Home Dir 750', 'severity': 'Low',
         'desc': 'Home directory permission quá rộng', 'config_pattern': r'drwxrwxrwx'},

        # Sudo
        {'id': 'CIS-4.1.1', 'item': 'Sudoers No NOPASSWD', 'severity': 'High',
         'desc': 'Cấu hình NOPASSWD sudo — nguy cơ privilege escalation',
         'config_pattern': r'NOPASSWD'},

        # Scheduled Tasks
        {'id': 'CIS-5.1.1', 'item': 'Cron Permissions', 'severity': 'Low',
         'desc': 'Cron file permission không an toàn', 'config_pattern': r'cron\S*\s+-rw-rw-rw-'},
    ]

    def __init__(self, config_text=None, config_file=None):
        self.config_text = config_text
        self.config_file = config_file
        if config_file:
            try:
                with open(config_file, 'r', encoding='utf-8', errors='ignore') as f:
                    self.config_text = f.read()
            except Exception:
                pass

    def scan(self):
        """Chạy toàn bộ hardening scan."""
        if not self.config_text:
            return {'vulnerabilities': [], 'note': 'Không có cấu hình OS để phân tích'}

        findings = []
        passed = 0
        total = len(self.CHECKS)

        for check in self.CHECKS:
            match = re.search(check['config_pattern'], self.config_text, re.IGNORECASE)
            if match:
                findings.append({
                    'check_id': check['id'],
                    'type': f"CIS: {check['item']}",
                    'severity': check['severity'],
                    'detail': check['desc'],
                    'confidence': 'High',
                })
            else:
                passed += 1

        compliance = round((passed / total) * 100) if total > 0 else 0

        return {
            'vulnerabilities': findings,
            'compliance_score': compliance,
            'total_checks': total,
            'passed_checks': passed,
            'failed_checks': len(findings),
        }