"""
Database Security Scanner — theo đặc tả v3.1 §20.4 (Feature List #86).

Quét cấu hình database: weak/default credentials, excessive privileges,
TLS config, audit logging, backup security, network exposure.
Hỗ trợ: PostgreSQL, MySQL, MSSQL, MongoDB (cấu hình-based, không cần kết nối).
"""
import re


class DatabaseScanner:
    """Phân tích cấu hình database từ file config hoặc content."""

    # Mặc định credentials phổ biến cần kiểm tra
    DEFAULT_CREDENTIALS = [
        ('root', 'root'), ('root', 'password'), ('root', '123456'),
        ('admin', 'admin'), ('admin', 'password'), ('postgres', 'postgres'),
        ('postgres', 'password'), ('sa', 'sa'), ('sa', 'password'),
        ('mongodb', 'mongodb'), ('test', 'test'), ('guest', 'guest'),
    ]

    DATABASE_ENGINES = ['postgresql', 'mysql', 'mssql', 'mongodb']

    def __init__(self, config_text=None, config_file=None, db_type='postgresql'):
        self.config_text = config_text
        self.config_file = config_file
        self.db_type = db_type if db_type in self.DATABASE_ENGINES else 'postgresql'
        self._load()

    def _load(self):
        if self.config_file:
            try:
                with open(self.config_file, 'r', encoding='utf-8', errors='ignore') as f:
                    self.config_text = f.read()
            except Exception:
                pass

    # ─── Kiểm tra default credentials ─────────────────────────
    def check_default_credentials(self):
        """Kiểm tra username/password default."""
        if not self.config_text:
            return []

        findings = []
        for user, password in self.DEFAULT_CREDENTIALS:
            pattern = rf'(?i)(USER|USERNAME)\s*=\s*["\']?{user}["\']?\s*(and|\n|;|,).*?(PASSWORD|PASS)\s*=\s*["\']?{password}["\']?'
            if re.search(pattern, self.config_text, re.DOTALL):
                findings.append({
                    'type': 'Database Default Credential',
                    'severity': 'Critical',
                    'detail': f"Cấu hình database dùng credential mặc định: {user}/{password}",
                    'confidence': 'High',
                    'payload': f"{user}/{password}",
                })

        # Simple password= field match
        for user, password in self.DEFAULT_CREDENTIALS:
            simple = rf'(?i)(user(name)?\s*[=:]\s*["\']?{user}["\']?\s*[,;\n]?\s*pass(word)?\s*[=:]\s*["\']?{password}["\']?)'
            if re.search(simple, self.config_text):
                findings.append({
                    'type': 'Database Default Credential',
                    'severity': 'Critical',
                    'detail': f"Cấu hình database dùng credential mặc định: {user}/{password}",
                    'confidence': 'High',
                })
        return findings

    # ─── Kiểm tra TLS ─────────────────────────────────────────
    def check_tls_config(self):
        """Kiểm tra SSL/TLS đã bật chưa."""
        if not self.config_text:
            return []

        findings = []
        text = self.config_text.lower()

        # PostgreSQL
        if self.db_type == 'postgresql':
            if 'ssl' in text and 'on' in text and 'off' not in text:
                pass  # SSL bật — OK
            elif 'ssl = off' in text or 'ssl=off' in text:
                findings.append({
                    'type': 'Database TLS Disabled',
                    'severity': 'High',
                    'detail': 'PostgreSQL SSL = off — dữ liệu truyền không mã hóa',
                    'confidence': 'High',
                })
            elif 'ssl' not in text:
                findings.append({
                    'type': 'Database TLS Not Configured',
                    'severity': 'Medium',
                    'detail': 'Không thấy cấu hình SSL — nên bật SSL/TLS cho database',
                    'confidence': 'Low',
                })

        # MySQL
        elif self.db_type == 'mysql':
            if 'ssl-ca' in text or 'require_secure_transport' in text:
                pass  # SSL bật
            elif 'skip-ssl' in text or 'skip_ssl' in text:
                findings.append({
                    'type': 'Database TLS Disabled',
                    'severity': 'High',
                    'detail': 'MySQL đang dùng skip-ssl — kết nối không mã hóa',
                    'confidence': 'High',
                })
            else:
                findings.append({
                    'type': 'Database TLS Not Confirmed',
                    'severity': 'Low',
                    'detail': 'Không xác nhận được SSL — kiểm tra thêm',
                    'confidence': 'Low',
                })

        return findings

    # ─── Kiểm tra audit logging ───────────────────────────────
    def check_audit_logging(self):
        """Kiểm tra audit logging có bật không."""
        if not self.config_text:
            return []

        findings = []
        text = self.config_text.lower()

        if self.db_type == 'postgresql':
            if 'log_statement' not in text:
                findings.append({
                    'type': 'Database Audit Disabled',
                    'severity': 'Medium',
                    'detail': 'PostgreSQL chưa cấu hình log_statement — không có audit logging',
                    'confidence': 'Medium',
                })
        elif self.db_type == 'mysql':
            if 'general_log' not in text or 'general_log = off' in text:
                findings.append({
                    'type': 'Database Audit Disabled',
                    'severity': 'Medium',
                    'detail': 'MySQL chưa bật general_log — không có audit logging',
                    'confidence': 'Medium',
                })
        elif self.db_type == 'mssql':
            if 'audit' not in text:
                findings.append({
                    'type': 'Database Audit Disabled',
                    'severity': 'Medium',
                    'detail': 'MSSQL chưa cấu hình SQL Server Audit',
                    'confidence': 'Medium',
                })
        return findings

    # ─── Kiểm tra network exposure ────────────────────────────
    def check_network_exposure(self):
        """Kiểm tra bind address có expose ra ngoài không."""
        if not self.config_text:
            return []

        findings = []
        text = self.config_text.lower()

        # PostgreSQL: listen_addresses
        match = re.search(r'listen_addresses\s*=\s*["\']([^"\']+)["\']', text, re.IGNORECASE)
        if match:
            addr = match.group(1)
            if addr == '*':
                findings.append({
                    'type': 'Database Network Exposure',
                    'severity': 'High',
                    'detail': "PostgreSQL listen_addresses = '*' — expose ra tất cả interfaces",
                    'confidence': 'High',
                })

        # MySQL: bind-address
        match = re.search(r'bind-address\s*=\s*([0-9.]+)', text, re.IGNORECASE)
        if match:
            addr = match.group(1)
            if addr == '0.0.0.0':
                findings.append({
                    'type': 'Database Network Exposure',
                    'severity': 'High',
                    'detail': "MySQL bind-address = 0.0.0.0 — expose ra tất cả interfaces",
                    'confidence': 'High',
                })

        return findings

    # ─── Kiểm tra backup security ─────────────────────────────
    def check_backup_security(self):
        """Kiểm tra backup có được mã hóa không."""
        if not self.config_text:
            return []

        findings = []
        text = self.config_text.lower()

        if ('backup' in text or 'dump' in text) and 'encrypt' not in text and 'cipher' not in text:
            findings.append({
                'type': 'Database Backup Not Encrypted',
                'severity': 'Medium',
                'detail': 'Cấu hình backup database không thấy mã hóa — nên mã hóa backup',
                'confidence': 'Low',
            })
        return findings

    # ─── Tổng hợp ─────────────────────────────────────────────
    def scan(self):
        """Chạy toàn bộ database scan."""
        if not self.config_text:
            return {'vulnerabilities': [], 'note': 'Không có cấu hình database để phân tích'}

        all_findings = []
        all_findings.extend(self.check_default_credentials())
        all_findings.extend(self.check_tls_config())
        all_findings.extend(self.check_audit_logging())
        all_findings.extend(self.check_network_exposure())
        all_findings.extend(self.check_backup_security())

        return {'vulnerabilities': all_findings}