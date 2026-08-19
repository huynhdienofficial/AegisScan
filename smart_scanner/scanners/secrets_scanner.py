"""
Secrets Scan + Docker/Container Audit — theo đặc tả v3.1 (Feature List #30, #29).

Secrets: phát hiện credential/API key hardcode trong config file, env, log.
Docker: image CVE, container privileged, exposed docker socket.
"""
import os
import re


class SecretsScanner:
    """Phát hiện secrets/credentials lộ trong file/config."""

    PATTERNS = [
        ('AWS Access Key', r'AKIA[0-9A-Z]{16}'),
        ('AWS Secret Key', r'(?i)aws_secret_access_key[\s"\'=:]+([A-Za-z0-9/+=]{40})'),
        ('GitHub Token', r'gh[pousr]_[A-Za-z0-9_]{36,255}'),
        ('Private Key', r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
        ('API Key Generic', r'(?i)(api[_-]?key|apikey|api_secret)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{16,64})'),
        ('JWT Token', r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),
        ('Slack Token', r'xox[baprs]-[0-9A-Z-]{10,}'),
        ('Stripe Key', r'sk_live_[0-9A-Za-z]{24,}'),
        ('Google API Key', r'AIza[0-9A-Za-z\-_]{35}'),
        ('Password In URL', r'(?i)(pass(word)?|pwd)\s*[:=]\s*["\']?[^\s"\'&]+'),
        ('Database Connection', r'(?i)(mysql|postgres|mongodb)(\+srv)?://[^\s"\'<>]+'),
    ]

    def __init__(self, paths=None, content=None, filename=''):
        self.paths = paths or []
        self.content = content
        self.filename = filename

    def scan_content(self, content, filename=''):
        """Quét nội dung text tìm secrets."""
        findings = []
        for pattern_name, pattern in self.PATTERNS:
            try:
                matches = re.finditer(pattern, content)
                for match in matches:
                    findings.append({
                        'type': f'Secret: {pattern_name}',
                        'severity': 'High',
                        'detail': f'Phát hiện {pattern_name} trong {filename}',
                        'confidence': 'High' if pattern_name != 'Password In URL' else 'Medium',
                        'payload': self._mask(match.group(0)),
                        'file': filename,
                    })
            except re.error:
                continue
        return findings

    def scan_directory(self):
        """Quét tất cả file trong thư mục."""
        all_findings = []
        for path in self.paths:
            if os.path.isfile(path):
                try:
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    all_findings.extend(self.scan_content(content, os.path.basename(path)))
                except Exception:
                    continue
            elif os.path.isdir(path):
                for root, _, files in os.walk(path):
                    for fname in files:
                        if fname.endswith(('.py', '.js', '.env', '.json', '.yaml', '.yml',
                                           '.conf', '.config', '.ini', '.log', '.sh')):
                            filepath = os.path.join(root, fname)
                            try:
                                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read()
                                all_findings.extend(self.scan_content(content, fname))
                            except Exception:
                                continue
        return all_findings

    @staticmethod
    def _mask(secret, visible=6):
        """Che giấu secret để không lộ trong report."""
        if len(secret) <= visible * 2:
            return secret[:visible] + '***'
        return f"{secret[:visible]}...{secret[-4:]}"

    def scan(self):
        """Chạy toàn bộ secrets scan."""
        all_findings = []
        if self.content:
            all_findings.extend(self.scan_content(self.content, self.filename))
        if self.paths:
            all_findings.extend(self.scan_directory())
        return {'vulnerabilities': all_findings}


class DockerScanner:
    """Audit cấu hình Docker/Container — non-invasive."""

    DANGEROUS_CAPABILITIES = [
        'CAP_SYS_ADMIN', 'CAP_NET_ADMIN', 'CAP_SYS_PTRACE',
        'CAP_SYS_CHROOT', 'CAP_DAC_OVERRIDE', 'CAP_NET_RAW',
    ]

    def __init__(self, config_text=None, config_file=None):
        """config_text: nội dung docker-compose.yml hoặc container inspect JSON."""
        self.config_text = config_text
        self.config_file = config_file
        import json
        self._load()

    def _load(self):
        if self.config_file and os.path.exists(self.config_file):
            with open(self.config_file, 'r', encoding='utf-8') as f:
                self.config_text = f.read()

    def scan_compose(self):
        """Quét docker-compose.yml tìm cấu hình nguy hiểm."""
        if not self.config_text:
            return []

        text = self.config_text.lower()
        findings = []

        # Privileged container
        if re.search(r'privileged\s*:\s*true', text):
            findings.append({
                'type': 'Docker Privileged Container',
                'severity': 'High',
                'detail': 'Container chạy với privileged:true — có quyền truy cập toàn bộ host',
                'confidence': 'High',
            })

        # Exposed Docker socket
        if re.search(r'/var/run/docker\.sock', text):
            findings.append({
                'type': 'Docker Socket Exposed',
                'severity': 'Critical',
                'detail': 'Docker socket /var/run/docker.sock được mount vào container — nguy cơ chiếm host',
                'confidence': 'High',
            })

        # Host network
        if re.search(r'network_mode\s*:\s*["\']?host', text):
            findings.append({
                'type': 'Docker Host Network',
                'severity': 'Medium',
                'detail': 'Container dùng network_mode: host — không có network isolation',
                'confidence': 'Medium',
            })

        # Risky capabilities
        for cap in self.DANGEROUS_CAPABILITIES:
            if re.search(cap.lower(), text):
                findings.append({
                    'type': 'Docker Dangerous Capability',
                    'severity': 'High',
                    'detail': f'Container có capability nguy hiểm: {cap}',
                    'confidence': 'Medium',
                })

        return findings

    def scan(self):
        """Chạy toàn bộ Docker scan."""
        return {'vulnerabilities': self.scan_compose()}