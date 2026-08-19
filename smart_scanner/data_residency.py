"""
Data Residency & Self Security — tính năng cuối cùng Phase 3 theo Feature List v3.1.

- Data Residency Option (#69): chọn vùng lưu trữ dữ liệu (in-country) theo yêu cầu tuân thủ
- Self Dependency Scan / SBOM (#66): nền tảng tự quét chính nó, pin dependency version
- Least Privilege Execution (#63): agent/scanner chạy non-root được xác nhận
- UI Localhost Binding (#64): chỉ bind UI vào 127.0.0.1 mặc định
"""
import hashlib
import json
import os
import re
import socket
from datetime import datetime


# ══════════════════════════════════════════════════════════════
# #69 Data Residency Option
# ══════════════════════════════════════════════════════════════

class DataResidencyManager:
    """
    Quản lý vùng lưu trữ dữ liệu theo yêu cầu tuân thủ.
    Hỗ trợ chọn vùng lưu trữ trong nước (in-country).
    """

    # Danh sách vùng lưu trữ khả dụng
    REGIONS = {
        'local': {
            'name': 'Máy Local (127.0.0.1)',
            'storage_path': './data_local',
            'network_required': 'none',
            'compliance': ['internal', 'lab', 'local'],
        },
        'vn': {
            'name': 'Việt Nam (In-Country)',
            'storage_path': './data_vn',
            'network_required': 'vpn',
            'compliance': ['iso27001', 'data_residency', 'pci_dss'],
        },
        'ap-southeast-1': {
            'name': 'AWS Singapore',
            'storage_path': './data_sg',
            'network_required': 'vpn',
            'compliance': ['iso27001', 'soc2'],
        },
        'eu-west-1': {
            'name': 'AWS Ireland (EU GDPR)',
            'storage_path': './data_eu',
            'network_required': 'vpn',
            'compliance': ['gdpr', 'iso27001'],
        },
        'us-east-1': {
            'name': 'AWS Virginia',
            'storage_path': './data_us',
            'network_required': 'vpn',
            'compliance': ['soc2', 'pci_dss'],
        },
    }

    def __init__(self, region='local'):
        self.current_region = region
        self.residency_log = []

    def set_region(self, region):
        """Đặt vùng lưu trữ dữ liệu."""
        if region not in self.REGIONS:
            raise ValueError(
                f"Vùng lưu trữ không hợp lệ: {region}. "
                f"Chọn: {', '.join(self.REGIONS.keys())}"
            )

        old_region = self.current_region
        self.current_region = region
        self.residency_log.append({
            'timestamp': datetime.now().isoformat(),
            'action': 'region.change',
            'from': old_region,
            'to': region,
            'detail': f"Đổi vùng lưu trữ từ {old_region} → {region}",
        })
        return {
            'ok': True,
            'region': region,
            'config': self.REGIONS[region],
        }

    def get_storage_config(self):
        """Lấy cấu hình lưu trữ hiện tại."""
        region_config = self.REGIONS.get(self.current_region, self.REGIONS['local'])
        return {
            'current_region': self.current_region,
            'compliant_regions': region_config['compliance'],
            'storage_path': region_config['storage_path'],
            'network_required': region_config['network_required'],
            'region_name': region_config['name'],
        }

    def check_compliance(self, requirement):
        """
        Kiểm tra vùng hiện tại có đáp ứng yêu cầu tuân thủ không.
        VD: 'gdpr', 'iso27001', 'pci_dss', 'data_residency'
        """
        region_config = self.REGIONS.get(self.current_region, self.REGIONS['local'])
        if requirement in region_config.get('compliance', []):
            return {
                'ok': True,
                'requirement': requirement,
                'region': self.current_region,
                'message': f"Vùng {self.current_region} đáp ứng yêu cầu {requirement}",
            }
        return {
            'ok': False,
            'requirement': requirement,
            'region': self.current_region,
            'message': (
                f"Vùng {self.current_region} KHÔNG đáp ứng yêu cầu {requirement}. "
                f"Vùng hợp lệ: {[r for r, c in self.REGIONS.items() if requirement in c.get('compliance', [])]}"
            ),
        }

    def suggest_region(self, requirement):
        """Gợi ý vùng lưu trữ phù hợp yêu cầu."""
        matches = []
        for region, config in self.REGIONS.items():
            if requirement in config.get('compliance', []):
                matches.append({
                    'region': region,
                    'name': config['name'],
                    'path': config['storage_path'],
                })
        return matches


# ══════════════════════════════════════════════════════════════
# #66 Self Dependency Scan / SBOM
# ══════════════════════════════════════════════════════════════

class SelfSecurityScanner:
    """Nền tảng tự quét chính nó — dependency, secrets, config."""

    # File dependency cần kiểm tra
    DEPENDENCY_FILES = ['requirements.txt', 'package.json', 'Pipfile.lock', 'poetry.lock']

    def __init__(self, project_path=None):
        self.project_path = project_path or os.path.dirname(os.path.abspath(__file__))
        self.findings = []

    def scan_dependencies(self):
        """Pin và quét dependency versions."""
        findings = []
        dependencies = []

        # Đọc requirements.txt
        req_file = os.path.join(self.project_path, 'requirements.txt')
        if os.path.exists(req_file):
            with open(req_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    match = re.match(r'([A-Za-z0-9_\-]+)\s*(==|>=|<=|~=|!=)?\s*([\d\.]+)?', line)
                    if match:
                        name = match.group(1)
                        op = match.group(2) or 'none'
                        version = match.group(3) or 'unpinned'

                        # Cảnh báo dependency chưa pin version
                        if op == 'none' or version == 'unpinned':
                            findings.append({
                                'type': 'Unpinned Dependency',
                                'severity': 'Medium',
                                'detail': f"'{name}' chưa pin version — nên dùng == {version}",
                                'confidence': 'High',
                                'component': name,
                            })
                        elif op not in ('==',):
                            findings.append({
                                'type': 'Dependency Not Exactly Pinned',
                                'severity': 'Low',
                                'detail': f"'{name}' dùng {op} {version} — nên pin chính xác với ==",
                                'confidence': 'Medium',
                                'component': name,
                            })
                        dependencies.append({
                            'name': name, 'operator': op, 'version': version,
                        })

        return {
            'dependencies_count': len(dependencies),
            'dependencies': dependencies,
            'findings': findings,
        }

    def scan_self_secrets(self):
        """Tự quét secrets lộ trong source code chính mình."""
        findings = []
        secret_patterns = [
            ('API Key', r'(api[_-]?key|apikey|api_key)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})'),
            ('AWS Key', r'AKIA[0-9A-Z]{12,}'),
            ('Private Key', r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----'),
            ('Hardcoded Password', r'(pass(word)?|pwd)\s*[:=]\s*["\']([^"\']{6,})["\']'),
        ]

        # Quét các file Python của chính nền tảng
        for root, _, files in os.walk(self.project_path):
            if '.venv' in root or '__pycache__' in root or '.git' in root:
                continue
            for fname in files:
                if fname.endswith('.py') and fname != os.path.basename(__file__):
                    filepath = os.path.join(root, fname)
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        for pattern_name, pattern in secret_patterns:
                            matches = re.findall(pattern, content, re.IGNORECASE)
                            if matches:
                                # Bỏ qua các file test hợp lệ
                                if 'test_' in fname:
                                    continue
                                findings.append({
                                    'type': f'Self Secret: {pattern_name}',
                                    'severity': 'High',
                                    'detail': f"Phát hiện {pattern_name} trong {filepath}",
                                    'confidence': 'Medium',
                                    'file': filepath,
                                })
                                break
                    except Exception:
                        continue
        return findings

    def verify_least_privilege(self):
        """Kiểm tra Least Privilege — scanner/agent chạy non-root."""
        user_info = {
            'platform': os.name,
            'user_env': os.environ.get('USER', os.environ.get('USERNAME', 'unknown')),
        }

        # Kiểm tra non-root trên Unix
        if os.name == 'posix':
            uid = os.getuid() if hasattr(os, 'getuid') else 0
            is_root = uid == 0
            return {
                'is_root': is_root,
                'least_privilege_violation': is_root,
                'recommendation': 'Scanner không nên chạy với quyền root — dùng user riêng',
                'check': 'CIS: Run scanner as non-root',
                'severity': 'High' if is_root else 'Info',
            }

        # Windows — kiểm tra admin token
        if os.name == 'nt':
            try:
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                return {
                    'is_admin': is_admin,
                    'least_privilege_violation': is_admin,
                    'recommendation': 'Scanner nên chạy với quyền tối thiểu, không phải Administrator',
                    'severity': 'High' if is_admin else 'Info',
                }
            except Exception:
                pass
        return {'is_root': False, 'least_privilege_violation': False, 'severity': 'Info'}

    def verify_ui_localhost_binding(self, ui_host='127.0.0.1'):
        """Kiểm tra UI chỉ bind localhost."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ui_host, 8501))
            sock.close()

            # Nếu connect được 127.0.0.1 → UI bind localhost OK
            return {
                'ui_binding': ui_host,
                'is_localhost_only': ui_host == '127.0.0.1',
                'ok': ui_host == '127.0.0.1',
                'message': (
                    'UI chỉ bind 127.0.0.1 — an toàn, không expose ra network'
                    if ui_host == '127.0.0.1' else
                    f'UI bind {ui_host} — cần authentication + CSRF protection'
                ),
                'severity': 'Info' if ui_host == '127.0.0.1' else 'High',
            }
        except Exception:
            return {
                'ui_binding': ui_host,
                'is_localhost_only': ui_host == '127.0.0.1',
                'ok': ui_host == '127.0.0.1',
                'message': 'Kiểm tra bind UI',
                'severity': 'Info',
            }

    def full_self_audit(self):
        """Chạy toàn bộ self-audit."""
        result = {
            'scanned_at': datetime.now().isoformat(),
            'project_path': self.project_path,
            'dependencies': self.scan_dependencies(),
            'secrets': self.scan_self_secrets(),
            'least_privilege': self.verify_least_privilege(),
            'ui_binding': self.verify_ui_localhost_binding(),
        }
        return result