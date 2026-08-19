"""
Governance Module — bổ sung các tính năng còn thiếu Phase 2-3.

- Firewall Rule Review (#26): đối chiếu rule với policy least privilege
- Exploit Module Manifest (#36): đăng ký exploit module có kiểm soát
- Business Impact Scoring (#48): nhập ảnh hưởng doanh thu/dữ liệu/vận hành
- Level 3 Automation - Ansible/Script (#56): playbook version hóa
- Scan Orchestrator (#4): lịch quét on-demand/cron/sự kiện
- Business Logic Testing (#79): price/quantity/coupon/order manipulation
- Secret Encryption at Rest (#65): mã hóa credential bằng key
"""
import json
import os
from datetime import datetime, timedelta


# ══════════════════════════════════════════════════════════════
# #26 Firewall Rule Review
# ══════════════════════════════════════════════════════════════

class FirewallRuleReview:
    """Đối chiếu firewall rules với policy chuẩn (least privilege)."""

    # Ports cần hạn chế theo policy chuẩn
    SENSITIVE_PORTS = {
        22: 'SSH', 23: 'Telnet', 3389: 'RDP', 3306: 'MySQL',
        5432: 'PostgreSQL', 6379: 'Redis', 9200: 'Elasticsearch',
        2375: 'Docker API', 2376: 'Docker API TLS', 27017: 'MongoDB',
    }

    def __init__(self, current_rules=None, policy_file=None):
        """
        current_rules: danh sách rule đang áp dụng
        [{port: 22, source: '0.0.0.0/0', action: 'ALLOW', protocol: 'tcp'}]
        policy_file: file JSON chứa policy chuẩn
        """
        self.current_rules = current_rules or []
        self.policy_file = policy_file
        self.violations = []

    def load_policy(self):
        """Load policy từ file nếu có."""
        if not self.policy_file or not os.path.exists(self.policy_file):
            return None
        with open(self.policy_file, 'r', encoding='utf-8') as f:
            return json.load(f)

    def review(self):
        """
        Kiểm tra rule hiện tại vs policy.
        Trả về các violations:
        - Port nhạy cảm mở ra 0.0.0.0/0 (Internet)
        - Telnet/RDP mở ra ngoài (nên dùng VPN)
        - Rule DENY bị ALLOW đè
        """
        violations = []

        for rule in self.current_rules:
            port = rule.get('port', rule.get('destination_port', 0))
            source = rule.get('source', rule.get('source_cidr', ''))
            action = rule.get('action', 'ALLOW').upper()

            # 1. Port nhạy cảm mở ra Internet
            if action == 'ALLOW' and source in ('0.0.0.0/0', '::/0', '*'):
                if port in self.SENSITIVE_PORTS:
                    violations.append({
                        'type': 'Sensitive Port Exposed To Internet',
                        'severity': 'High',
                        'detail': (
                            f"Port {port} ({self.SENSITIVE_PORTS[port]}) "
                            f"được phép từ {source} — nên giới hạn theo policy"
                        ),
                        'rule': rule,
                        'confidence': 'High',
                    })

            # 2. Telnet/RDP mở ra ngoài
            if action == 'ALLOW' and port in (23, 3389):
                if source in ('0.0.0.0/0', '::/0', '*'):
                    violations.append({
                        'type': 'Unencrypted Remote Access Exposed',
                        'severity': 'High',
                        'detail': f"Port {port} mở từ {source} — nên dùng VPN + hạn chế source",
                        'rule': rule,
                        'confidence': 'High',
                    })

            # 3. Deny bị allow đè (checking order)
            if action == 'ALLOW':
                for other in self.current_rules:
                    if (other.get('action', '').upper() == 'DENY'
                            and other.get('source') == source
                            and other.get('port') == port):
                        violations.append({
                            'type': 'Rule Conflict - Allow Overrides Deny',
                            'severity': 'Medium',
                            'detail': f"Port {port}: ALLOW rule đè DENY rule — kiểm tra thứ tự ưu tiên",
                            'rule': rule,
                            'confidence': 'Medium',
                        })

        return {
            'rules_reviewed': len(self.current_rules),
            'violations': violations,
            'compliance': round(max(0, (1 - len(violations) / max(len(self.current_rules), 1))) * 100),
        }


# ══════════════════════════════════════════════════════════════
# #36 Exploit Module Manifest
# ══════════════════════════════════════════════════════════════

class ExploitManifestRegistry:
    """
    Đăng ký exploit modules có kiểm soát.
    Mỗi module phải có manifest: CVE, tiền điều kiện, tác động, rollback.
    """

    def __init__(self, rbac_manager=None):
        self.modules = {}
        # Nếu có rbac_manager, approved_by bắt buộc phải là user thật có quyền
        # exploit.approve — thay vì chấp nhận bất kỳ chuỗi truthy nào. Không
        # truyền rbac_manager giữ hành vi cũ (tương thích ngược) nhưng khi đó
        # enable_module() không xác thực được danh tính approver.
        self.rbac = rbac_manager

    def register_module(self, module_id, name, cve_ref, preconditions,
                        impact_description, can_disrupt=False,
                        rollback_method=None, risk_level='Medium'):
        """Đăng ký exploit module."""
        module = {
            'module_id': module_id,
            'name': name,
            'cve_ref': cve_ref,
            'preconditions': preconditions,
            'impact_description': impact_description,
            'can_disrupt': can_disrupt,
            'rollback_method': rollback_method,
            'risk_level': risk_level,
            'version': '1.0.0',
            'registered_at': datetime.now().isoformat(),
            'enabled': False,  # Mặc định tắt — cần enable
        }
        self.modules[module_id] = module
        return module

    def enable_module(self, module_id, approved_by=None):
        """Bật module — cần approver cho module can_disrupt."""
        module = self.modules.get(module_id)
        if not module:
            return {'ok': False, 'reason': 'Module không tồn tại'}

        if module['can_disrupt']:
            if not approved_by:
                return {'ok': False, 'reason': 'Module gây gián đoạn cần approver phê duyệt'}
            if self.rbac is not None:
                user = self.rbac.get_user(approved_by)
                if not user or not user.can_use_exploitation():
                    return {'ok': False,
                            'reason': f"'{approved_by}' không có quyền phê duyệt (cần role Admin/Approver)"}

        module['enabled'] = True
        module['approved_by'] = approved_by
        module['enabled_at'] = datetime.now().isoformat()
        return {'ok': True, 'module': module}

    def list_modules(self):
        return list(self.modules.values())


# ══════════════════════════════════════════════════════════════
# #48 Business Impact Scoring
# ══════════════════════════════════════════════════════════════

class BusinessImpactScoring:
    """Tính mức ảnh hưởng kinh doanh cho asset."""

    # Trọng số theo loại ảnh hưởng
    IMPACT_WEIGHTS = {
        'revenue': 0.4,          # 40% — ảnh hưởng doanh thu
        'customer_data': 0.3,    # 30% — dữ liệu khách hàng
        'financial_data': 0.2,   # 20% — dữ liệu tài chính
        'operations': 0.1,       # 10% — ảnh hưởng vận hành
    }

    def __init__(self):
        self.assets_impact = {}  # asset_id -> {revenue, customer_data, financial_data, operations}

    def set_impact(self, asset_id, revenue=1, customer_data=1, financial_data=1, operations=1):
        """
        Mỗi mức 1-5:
        1 = không ảnh hưởng, 5 = rất nghiêm trọng
        """
        self.assets_impact[asset_id] = {
            'revenue': min(max(int(revenue), 1), 5),
            'customer_data': min(max(int(customer_data), 1), 5),
            'financial_data': min(max(int(financial_data), 1), 5),
            'operations': min(max(int(operations), 1), 5),
        }

    def calculate_score(self, asset_id):
        """Tính Business Impact Score 0-100."""
        if asset_id not in self.assets_impact:
            return 0

        impacts = self.assets_impact[asset_id]
        score = 0
        breakdown = {}
        for key, weight in self.IMPACT_WEIGHTS.items():
            val = impacts.get(key, 1)
            contribution = (val / 5.0) * 100 * weight
            score += contribution
            breakdown[key] = {
                'level': val,
                'weight': weight,
                'contribution': round(contribution, 1),
            }

        return {
            'asset_id': asset_id,
            'business_impact_score': round(score, 1),
            'rating': 'Critical' if score >= 80 else 'High' if score >= 60 else 'Medium' if score >= 40 else 'Low',
            'breakdown': breakdown,
        }


# ══════════════════════════════════════════════════════════════
# #56 Level 3 Remediation Automation (Ansible/Script)
# ══════════════════════════════════════════════════════════════

class RemediationAutomation:
    """Tạo Ansible playbook / Bash / PowerShell script version hóa."""

    def __init__(self):
        self.playbooks = []

    def generate_ansible_playbook(self, finding_id, hosts, tasks, name=''):
        """Tạo Ansible playbook YAML có kiểm soát."""
        playbook = f"""---
- name: {name or f'Remediation for {finding_id}'}
  hosts: {hosts}
  become: yes
  gather_facts: yes
  tasks:
"""
        for task in tasks:
            playbook += f"""    - name: {task['name']}
      ansible.builtin.{task['module']}:
{task.get('args', '')}
"""
        return {
            'finding_id': finding_id,
            'type': 'ansible',
            'hosts': hosts,
            'content': playbook,
            'version': '1.0.0',
            'created_at': datetime.now().isoformat(),
        }

    def generate_bash_script(self, finding_id, commands, name=''):
        """Tạo Bash script."""
        script = f"""#!/bin/bash
# {name or f'Remediation for {finding_id}'}
# Generated: {datetime.now().isoformat()}
# **** RUN WITH CAUTION - REVIEW BEFORE EXECUTION ****

set -e

"""
        for cmd in commands:
            script += f"# {cmd['description']}\n{cmd['command']}\n\n"

        return {
            'finding_id': finding_id,
            'type': 'bash',
            'content': script,
            'version': '1.0.0',
            'created_at': datetime.now().isoformat(),
        }

    def register_playbook(self, playbook):
        """Đăng ký playbook vào thư viện."""
        pb = dict(playbook)
        pb['id'] = f"PB-{len(self.playbooks) + 1:03d}"
        self.playbooks.append(pb)
        return pb


# ══════════════════════════════════════════════════════════════
# #4 Scan Orchestrator
# ══════════════════════════════════════════════════════════════

class ScanScheduler:
    """Lịch quét: on-demand, cron, theo sự kiện."""

    def __init__(self):
        self.schedules = []  # danh sách lịch
        self.scan_queue = []  # hàng đợi scan

    def add_ondemand_scan(self, target, profile='safe-active'):
        """Scan ngay khi yêu cầu."""
        job = {
            'job_id': f"JOB-{len(self.schedules) + 1:04d}",
            'target': target,
            'profile': profile,
            'schedule_type': 'ondemand',
            'status': 'queued',
            'created_at': datetime.now().isoformat(),
        }
        self.schedules.append(job)
        self.scan_queue.append(job)
        return job

    def add_cron_scan(self, target, profile, cron_expr, description=''):
        """Lịch quét định kỳ theo cron expression."""
        job = {
            'job_id': f"JOB-{len(self.schedules) + 1:04d}",
            'target': target,
            'profile': profile,
            'schedule_type': 'cron',
            'cron_expr': cron_expr,
            'description': description,
            'status': 'scheduled',
            'created_at': datetime.now().isoformat(),
        }
        self.schedules.append(job)
        return job

    def add_event_scan(self, target, profile, event_type='new_asset'):
        """Scan theo sự kiện (asset mới/CVE mới)."""
        job = {
            'job_id': f"JOB-{len(self.schedules) + 1:04d}",
            'target': target,
            'profile': profile,
            'schedule_type': 'event',
            'event_type': event_type,
            'status': 'waiting_event',
            'created_at': datetime.now().isoformat(),
        }
        self.schedules.append(job)
        return job

    def trigger_event(self, event_type='new_asset'):
        """Kích hoạt scan khi sự kiện xảy ra."""
        triggered = []
        for job in self.schedules:
            if (job.get('schedule_type') == 'event'
                    and job.get('event_type') == event_type
                    and job.get('status') == 'waiting_event'):
                job['status'] = 'queued'
                self.scan_queue.append(job)
                triggered.append(job)
        return triggered

    def get_queue(self):
        return list(self.scan_queue)

    def mark_running(self, job_id):
        for job in self.schedules:
            if job['job_id'] == job_id:
                job['status'] = 'running'
                return True
        return False

    def mark_completed(self, job_id):
        for job in self.schedules:
            if job['job_id'] == job_id:
                job['status'] = 'completed'
                job['completed_at'] = datetime.now().isoformat()
                return True
        return False

    def get_stats(self):
        return {
            'total_jobs': len(self.schedules),
            'queued': len(self.scan_queue),
            'by_type': {
                'ondemand': sum(1 for j in self.schedules if j['schedule_type'] == 'ondemand'),
                'cron': sum(1 for j in self.schedules if j['schedule_type'] == 'cron'),
                'event': sum(1 for j in self.schedules if j['schedule_type'] == 'event'),
            }
        }


# ══════════════════════════════════════════════════════════════
# #79 Business Logic Testing
# ══════════════════════════════════════════════════════════════

class BusinessLogicScanner:
    """Test logic nghiệp vụ: price, quantity, coupon, order."""

    def __init__(self, request_handler=None, base_url=None):
        self.request_handler = request_handler
        self.base_url = base_url

    def generate_price_payloads(self):
        """Sinh payload price manipulation."""
        return {
            'negative_price': {'price': -100, 'quantity': 1},
            'zero_price': {'price': 0, 'quantity': 1},
            'huge_quantity': {'price': 10, 'quantity': 999999},
            'negative_quantity': {'price': 10, 'quantity': -1},
            'decimal_price': {'price': 0.01, 'quantity': 1},
        }

    def generate_coupon_payloads(self):
        """Sinh payload coupon abuse."""
        return [
            {'coupon': 'SAVE100', 'repeat': 10},   # áp dụng nhiều lần
            {'coupon': 'SAVE100', 'order_total': 1},  # dùng cho đơn nhỏ
            {'coupon': 'FREE', 'quantity': -1},    # quantity âm + coupon
        ]

    def scan_price_logic(self, endpoint, param_names=('price', 'quantity')):
        """Test manipulation price/quantity."""
        if not self.request_handler or not self.base_url:
            return {'vulnerabilities': [], 'note': 'Không thể test business logic'}

        findings = []
        payloads = self.generate_price_payloads()

        for name, data in payloads.items():
            try:
                resp = self.request_handler.send_request(
                    'POST', self.base_url + endpoint,
                    data=data,
                    headers={'Content-Type': 'application/json'},
                )
                status = getattr(resp, 'status_code', 0)
                text = getattr(resp, 'text', '')

                # Server chấp nhận giá trị bất thường → lỗ hổng logic
                if status in (200, 201, 202) and 'error' not in text.lower():
                    findings.append({
                        'type': 'Business Logic Flaw',
                        'severity': 'Medium',
                        'detail': f"Server chấp nhận {name}: {json.dumps(data)}",
                        'confidence': 'Medium',
                        'payload': json.dumps(data),
                    })
            except Exception:
                continue

        return {'vulnerabilities': findings}

    def scan_coupon_abuse(self, endpoint):
        """Test coupon abuse."""
        if not self.request_handler:
            return {'vulnerabilities': [], 'note': 'Không thể test coupon'}

        findings = []
        for payload in self.generate_coupon_payloads():
            try:
                resp = self.request_handler.send_request(
                    'POST', self.base_url + endpoint,
                    data=json.dumps(payload),
                    headers={'Content-Type': 'application/json'},
                )
                status = getattr(resp, 'status_code', 0)
                if status in (200, 201) and 'error' not in getattr(resp, 'text', '').lower():
                    findings.append({
                        'type': 'Coupon Abuse',
                        'severity': 'Medium',
                        'detail': f"Server chấp nhận coupon abuse: {json.dumps(payload)}",
                        'confidence': 'Low',
                        'payload': json.dumps(payload),
                    })
            except Exception:
                continue
        return {'vulnerabilities': findings}


# ══════════════════════════════════════════════════════════════
# #65 Secret Encryption at Rest
# ══════════════════════════════════════════════════════════════

class SecretVault:
    """Mã hóa credentials at rest — không lưu plaintext.

    Dùng Fernet (AES-128-CBC + HMAC-SHA256, thư viện `cryptography`) — trước
    đây module này dùng XOR lặp-khoá và tự gọi đó là "mã hóa", nhưng XOR với
    khoá cố định bị phá trong vài giây bằng known-plaintext/frequency attack,
    nên không đạt yêu cầu "Secret Encryption at Rest" của đặc tả §14.
    """

    def __init__(self, master_key_file=None):
        """Nếu không có key file, tự tạo key mới."""
        from cryptography.fernet import Fernet
        self._fernet = Fernet(self._load_or_create_key(master_key_file))

    def _load_or_create_key(self, key_file):
        from cryptography.fernet import Fernet
        if key_file and os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                return f.read()
        key = Fernet.generate_key()
        if key_file:
            os.makedirs(os.path.dirname(key_file) or '.', exist_ok=True)
            with open(key_file, 'wb') as f:
                f.write(key)
        return key

    def encrypt(self, secret_text):
        """Mã hóa secret bằng Fernet (AES-128-CBC + HMAC)."""
        return self._fernet.encrypt(secret_text.encode('utf-8')).decode()

    def decrypt(self, encrypted_token):
        """Giải mã secret."""
        return self._fernet.decrypt(encrypted_token.encode('utf-8')).decode('utf-8')

    def store_credential(self, name, username, password):
        """Lưu credential mã hóa."""
        encrypted = self.encrypt(f"{username}:{password}")
        return {
            'name': name,
            'username_encrypted': self.encrypt(username),
            'credential_encrypted': encrypted,
            'stored_at': datetime.now().isoformat(),
            'plaintext_visible': False,
        }

    def redact_secrets(self, text):
        """Redact các secret pattern trong text trước khi log/report."""
        # Reuse từ ExploitModule
        from exploitation import ExploitModule
        return ExploitModule.redact_evidence(text)