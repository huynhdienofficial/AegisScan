import sys
import json
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SMART = ROOT / 'smart_scanner'
sys.path.insert(0, str(SMART))

from governance import (
    FirewallRuleReview,
    ExploitManifestRegistry,
    BusinessImpactScoring,
    RemediationAutomation,
    ScanScheduler,
    BusinessLogicScanner,
    SecretVault,
)


def test_firewall_rule_review():
    """FirewallRuleReview phát hiện port nhạy cảm mở Internet."""
    rules = [
        {'port': 22, 'source': '0.0.0.0/0', 'action': 'ALLOW', 'protocol': 'tcp'},
        {'port': 443, 'source': '0.0.0.0/0', 'action': 'ALLOW', 'protocol': 'tcp'},
        {'port': 3306, 'source': '0.0.0.0/0', 'action': 'ALLOW', 'protocol': 'tcp'},
        {'port': 3389, 'source': '10.0.0.0/8', 'action': 'ALLOW', 'protocol': 'tcp'},
    ]
    review = FirewallRuleReview(current_rules=rules)
    result = review.review()

    assert result['rules_reviewed'] == 4
    assert len(result['violations']) >= 2

    types = [v['type'] for v in result['violations']]
    assert 'Sensitive Port Exposed To Internet' in types
    assert 'compliance' in result


def test_exploit_manifest_registry():
    """ExploitManifestRegistry đăng ký đúng manifest."""
    registry = ExploitManifestRegistry()

    # Đăng ký module an toàn (không disrupt)
    registry.register_module(
        module_id='EXP-001',
        name='Log4Shell Detection',
        cve_ref='CVE-2021-44228',
        preconditions=['Apache Log4j version < 2.15'],
        impact_description='RCE qua JNDI lookup',
        can_disrupt=False,
        rollback_method='None',
    )

    # Đăng ký module gây gián đoạn (cần approver)
    registry.register_module(
        module_id='EXP-002',
        name='Heartbleed Data Read',
        cve_ref='CVE-2014-0160',
        preconditions=['OpenSSL 1.0.1-1.0.1f'],
        impact_description='Đọc memory nếu khai thác sâu',
        can_disrupt=True,
        rollback_method='Restart service',
        risk_level='High',
    )

    # Module an toàn bật được không cần approver
    result1 = registry.enable_module('EXP-001')
    assert result1['ok'] is True

    # Module gây gián đoạn cần approver
    result2 = registry.enable_module('EXP-002')
    assert result2['ok'] is False
    assert 'approver' in result2['reason']

    # Với approver → bật được
    result3 = registry.enable_module('EXP-002', approved_by='admin1')
    assert result3['ok'] is True


def test_business_impact_scoring():
    """BusinessImpactScoring tính score 0-100."""
    scorer = BusinessImpactScoring()

    # Asset quan trọng: ảnh hưởng lớn
    scorer.set_impact('AST-0001', revenue=5, customer_data=5, financial_data=5, operations=5)
    high = scorer.calculate_score('AST-0001')
    assert high['business_impact_score'] >= 80
    assert high['rating'] == 'Critical'

    # Asset ít quan trọng
    scorer.set_impact('AST-0002', revenue=1, customer_data=1, financial_data=1, operations=1)
    low = scorer.calculate_score('AST-0002')
    assert low['business_impact_score'] <= 20

    # Asset chưa đặt → 0
    assert scorer.calculate_score('AST-9999') == 0


def test_remediation_automation():
    """RemediationAutomation tạo Ansible playbook + Bash script."""
    automation = RemediationAutomation()

    # Ansible playbook
    pb = automation.generate_ansible_playbook(
        finding_id='FND-0001',
        hosts='webservers',
        tasks=[
            {'name': 'Update nginx', 'module': 'apt', 'args': 'name: nginx\n      state: latest'},
            {'name': 'Restart nginx', 'module': 'service', 'args': 'name: nginx\n      state: restarted'},
        ],
        name='Fix nginx vuln',
    )
    assert pb['type'] == 'ansible'
    assert pb['hosts'] == 'webservers'
    assert '- name: Update nginx' in pb['content']
    assert 'ansible.builtin.apt' in pb['content']

    # Bash script
    script = automation.generate_bash_script(
        finding_id='FND-0002',
        commands=[
            {'description': 'Upgrade openssh', 'command': 'sudo apt upgrade -y openssh-server'},
        ],
        name='SSH fix',
    )
    assert script['type'] == 'bash'
    assert 'sudo apt upgrade' in script['content']

    # Đăng ký playbook
    registered = automation.register_playbook(pb)
    assert registered['id'].startswith('PB-')


def test_scan_scheduler():
    """ScanScheduler lên lịch on-demand/cron/event."""
    scheduler = ScanScheduler()

    # On-demand
    job = scheduler.add_ondemand_scan('https://example.com')
    assert job['status'] == 'queued'
    assert len(scheduler.get_queue()) == 1

    # Cron
    cron = scheduler.add_cron_scan('https://example.com', 'safe-active', '0 2 * * *', 'Scan hàng đêm')
    assert cron['schedule_type'] == 'cron'

    # Event
    event = scheduler.add_event_scan('https://new-service.com', 'safe-active', event_type='new_asset')
    assert event['status'] == 'waiting_event'

    # Trigger event
    triggered = scheduler.trigger_event(event_type='new_asset')
    assert len(triggered) == 1
    assert triggered[0]['status'] == 'queued'

    # Complete
    assert scheduler.mark_running(job['job_id']) is True
    assert scheduler.mark_completed(job['job_id']) is True

    stats = scheduler.get_stats()
    assert stats['total_jobs'] == 3


def test_business_logic_scanner():
    """BusinessLogicScanner sinh payload price manipulation."""
    scanner = BusinessLogicScanner(request_handler=None)

    # Không có handler → không test được
    result = scanner.scan_price_logic('/checkout')
    assert 'note' in result

    # Verify payload generation
    payloads = scanner.generate_price_payloads()
    assert 'negative_price' in payloads
    assert 'huge_quantity' in payloads

    coupons = scanner.generate_coupon_payloads()
    assert len(coupons) >= 3
    assert 'SAVE100' in coupons[0]['coupon']


def test_secret_vault_encryption():
    """SecretVault mã hóa credentials."""
    vault = SecretVault()

    # Encrypt/decrypt roundtrip
    encrypted = vault.encrypt('my-password-123')
    assert encrypted != 'my-password-123'  # Không phải plaintext
    assert vault.decrypt(encrypted) == 'my-password-123'

    # Store credential — không lộ plaintext
    cred = vault.store_credential('db_prod', 'admin', 'SuperSecret123')
    assert cred['plaintext_visible'] is False
    assert 'SuperSecret123' not in str(cred)
    assert 'admin' not in str(cred['credential_encrypted'])

    # Decrypt lại đúng
    decrypted = vault.decrypt(cred['credential_encrypted'])
    assert decrypted == 'admin:SuperSecret123'


def test_secret_vault_uses_real_encryption_not_xor():
    """Regression: vault trước đây dùng XOR lặp-khoá (dễ phá bằng
    known-plaintext) dù gọi là 'mã hóa'. Nay dùng Fernet (AES + HMAC) —
    hai lần mã hóa cùng plaintext phải cho ciphertext KHÁC nhau (do IV/nonce
    ngẫu nhiên), điều XOR-với-khoá-cố-định không bao giờ thỏa mãn."""
    vault = SecretVault()
    c1 = vault.encrypt('same-secret')
    c2 = vault.encrypt('same-secret')
    assert c1 != c2
    assert vault.decrypt(c1) == 'same-secret'
    assert vault.decrypt(c2) == 'same-secret'


def test_exploit_manifest_registry_validates_approver_via_rbac():
    """Khi ExploitManifestRegistry được gắn RBACManager, approved_by phải
    là user thật có quyền exploit.approve — không còn chấp nhận chuỗi bất kỳ."""
    from utils.rbac import RBACManager, Role

    rbac = RBACManager()
    rbac.create_user('admin1', Role.ADMIN)
    rbac.create_user('viewer1', Role.VIEWER)

    registry = ExploitManifestRegistry(rbac_manager=rbac)
    registry.register_module(
        module_id='EXP-003', name='Disrupt Module', cve_ref='CVE-2020-0001',
        preconditions=[], impact_description='Có thể gây gián đoạn',
        can_disrupt=True, rollback_method='Restart',
    )

    # Chuỗi tuỳ ý không còn hợp lệ khi có RBAC gắn kèm
    denied = registry.enable_module('EXP-003', approved_by='not-a-real-user')
    assert denied['ok'] is False

    # Viewer không có quyền exploit.approve
    denied2 = registry.enable_module('EXP-003', approved_by='viewer1')
    assert denied2['ok'] is False

    # Admin thật → được phép
    allowed = registry.enable_module('EXP-003', approved_by='admin1')
    assert allowed['ok'] is True