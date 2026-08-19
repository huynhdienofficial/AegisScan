import asyncio
import sys
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SMART = ROOT / 'smart_scanner'
sys.path.insert(0, str(SMART))

from scanners.database_scanner import DatabaseScanner
from scanners.kubernetes_scanner import KubernetesScanner
from scanners.web.advanced_scanners import WAFEvasionScanner, RequestSmugglingScanner, RaceConditionScanner
from exploitation import ExploitModule, RemediationManager, NotificationService, ComplianceMapper
from utils.rbac import RBACManager, Role
from utils.authorization import AuthorizationRegistry


def test_database_scanner_postgresql_config():
    """DatabaseScanner phát hiện lỗ hổng PostgreSQL config."""
    config = """
    # PostgreSQL config
    listen_addresses = '*'
    ssl = off
    password_encryption = md5
    """
    scanner = DatabaseScanner(config_text=config, db_type='postgresql')
    findings = scanner.scan()['vulnerabilities']

    assert len(findings) >= 2
    types = [f['type'] for f in findings]
    assert 'Database Network Exposure' in types
    assert 'Database TLS Disabled' in types


def test_database_scanner_mysql_default_credentials():
    """DatabaseScanner phát hiện default credentials MySQL."""
    config = """
    user = root
    password = root
    bind-address = 0.0.0.0
    """
    scanner = DatabaseScanner(config_text=config, db_type='mysql')
    findings = scanner.scan()['vulnerabilities']

    types = [f['type'] for f in findings]
    assert 'Database Default Credential' in types
    assert 'Database Network Exposure' in types


def test_kubernetes_scanner_manifest():
    """KubernetesScanner phát hiện cấu hình nguy hiểm."""
    manifest = """
    apiVersion: v1
    kind: Pod
    metadata:
      name: test-pod
    spec:
      securityContext:
        runAsNonRoot: false
      containers:
      - name: app
        image: nginx
        securityContext:
          privileged: true
          capabilities:
            add:
            - CAP_SYS_ADMIN
        volumeMounts:
        - name: docker
          mountPath: /var/run/docker.sock
    volumes:
    - name: docker
      hostPath:
        path: /var/run/docker.sock
    """
    scanner = KubernetesScanner(manifest_text=manifest)
    findings = scanner.scan()['vulnerabilities']

    types = [f['type'] for f in findings]
    assert 'K8s Privileged Container' in types
    assert 'K8s Dangerous Capability' in types


def test_waf_evasion_generates_variants():
    """WAFEvasionScanner sinh các encoding khác nhau."""
    scanner = WAFEvasionScanner(request_handler=None)
    variants = scanner.generate_evasion_payloads("' OR 1=1--")

    assert 'original' in variants
    assert 'url' in variants
    assert 'sql_comment' in variants
    # URL encoded khác original
    assert variants['url'] != "' OR 1=1--"


def test_request_smuggling_no_handler():
    """RequestSmugglingScanner không có request_handler."""
    scanner = RequestSmugglingScanner(request_handler=None, target_url='https://x.com')
    result = asyncio.run(scanner.scan())
    assert 'note' in result


def test_exploitation_module_levels():
    """Exploitation Module Level 1-3 có kiểm soát — cần CẢ RBAC approve
    LẪN một Authorization Record hợp lệ, không chỉ một approver_username."""
    rbac = RBACManager()
    rbac.create_user('admin1', Role.ADMIN)

    module = ExploitModule(rbac_manager=rbac, target_url='https://lab.example.com')

    # Level 1 mặc định bật
    findings = module.level1_signal_detection(
        response_text="ERROR: You have an error in your SQL syntax",
        headers={'server': 'nginx/1.18.0'},
    )
    assert len(findings) >= 1

    # Thiếu Authorization Record → bị từ chối dù approver hợp lệ
    assert module.enable_level(2, approver_username='admin1') is False
    assert module.level == 1

    # Có Authorization Record hợp lệ, đúng tier, đúng scope → được bật
    registry = AuthorizationRegistry(rbac_manager=rbac)
    record = registry.issue('admin1', scope=['lab.example.com'], authorization_type='active_scan')
    assert module.enable_level(2, approver_username='admin1', authorization_record=record) is True
    assert module.level == 2

    # Kill-switch dừng ngay
    module.emergency_stop()
    result = module.level2_safe_verification(lambda: [{'type': 'test'}])
    assert result == []


def test_exploitation_module_self_approval_bypass_closed():
    """Không thể tự cấp quyền Level 2/3 chỉ bằng cách truyền approved_by ở
    constructor — đây là lỗ hổng đã được vá."""
    module = ExploitModule(approved_by='self-approved-hacker', target_url='https://lab.example.com')
    # approved_by ở constructor không nâng level
    assert module.level == 1
    # Không có rbac_manager → enable_level(2) luôn bị từ chối
    assert module.enable_level(2, approver_username='anyone') is False
    assert module.level == 1


def test_exploitation_level3_blocks_production_regardless_of_target_string_bug():
    """Regression test cho lỗi logic: điều kiện production-check trước đây
    LUÔN đúng bất kể target có phải production hay không (do ưu tiên toán
    tử `and`/`or` sai), khiến Level 3 luôn "executed" kể cả trên production."""
    rbac = RBACManager()
    rbac.create_user('admin1', Role.ADMIN)
    registry = AuthorizationRegistry(rbac_manager=rbac)

    module = ExploitModule(rbac_manager=rbac, target_url='https://myapp-production.example.com')
    record = registry.issue('admin1', scope=['myapp-production.example.com'], authorization_type='exploitation')
    assert module.enable_level(3, approver_username='admin1', authorization_record=record) is True

    result = module.level3_controlled_exploit('https://myapp-production.example.com', dry_run=False)
    assert result['status'] == 'blocked'
    assert 'production' in result['reason'].lower() or 'Production' in result['reason']

    # Target không phải production → được phép "executed"
    lab_module = ExploitModule(rbac_manager=rbac, target_url='https://lab.example.com')
    lab_record = registry.issue('admin1', scope=['lab.example.com'], authorization_type='exploitation')
    assert lab_module.enable_level(3, approver_username='admin1', authorization_record=lab_record) is True
    lab_result = lab_module.level3_controlled_exploit('https://lab.example.com', dry_run=False)
    assert lab_result['status'] == 'executed'


def test_exploit_evidence_redaction():
    """Evidence redaction che giấu secrets."""
    text = """
    Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0
    Cookie: sessionid=abc123
    API key: AKIAIOSFODNN7EXAMPLE
    """
    redacted = ExploitModule.redact_evidence(text)
    assert 'eyJhbGci' not in redacted
    assert 'abc123' not in redacted
    assert 'AKIAIOSFODNN7EXAMPLE' not in redacted
    assert 'REDACTED' in redacted


def test_remediation_workflow():
    """RemediationWorkflow: pending → approved → executed → closed."""
    manager = RemediationManager()
    rem = manager.create_remediation(
        finding_id='FND-000001',
        level=2,
        action='sudo apt update && sudo apt upgrade openssh-server',
        description='Upgrade OpenSSH lên bản mới',
    )

    rem2 = manager.preview(rem.get('finding_id'))
    # Tìm lại theo id nếu có
    all_rems = manager.remediations
    target = all_rems[0]
    manager.dry_run(target.get('id', 'FND-000001'))
    manager.approve(target.get('id', 'FND-000001'), 'admin1')
    
    # Execute khi đã approved
    result = manager.execute(target.get('id', 'FND-000001'))
    assert result.get('status') == 'executed'
    assert 'executed_at' in result


def test_notification_critical_only():
    """Notification chỉ gửi cho Critical/High."""
    service = NotificationService(webhook_url='https://example.com/hook')
    # Low → không gửi
    low = service.notify_critical_finding({'severity': 'Low', 'type': 'test'})
    assert low is None
    # Critical → gửi
    critical = service.notify_critical_finding(
        {'severity': 'Critical', 'type': 'SQLi', 'title': 'SQL Injection'}
    )
    assert critical is not None
    assert 'webhook' in critical['channels']


def test_compliance_mapping():
    """ComplianceMapper map finding sang ISO/SOC/PCI."""
    mapping = ComplianceMapper.map_finding({
        'type': 'SQL Injection',
        'title': 'SQLi in login',
    })
    assert 'PCI DSS 6.6' in mapping['mapped_controls']
    assert any('ISO 27001' in c for c in mapping['mapped_controls'])