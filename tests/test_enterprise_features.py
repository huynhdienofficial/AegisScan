import sys
import json
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SMART = ROOT / 'smart_scanner'
sys.path.insert(0, str(SMART))

from scanners.cloud_scanner import CloudScanner
from scanners.os_hardening import OSHardeningScanner
from enterprise import SIEMIntegrator, TicketingIntegrator, PublicAPI
from storage import SQLiteStorage


def test_cloud_scanner_aws_findings():
    """CloudScanner phát hiện lỗ hổng AWS."""
    config = {
        'aws': {
            'iam': {
                'root_mfa_enabled': False,
                'users': [
                    {'name': 'admin-user', 'is_admin': True, 'mfa_enabled': False},
                ],
            },
            's3': {
                'buckets': [
                    {'name': 'public-bucket', 'public': True, 'encryption_enabled': False},
                ],
            },
            'ec2': {
                'security_groups': [
                    {'name': 'sg-1', 'rules': [{'port': 22, 'cidr': '0.0.0.0/0'}]},
                ],
            },
        },
    }
    scanner = CloudScanner(cloud_provider='aws', config_json=config)
    findings = scanner.scan()['vulnerabilities']

    check_ids = [f['check_id'] for f in findings]
    assert 'AWS-IAM-001' in check_ids  # Root MFA
    assert 'AWS-IAM-002' in check_ids  # Admin MFA
    assert 'AWS-S3-001' in check_ids   # Public bucket
    assert 'AWS-S3-002' in check_ids   # No encryption
    assert 'AWS-EC2-001' in check_ids  # Open port


def test_cloud_scanner_azure_and_gcp():
    """CloudScanner hỗ trợ Azure + GCP."""
    azure = CloudScanner(config_json={
        'azure': {'ad': {'mfa_enabled': False}, 'storage': {'accounts': [{'name': 'blob1', 'public_access': True}]}}
    })
    az_findings = azure.scan()['vulnerabilities']
    assert any(f['check_id'] == 'AZ-AD-001' for f in az_findings)
    assert any(f['check_id'] == 'AZ-STORAGE-001' for f in az_findings)

    gcp = CloudScanner(config_json={
        'gcp': {'storage': {'buckets': [{'name': 'bucket1', 'public': True}]}}
    })
    gcp_findings = gcp.scan()['vulnerabilities']
    assert any(f['check_id'] == 'GCP-STORE-001' for f in gcp_findings)


def test_os_hardening_cis_compliance():
    """OSH hardening scan chấm điểm compliance."""
    config = """
    # /etc/ssh/sshd_config
    PermitRootLogin yes
    PasswordAuthentication no
    Protocol 1
    X11Forwarding no
    MaxAuthTries 3

    # /etc/sudoers
    %admin ALL=(ALL) NOPASSWD: ALL
    """
    scanner = OSHardeningScanner(config_text=config)
    result = scanner.scan()

    assert 'compliance_score' in result
    assert result['total_checks'] == 13
    assert result['failed_checks'] > 0
    assert 'CIS-1.1.1' in [f['check_id'] for f in result['vulnerabilities']]


def test_siem_and_ticketing_integration():
    """SIEM + Ticketing integration hoạt động."""
    siem = SIEMIntegrator(siem_type='splunk')
    findings = [
        {'severity': 'High', 'title': 'SQL Injection', 'type': 'SQLi', 'url': 'https://x.com/login'},
        {'severity': 'Critical', 'title': 'RCE', 'type': 'RCE', 'url': 'https://x.com/cmd'},
    ]
    events = siem.send_batch(findings)
    assert len(events) == 2
    assert events[0]['type'] == 'splunk'

    ticketing = TicketingIntegrator(ticketing_type='jira', project='SEC')
    ticket = ticketing.create_ticket(findings[1])
    assert ticket['priority'] == 'P1'
    assert ticket['project'] == 'SEC'
    assert ticket['status'] == 'open'


def test_public_api():
    """Public API trả findings dạng JSON + SARIF."""
    api = PublicAPI(api_key='test-key')
    assert api.authenticate('test-key') is True
    assert api.authenticate('wrong') is False

    findings = [{'type': 'SQLi', 'severity': 'Critical', 'url': 'https://x.com'}]
    json_result = api.get_findings(findings, format='json')
    data = json.loads(json_result)
    assert data['count'] == 1

    sarif_result = api.get_findings(findings, format='sarif')
    sarif = json.loads(sarif_result)
    assert sarif['version'] == '2.1.0'


def test_sqlite_storage(tmp_path):
    """SQLite storage lưu scan/asset/finding đúng cách."""
    db_path = tmp_path / 'test_scanner.db'
    storage = SQLiteStorage(db_path=str(db_path))

    # Save scan
    storage.save_scan({
        'scan_id': 'SCAN-001',
        'target': 'https://example.com',
        'profile': 'safe-active',
        'started_at': '2026-01-01T00:00:00',
        'status': 'completed',
    })

    # Save asset
    storage.save_asset({
        'asset_id': 'AST-0001',
        'name': 'Web Server',
        'asset_type': 'web_app',
        'hostname': 'example.com',
        'url': 'https://example.com',
        'environment': 'production',
        'business_criticality': 'high',
    })

    # Save finding (evidence tự redact)
    storage.save_finding({
        'finding_id': 'FND-000001',
        'asset_id': 'AST-0001',
        'scan_id': 'SCAN-001',
        'rule_id': 'SQLI-001',
        'severity': 'Critical',
        'title': 'SQL Injection',
        'status': 'suspected',
        'evidence': {'request': 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc.def'},
    })

    # Verify
    scan = storage.get_scan('SCAN-001')
    assert scan['target'] == 'https://example.com'

    assets = storage.list_assets()
    assert len(assets) == 1
    assert assets[0]['hostname'] == 'example.com'

    findings = storage.list_findings()
    assert len(findings) == 1
    assert findings[0]['severity'] == 'Critical'

    # Evidence đã redact — không chứa token
    evidence = findings[0]['evidence']
    assert 'eyJhbGciOiJIUzI1NiJ9' not in evidence

    stats = storage.get_stats()
    assert stats['scans'] == 1
    assert stats['assets'] == 1
    assert stats['findings'] == 1

    storage.close()