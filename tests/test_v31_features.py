import json
import sys
import time as time_module
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SMART = ROOT / 'smart_scanner'
sys.path.insert(0, str(SMART))

from assets.asset_manager import Asset, AssetInventory
from finding_management import FindingManager
from report_exporters import SARIFExporter, CSVExporter, MultiFactorRiskEngine
from scanners.infra_scanner import PortScanner


def test_asset_inventory_manages_assets():
    inv = AssetInventory()
    asset = Asset(
        name='Web Server',
        asset_type='web_app',
        hostname='example.com',
        url='https://example.com',
        environment='production',
        business_criticality='high',
        internet_facing=True,
        network_zone='internet',
    )
    asset_id = inv.add_asset(asset)
    assert asset_id == 'AST-0001'
    assert inv.get_asset(asset_id).hostname == 'example.com'
    assert len(inv.assets) == 1

    found = inv.find_by_hostname('example.com')
    assert found is not None
    assert found.asset_id == asset_id

    shadow = inv.detect_shadow_it(['evil.com', 'example.com'])
    assert len(shadow) == 1
    assert shadow[0]['hostname'] == 'evil.com'


def test_finding_management_lifecycle_and_duplicates():
    mgr = FindingManager()
    f1 = mgr.create_finding(
        asset_id='AST-0001', rule_id='SQLI-001', severity='Critical',
        title='SQL Injection', endpoint='https://example.com/login?user=test',
        parameter='user', payload="' OR 1=1--",
        evidence={'request': 'GET /login?user=', 'response': 'SQL syntax error'},
    )
    f2 = mgr.create_finding(
        asset_id='AST-0001', rule_id='SQLI-001', severity='Critical',
        title='SQL Injection Duplicate', endpoint='https://example.com/login?user=test',
        parameter='user', payload="' OR 1=1--",
        evidence={'request': 'GET /login?user=', 'response': 'SQL syntax error'},
    )

    assert f1.status == 'suspected'
    f1.update_status('verified')
    f1.update_status('confirmed')
    assert f1.status == 'confirmed'

    dups = mgr.correlate_duplicates()
    assert len(dups) == 1
    assert dups[0]['count'] == 2
    assert f2.duplicate_of == f1.finding_id

    f1.suppress(reason='False positive', approver='admin', expires_in_days=30)
    assert f1.suppressed is True
    assert f1.suppression_approver == 'admin'


def test_finding_delta_comparison():
    mgr = FindingManager()
    f1 = mgr.create_finding('AST-0001', 'XSS-001', 'High', 'XSS Found',
                            endpoint='https://example.com/search?q=1')
    mgr.take_snapshot('SCAN-001', 'https://example.com')

    f1.update_status('resolved')
    mgr.create_finding('AST-0001', 'SSRF-001', 'High', 'SSRF Found',
                       endpoint='https://example.com/url?target=http://x')
    mgr.take_snapshot('SCAN-002', 'https://example.com')

    delta = mgr.compare_snapshots('SCAN-001', 'SCAN-002')
    assert delta is not None
    assert delta['summary']['fixed_count'] == 1
    assert delta['summary']['new_count'] == 1


def test_infra_scanner_port_findings_network_exposure():
    open_ports = [
        {'port': 3306, 'service': 'MySQL', 'internet_facing': True, 'network_zone': 'internet'},
        {'port': 443, 'service': 'HTTPS', 'internet_facing': True, 'network_zone': 'internet'},
        {'port': 22, 'service': 'SSH', 'internet_facing': False, 'network_zone': 'internal'},
    ]
    findings = PortScanner.get_findings('db.example.com', open_ports, internet_facing=True)
    assert len(findings) == 3

    mysql_find = [f for f in findings if f.get('port') == 3306][0]
    assert mysql_find['severity'] == 'High'
    assert 'INTERNET' in mysql_find['detail']

    https_find = [f for f in findings if f.get('port') == 443][0]
    assert https_find['severity'] == 'Info'


def test_sarif_and_csv_export(tmp_path):
    findings = [
        {
            'type': 'SQL Injection', 'severity': 'Critical', 'url': 'https://x.com/login',
            'parameter': 'user', 'payload': "' OR 1=1--", 'detail': 'SQL error detected',
        },
        {
            'type': 'XSS', 'severity': 'Medium', 'url': 'https://x.com/search',
            'parameter': 'q', 'payload': '<script>alert(1)</script>', 'detail': 'Reflection',
        },
    ]

    sarif_path = tmp_path / 'scan.sarif'
    SARIFExporter.save(findings, str(sarif_path))
    assert sarif_path.exists()
    sarif = json.loads(sarif_path.read_text(encoding='utf-8'))
    assert sarif['version'] == '2.1.0'
    assert len(sarif['runs'][0]['results']) == 2

    csv_path = tmp_path / 'scan.csv'
    CSVExporter.export(findings, str(csv_path))
    assert csv_path.exists()
    content = csv_path.read_text(encoding='utf-8')
    assert 'SQL Injection' in content
    assert 'XSS' in content


def test_multi_factor_risk_engine():
    high_risk = MultiFactorRiskEngine.calculate(
        cvss_score=9.8,
        epss=0.95,
        in_kev=True,
        network_zone='internet',
        business_criticality='critical',
        environment='production',
        internet_facing=True,
    )
    assert high_risk['rating'] == 'Critical'
    assert high_risk['risk_score'] >= 80

    low_risk = MultiFactorRiskEngine.calculate(
        cvss_score=9.8,
        epss=0.0,
        in_kev=False,
        network_zone='localhost',
        business_criticality='low',
        environment='lab',
        internet_facing=False,
    )
    assert low_risk['risk_score'] < high_risk['risk_score']
    assert 'breakdown' in low_risk