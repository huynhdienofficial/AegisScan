import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SMART = ROOT / 'smart_scanner'
sys.path.insert(0, str(SMART))

from agents import AgentlessCollector, AgentCollector, AgentManager
from sbom import SBOMGenerator, SecurityDashboard, ZeroDayML


def test_agentless_collector():
    """AgentlessCollector kiểm tra port."""
    collector = AgentlessCollector(host='localhost', port=9999, timeout=1)
    result = collector.collect()
    assert result['host'] == 'localhost'
    assert 'port_open' in result


def test_agent_manager_lifecycle():
    """AgentManager deploy/update/heartbeat/remove."""
    mgr = AgentManager()
    agent = mgr.deploy_agent(hostname='web-server-01')
    assert agent.agent_id.startswith('AGENT-')

    assert mgr.update_agent(agent.agent_id, '1.1.0') is True
    assert mgr.heartbeat(agent.agent_id) is True

    health = mgr.check_health(agent.agent_id)
    assert health[agent.agent_id]['status'] == 'healthy'

    assert mgr.remove_agent(agent.agent_id) is True
    stats = mgr.get_stats()
    assert stats['total_agents'] == 0


def test_agent_collector_system_info():
    """AgentCollector lấy thông tin hệ thống."""
    agent = AgentCollector()
    info = agent.get_system_info()
    assert 'os' in info
    assert 'hostname' in info


def test_sbom_generator_python():
    """SBOMGenerator sinh components từ requirements.txt."""
    tmp = ROOT / 'smart_scanner'
    sbom = SBOMGenerator()
    components = sbom.scan_python(path=str(tmp))
    assert len(components) > 0

    cyclonedx = sbom.generate_cyclonedx()
    assert cyclonedx['bomFormat'] == 'CycloneDX'
    assert len(cyclonedx['components']) > 0

    spdx = sbom.generate_spdx()
    assert spdx['spdxVersion'] == 'SPDX-2.3'


def test_sbom_generator_node():
    """SBOMGenerator parse package.json."""
    import json
    tmp = ROOT / 'smart_scanner'
    sbom = SBOMGenerator()
    # Tự tạo package.json trong temp
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        pkg = {'dependencies': {'express': '^4.18.0', 'lodash': '~4.17.21'}}
        with open(Path(tmpdir) / 'package.json', 'w') as f:
            json.dump(pkg, f)
        components = sbom.scan_node(path=tmpdir)
        assert len(components) == 2
        assert 'express' in [c['name'] for c in components]


def test_security_dashboard_trend():
    """SecurityDashboard tạo trend + top risk."""
    dash = SecurityDashboard()
    dash.record_scan([
        {'severity': 'Critical'}, {'severity': 'High'}, {'severity': 'Medium'}
    ], asset_id='AST-0001')

    trend = dash.trend_by_severity()
    assert len(trend['labels']) == 1
    assert trend['series']['critical'] == [1]

    top = dash.top_risk_assets()
    assert len(top) == 1
    assert top[0]['asset_id'] == 'AST-0001'


def test_zero_day_ml_detection():
    """ZeroDayML phát hiện anomaly."""
    ml = ZeroDayML()
    # Học baseline bình thường
    for i in range(10):
        ml.learn_baseline('/api/login', response_time=0.15, error_rate=0.01)

    # Response bình thường → không anomaly
    normal = ml.detect_anomaly('/api/login', response_time=0.2, error_rate=0.02)
    assert normal['is_anomaly'] is False

    # Response quá chậm → anomaly
    slow = ml.detect_anomaly('/api/login', response_time=5.0, error_rate=0.9)
    assert slow['is_anomaly'] is True
    assert 'Response time' in slow['reason']