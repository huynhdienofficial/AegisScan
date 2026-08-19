import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SMART = ROOT / 'smart_scanner'
sys.path.insert(0, str(SMART))

from correlation_engine import CorrelationEngine, UnifiedFinding, UNIFIED_FINDING_FIELDS


def test_normalize_maps_arbitrary_scanner_dict_to_unified_schema():
    engine = CorrelationEngine(asset='asset-1')
    raw = {
        'type': 'SQL Injection', 'url': 'https://app.example.com/login?id=1',
        'severity': 'high', 'confidence': 'medium', 'detail': "' OR 1=1--",
    }
    unified = engine.normalize(raw, detection_source='zap')
    d = unified.to_dict()

    for field in UNIFIED_FINDING_FIELDS:
        assert field in d
    assert d['vulnerability'] == 'SQL Injection'
    assert d['cwe'] == 'CWE-89'  # heuristic map hoạt động
    assert d['severity'] == 'High'
    assert d['detection_source'] == 'zap'
    assert d['confidence'] == 'Suspected'  # 1 nguồn duy nhất


def test_correlate_merges_same_vuln_from_two_sources_and_raises_confidence():
    engine = CorrelationEngine(asset='asset-1')
    finding_zap = engine.normalize(
        {'type': 'SQL Injection', 'url': 'https://app.example.com/login?id=1', 'severity': 'High'},
        detection_source='zap',
    )
    finding_nuclei = engine.normalize(
        {'type': 'SQL Injection', 'url': 'https://app.example.com/login?id=1', 'severity': 'High', 'cve': 'CVE-2021-9999'},
        detection_source='nuclei',
    )

    merged = engine.correlate([finding_zap, finding_nuclei])

    # Cùng asset+endpoint+CWE → gộp thành 1 finding duy nhất, không hiện 2 lần
    assert len(merged) == 1
    result = merged[0].to_dict()
    assert result['sources_agreeing'] == 2
    assert 'zap' in result['detection_source'] and 'nuclei' in result['detection_source']
    # 2 nguồn đồng thuận → Confidence nâng từ Suspected lên Verified
    assert result['confidence'] == 'Verified'
    # Field còn thiếu ở finding đầu được bổ sung từ finding thứ hai khi merge
    assert result['cve'] == 'CVE-2021-9999'


def test_correlate_keeps_different_vulns_separate():
    engine = CorrelationEngine(asset='asset-1')
    xss = engine.normalize({'type': 'XSS', 'url': 'https://app.example.com/search?q=x'}, detection_source='zap')
    sqli = engine.normalize({'type': 'SQL Injection', 'url': 'https://app.example.com/search?q=x'}, detection_source='zap')

    merged = engine.correlate([xss, sqli])
    assert len(merged) == 2


def test_normalize_and_correlate_convenience_helper():
    engine = CorrelationEngine(asset='asset-1')
    findings_by_source = {
        'zap': [{'type': 'XSS', 'url': 'https://a.com/x', 'severity': 'Medium'}],
        'nuclei': [{'type': 'XSS', 'url': 'https://a.com/x', 'severity': 'Medium'}],
        'wapiti': [{'type': 'CSRF', 'url': 'https://a.com/form', 'severity': 'Low'}],
    }
    merged = engine.normalize_and_correlate(findings_by_source)
    # 2 XSS trùng gộp thành 1, CSRF riêng biệt → tổng 2 finding
    assert len(merged) == 2
    xss_result = next(f for f in merged if f.vulnerability == 'XSS')
    assert xss_result.dedup_key() is not None
    assert len(xss_result.detection_sources) == 2
