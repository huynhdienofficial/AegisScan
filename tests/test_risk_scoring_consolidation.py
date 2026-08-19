"""
Regression test: trước đây có 4 công thức risk-score khác nhau
(report_exporters.MultiFactorRiskEngine, fingerprint/attack_surface/risk_engine.RiskEngine,
fingerprint/attack_surface/exploit_manager.ExploitManager._assess_risk,
utils/risk_analyzer.RiskAnalyzer.assess_overall_risk) — cùng một tập finding
có thể cho ra 3-4 điểm/rating khác nhau tùy module nào chạy. Cả 4 nay đều
delegate sang MultiFactorRiskEngine.calculate_from_findings — test này khoá
lại tính nhất quán đó.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SMART = ROOT / 'smart_scanner'
sys.path.insert(0, str(SMART))

from report_exporters import MultiFactorRiskEngine
from fingerprint.attack_surface.risk_engine import RiskEngine
from utils.risk_analyzer import RiskAnalyzer


SAMPLE_FINDINGS_SEVERITY = [
    {'severity': 'critical', 'type': 'SQL Injection'},
    {'severity': 'high', 'type': 'XSS'},
    {'severity': 'medium', 'type': 'Missing Security Header'},
]


def test_multifactor_engine_and_legacy_risk_engine_agree():
    mf = MultiFactorRiskEngine.calculate_from_findings(SAMPLE_FINDINGS_SEVERITY)
    legacy = RiskEngine.calculate(SAMPLE_FINDINGS_SEVERITY)

    expected_safety_score = round(max(0.0, 100.0 - mf['risk_score']))
    assert legacy['score'] == expected_safety_score
    assert legacy['metrics']['critical'] == mf['counts']['critical']
    assert legacy['metrics']['high'] == mf['counts']['high']


def test_risk_analyzer_delegates_to_same_engine():
    """assess_overall_risk() phải cho cùng con số với engine chung khi đưa
    vào đúng field 'severity' (thay vì đường vòng confidence/indicators)."""
    passive_findings = SAMPLE_FINDINGS_SEVERITY
    result = RiskAnalyzer.assess_overall_risk(findings=[], passive_findings=passive_findings)

    mf = MultiFactorRiskEngine.calculate_from_findings(passive_findings)
    expected_score = round(max(0.0, 100.0 - mf['risk_score']))
    assert result['score'] == expected_score
    assert result['metrics']['critical'] == mf['counts']['critical']


def test_empty_findings_are_safe_across_all_entry_points():
    assert RiskEngine.calculate([])['score'] == 100
    assert RiskAnalyzer.assess_overall_risk(findings=[], passive_findings=[])['score'] == 100
    assert MultiFactorRiskEngine.calculate_from_findings([])['risk_score'] == 0.0


def test_more_critical_findings_never_scores_safer():
    """Sanity: càng nhiều finding Critical thì safety score càng thấp
    (không đảo chiều) — regression cho công thức hợp nhất."""
    one_critical = [{'severity': 'critical'}]
    three_critical = [{'severity': 'critical'}, {'severity': 'critical'}, {'severity': 'critical'}]

    score_one = RiskEngine.calculate(one_critical)['score']
    score_three = RiskEngine.calculate(three_critical)['score']
    assert score_three <= score_one
