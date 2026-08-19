"""
Report Exporters — theo đặc tả v3.1 mục 8.2.

- SARIF: chuẩn integration CI/CD (mục Feature List #59)
- CSV: danh sách findings tổng hợp
- Multi-factor Risk Engine: CVSS + Exposure + Asset Criticality (mục 10)
"""
import csv
import json
from datetime import datetime


class SARIFExporter:
    """Xuất findings sang SARIF 2.1.0 format cho CI/CD."""

    @staticmethod
    def export(findings, tool_name='AegisScan', tool_version='3.1.0'):
        """Tạo SARIF report từ danh sách findings."""
        rules = {}
        results = []

        for i, f in enumerate(findings):
            # Đọc cả field của Unified Finding Data Model (§25.2: vulnerability/
            # location/evidence/owasp_mapping) LẪN field "thô" kiểu cũ mà một số
            # scanner trong repo vẫn dùng (type/url/detail/owasp) — để exporter
            # dùng được cho cả hai nguồn dữ liệu.
            vuln_name = f.get('vulnerability') or f.get('type') or f.get('title')
            rule_id = f.get('rule_id') or f.get('cwe') or vuln_name or f'RULE-{i}'
            location = f.get('location') or f.get('url') or f.get('endpoint') or 'unknown'
            evidence_text = f.get('evidence') or f.get('detail') or vuln_name or ''
            owasp = f.get('owasp_mapping') or f.get('owasp')

            if rule_id not in rules:
                rules[rule_id] = {
                    'id': rule_id,
                    'name': f.get('title', vuln_name or rule_id),
                    'shortDescription': {'text': f.get('description', evidence_text)[:500]},
                    'defaultConfiguration': {'level': SARIFExporter._sarif_level(f.get('severity', 'Low'))},
                    'helpUri': f"https://example.com/rules/{rule_id}",
                }

            results.append({
                'ruleId': rule_id,
                'level': SARIFExporter._sarif_level(f.get('severity', 'Low')),
                'message': {'text': (evidence_text or vuln_name or '')[:2000]},
                'locations': [{
                    'physicalLocation': {
                        'artifactLocation': {'uri': location},
                    }
                }],
                'properties': {
                    'confidence': f.get('confidence', 'Low'),
                    'parameter': f.get('parameter', ''),
                    'method': f.get('method', 'GET'),
                    'cvss': f.get('cvss', None),
                    'cwe': f.get('cwe', None),
                    'owasp': owasp,
                    'scan_id': f.get('scan_id', ''),
                },
            })

        log = {
            '$schema': 'https://json.schemastore.org/sarif-2.1.0.json',
            'version': '2.1.0',
            'runs': [{
                'tool': {
                    'driver': {
                        'name': tool_name,
                        'version': tool_version,
                        'informationUri': 'https://example.com/scanner',
                        'rules': list(rules.values()),
                    }
                },
                'results': results,
            }]
        }
        return log

    @staticmethod
    def _sarif_level(severity):
        """Map severity sang SARIF level."""
        severity_lower = severity.lower()
        if severity_lower in ('critical', 'high'):
            return 'error'
        if severity_lower == 'medium':
            return 'warning'
        return 'note'

    @staticmethod
    def save(findings, filepath):
        """Lưu SARIF ra file."""
        log = SARIFExporter.export(findings)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(log, f, ensure_ascii=False, indent=2)
        return filepath


class CSVExporter:
    """Xuất findings sang CSV."""

    @staticmethod
    def export(findings, filepath):
        """Lưu findings ra CSV."""
        columns = [
            'severity', 'type', 'title', 'detail', 'url', 'endpoint',
            'parameter', 'payload', 'method', 'confidence', 'cwe', 'owasp',
            'cvss', 'status', 'detected_at',
        ]
        with open(filepath, 'w', encoding='utf-8', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=columns, extrasaction='ignore')
            writer.writeheader()
            for finding in findings:
                vuln_name = finding.get('vulnerability') or finding.get('type', '')
                location = finding.get('location') or finding.get('url', '')
                row = {
                    'severity': finding.get('severity', ''),
                    'type': vuln_name,
                    'title': finding.get('title', vuln_name),
                    'detail': finding.get('evidence') or finding.get('detail', finding.get('description', '')),
                    'url': location,
                    'endpoint': finding.get('endpoint', location),
                    'parameter': finding.get('parameter', ''),
                    'payload': finding.get('payload', ''),
                    'method': finding.get('method', 'GET'),
                    'confidence': finding.get('confidence', ''),
                    'cwe': finding.get('cwe', ''),
                    'owasp': finding.get('owasp_mapping') or finding.get('owasp', ''),
                    'cvss': finding.get('cvss', ''),
                    'status': finding.get('false_positive_status') or finding.get('status', 'suspected'),
                    'detected_at': (finding.get('last_detected') or finding.get('detected_at')
                                    or finding.get('created_at', datetime.now().isoformat())),
                }
                writer.writerow(row)
        return filepath


class MultiFactorRiskEngine:
    """
    Risk Engine đa yếu tố — theo đặc tả v3.1 mục 10.

    Risk Score = f(CVSS, EPSS, KEV) × Exposure Multiplier × Asset Criticality Multiplier
    """

    EXPOSURE_MULTIPLIERS = {
        'internet': 1.5,
        'dmz': 1.2,
        'internal': 1.0,
        'vpn': 0.8,
        'localhost': 0.5,
    }

    CRITICALITY_MULTIPLIERS = {
        'critical': 1.5,
        'high': 1.3,
        'medium': 1.0,
        'low': 0.7,
    }

    ENVIRONMENT_MULTIPLIERS = {
        'production': 1.3,
        'staging': 1.0,
        'development': 0.8,
        'test': 0.7,
        'lab': 0.6,
    }

    @staticmethod
    def calculate(cvss_score=None, severity=None, epss=None, in_kev=False,
                  network_zone='internal', business_criticality='medium',
                  environment='development', internet_facing=False):
        """
        Tính Risk Score đa yếu tố.

        - cvss_score: CVSS base (0-10) hoặc None
        - severity: severity label nếu không có CVSS
        - epss: EPSS score (0-1)
        - in_kev: có nằm trong CISA KEV không
        """
        # 1. Technical — CVSS hoặc severity
        if cvss_score is not None:
            technical = float(cvss_score) / 10.0  # 0-1
        else:
            severity_map = {'critical': 0.95, 'high': 0.75, 'medium': 0.5, 'low': 0.25, 'info': 0.1}
            technical = severity_map.get((severity or 'low').lower(), 0.3)

        # 2. Threat — EPSS + KEV boost
        threat = 0.1
        if epss is not None:
            threat = float(epss)  # 0-1
        if in_kev:
            threat = max(threat, 0.9)  # KEV = gần như chắc chắn bị khai thác

        # 3. Exposure multiplier
        if internet_facing and network_zone == 'internal':
            actual_zone = 'internet'
        else:
            actual_zone = network_zone
        exposure_mult = MultiFactorRiskEngine.EXPOSURE_MULTIPLIERS.get(actual_zone, 1.0)

        # 4. Asset criticality multiplier
        criticality_mult = MultiFactorRiskEngine.CRITICALITY_MULTIPLIERS.get(
            (business_criticality or 'medium').lower(), 1.0)

        # 5. Environment multiplier
        env_mult = MultiFactorRiskEngine.ENVIRONMENT_MULTIPLIERS.get(
            (environment or 'development').lower(), 1.0)

        # 6. Tổng hợp
        base = (technical * 0.6) + (threat * 0.4)  # Technical + Threat
        risk_score = base * exposure_mult * criticality_mult * env_mult
        risk_score = min(1.0, risk_score)
        risk_percent = round(risk_score * 100, 1)

        # Rating
        if risk_percent >= 80:
            rating = 'Critical'
        elif risk_percent >= 60:
            rating = 'High'
        elif risk_percent >= 40:
            rating = 'Medium'
        elif risk_percent >= 20:
            rating = 'Low'
        else:
            rating = 'Info'

        return {
            'risk_score': risk_percent,
            'rating': rating,
            'breakdown': {
                'technical': round(technical * 100, 1),
                'threat': round(threat * 100, 1),
                'exposure_multiplier': exposure_mult,
                'criticality_multiplier': criticality_mult,
                'environment_multiplier': env_mult,
                'cvss': cvss_score,
                'epss': epss,
                'in_kev': in_kev,
                'network_zone': actual_zone,
            }
        }

    # Confidence label (High/Medium/Low) → severity, cho các finding không
    # tự gắn 'severity' mà chỉ có 'confidence' (một vài scanner cũ trong repo
    # dùng quy ước này).
    _CONFIDENCE_TO_SEVERITY = {'high': 'critical', 'medium': 'high', 'low': 'medium'}

    @classmethod
    def calculate_from_findings(cls, findings, network_zone='internal',
                                 business_criticality='medium', environment='development',
                                 internet_facing=False):
        """Tổng hợp Risk Score từ MỘT DANH SÁCH findings.

        Đây là nguồn tính toán DUY NHẤT cho "risk score tổng hợp từ danh sách
        finding" — trước đây có 4 công thức khác nhau nằm rải rác
        (report_exporters.MultiFactorRiskEngine chỉ tính 1 finding đơn lẻ,
        fingerprint/attack_surface/risk_engine.RiskEngine, fingerprint/attack_surface/
        exploit_manager.ExploitManager._assess_risk, utils/risk_analyzer.RiskAnalyzer
        đều tự viết công thức đếm severity riêng — không đồng nhất, cùng một
        tập finding cho ra 3-4 điểm khác nhau tùy module nào chạy). Các module
        đó nay đều delegate sang đây, chỉ còn khác nhau ở shape dữ liệu trả về
        để tương thích ngược với caller cũ.

        Nguyên tắc: risk của asset = risk của finding NGHIÊM TRỌNG NHẤT (không
        pha loãng bằng cách cộng dồn/trừ điểm tuyến tính theo số lượng), cộng
        thêm một khoản phạt nhẹ khi có nhiều finding Critical/High cùng lúc.
        """
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        if not findings:
            return {'risk_score': 0.0, 'rating': 'Info', 'counts': counts, 'worst_single_finding': 0.0}

        per_finding_scores = []
        for f in findings:
            severity = str(f.get('severity', '') or '').lower()
            if not severity:
                confidence = str(f.get('confidence', 'low') or 'low').lower()
                severity = cls._CONFIDENCE_TO_SEVERITY.get(confidence, 'low')
            if severity not in counts:
                severity = 'low'
            counts[severity] += 1

            result = cls.calculate(
                cvss_score=f.get('cvss'), severity=severity, epss=f.get('epss'),
                in_kev=bool(f.get('in_kev', False)), network_zone=network_zone,
                business_criticality=business_criticality, environment=environment,
                internet_facing=internet_facing,
            )
            per_finding_scores.append(result['risk_score'])

        worst = max(per_finding_scores)
        volume_penalty = min(15.0, counts['critical'] * 3 + counts['high'] * 1.5)
        risk_percent = round(min(100.0, worst + volume_penalty), 1)

        if risk_percent >= 80:
            rating = 'Critical'
        elif risk_percent >= 60:
            rating = 'High'
        elif risk_percent >= 40:
            rating = 'Medium'
        elif risk_percent >= 20:
            rating = 'Low'
        else:
            rating = 'Info'

        return {
            'risk_score': risk_percent,
            'rating': rating,
            'counts': counts,
            'worst_single_finding': worst,
            'volume_penalty': volume_penalty,
        }


class ReportBuilder:
    """Báo cáo chuẩn 11 mục theo đặc tả v3.1 mục 13.1."""

    @staticmethod
    def build_standard_report(scan_info, findings, deliverables=None):
        """Xây report chuẩn 11 mục."""
        deliverables = deliverables or {}
        total_findings = len(findings)
        critical = sum(1 for f in findings if f.get('severity', '').lower() == 'critical')
        high = sum(1 for f in findings if f.get('severity', '').lower() == 'high')
        medium = sum(1 for f in findings if f.get('severity', '').lower() == 'medium')
        low = sum(1 for f in findings if f.get('severity', '').lower() == 'low')

        return {
            '1_executive_summary': {
                'overview': (
                    f"Quét {scan_info.get('target', 'www.example.com')} phát hiện "
                    f"{total_findings} findings ({critical} critical, {high} high)."
                ),
                'risk_rating': deliverables.get('risk_rating', 'Unknown'),
            },
            '2_target_scope': {
                'target': scan_info.get('target'),
                'scan_id': scan_info.get('scan_id'),
                'profile': scan_info.get('profile', 'safe-active'),
                'scanned_at': scan_info.get('scanned_at'),
            },
            '3_scan_configuration': scan_info.get('config', {}),
            '4_asset_technology_inventory': {
                'assets': deliverables.get('assets', []),
                'technologies': deliverables.get('technologies', []),
            },
            '5_attack_surface_inventory': {
                'urls': deliverables.get('urls', []),
                'parameters': deliverables.get('parameters', []),
                'forms': deliverables.get('forms', []),
                'apis': deliverables.get('apis', []),
                'ports': deliverables.get('ports', []),
            },
            '6_findings_by_severity': {
                'total': total_findings,
                'critical': critical,
                'high': high,
                'medium': medium,
                'low': low,
                'info': sum(1 for f in findings if f.get('severity', '').lower() == 'info'),
                'findings': findings,
            },
            '7_detailed_evidence': [
                {
                    'id': f.get('id', f.get('type', f'FIND-{i}')),
                    'evidence': f.get('evidence', f.get('detail', '')),
                }
                for i, f in enumerate(findings[:20])
            ],
            '8_delta_previous_scan': deliverables.get('delta', None),
            '9_remediation_plan': deliverables.get('remediation', []),
            '10_scan_limitations': deliverables.get('limitations', [
                'Scan thực hiện trong môi trường local/lab cho phép.',
                'Không khai thác destructive payload.',
                'Kết quả có thể thiếu nếu ứng dụng yêu cầu authentication phức tạp.',
            ]),
            '11_appendix': {
                'rules_version': '3.1.0',
                'scanner_version': deliverables.get('scanner_version', '3.1.0'),
                'generated_at': datetime.now().isoformat(),
            },
        }