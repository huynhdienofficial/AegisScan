"""
SBOM Generation & Dashboard Analytics — theo đặc tả v3.1.

- SBOM Generation (#31): sinh CycloneDX/SPDX cho runtime Python/Node
- Supply Chain CVE Matching (#32): đối chiếu SBOM với CVE database
- Security Trend Dashboard (#60) + Top Risk Asset/CVE (#61) + SLA (#62)
- Zero-day ML Detection (#83): anomaly detection cơ bản
"""
import hashlib
import json
import os
import re
from datetime import datetime, timedelta
from statistics import mean, median


class SBOMGenerator:
    """Sinh SBOM (CycloneDX/SPDX) cho runtime Python/Node."""

    def __init__(self):
        self.components = []

    def scan_python(self, requirements_file='requirements.txt', path=None):
        """Parse Python dependencies từ requirements.txt hoặc installed packages."""
        components = []

        # Từ requirements.txt
        if path and os.path.exists(path):
            req_path = os.path.join(path, requirements_file)
            if os.path.exists(req_path):
                with open(req_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        match = re.match(r'([A-Za-z0-9_\-]+)\s*(?:==|>=|<=|~=|!=)?\s*([\d\.]+)?', line)
                        if match:
                            name = match.group(1)
                            version = match.group(2) or 'unknown'
                            components.append({
                                'type': 'library',
                                'name': name,
                                'version': version,
                                'purl': f'pkg:pypi/{name}@{version}',
                            })

        # Từ pip list (nếu chạy trong env có pip)
        if not components:
            try:
                import subprocess
                result = subprocess.run(
                    [os.sys.executable, '-m', 'pip', 'list', '--format=json'],
                    capture_output=True, text=True, timeout=15,
                )
                if result.returncode == 0:
                    for pkg in json.loads(result.stdout):
                        name = pkg.get('name', '')
                        version = pkg.get('version', '')
                        if name:
                            components.append({
                                'type': 'library',
                                'name': name,
                                'version': version,
                                'purl': f'pkg:pypi/{name}@{version}',
                            })
            except Exception:
                pass

        self.components = components
        return components

    def scan_node(self, package_file='package.json', path=None):
        """Parse Node.js dependencies."""
        components = []
        if path and os.path.exists(path):
            pkg_path = os.path.join(path, package_file)
            if os.path.exists(pkg_path):
                with open(pkg_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                deps = data.get('dependencies', {})
                for name, version in deps.items():
                    components.append({
                        'type': 'library',
                        'name': name,
                        'version': version.lstrip('^~'),
                        'purl': f'pkg:npm/{name}@{version.lstrip("^~")}',
                    })
        self.components = components
        return components

    def generate_cyclonedx(self):
        """Tạo SBOM CycloneDX format."""
        return {
            'bomFormat': 'CycloneDX',
            'specVersion': '1.4',
            'serialNumber': f'urn:uuid:{hashlib.md5(str(datetime.now()).encode()).hexdigest()[:36]}',
            'version': 1,
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'tools': [{'vendor': 'AegisScan', 'name': 'SBOMGenerator', 'version': '3.1.0'}],
            },
            'components': self.components,
        }

    def generate_spdx(self):
        """Tạo SBOM SPDX format."""
        return {
            'spdxVersion': 'SPDX-2.3',
            'dataLicense': 'CC0-1.0',
            'SPDXID': 'SPDXRef-DOCUMENT',
            'name': 'AegisScan SBOM',
            'documentNamespace': f'https://example.com/sbom/{hashlib.md5(str(datetime.now()).encode()).hexdigest()[:16]}',
            'creationInfo': {
                'created': datetime.now().isoformat(),
                'creators': ['Tool: AegisScan 3.1.0'],
            },
            'packages': [
                {
                    'name': c['name'],
                    'versionInfo': c['version'],
                    'SPDXID': f"SPDXRef-Package-{i+1}",
                    'externalRefs': [{'referenceCategory': 'PACKAGE-MANAGER',
                                      'referenceType': 'purl',
                                      'referenceLocator': c['purl']}],
                }
                for i, c in enumerate(self.components)
            ],
        }

    def match_cves(self, threat_intel=None):
        """Đối chiếu SBOM components với CVE database."""
        if not threat_intel:
            return []

        matches = []
        for comp in self.components:
            cves = threat_intel.find_cves_for_version(comp['name'], comp['version'])
            for cve_id in cves:
                info = threat_intel.lookup_cve(cve_id)
                matches.append({
                    'component': comp['name'],
                    'version': comp['version'],
                    'cve_id': cve_id,
                    'cvss': info.get('cvss'),
                    'in_kev': info.get('in_kev', False),
                    'epss': info.get('epss'),
                })
        return matches


class SecurityDashboard:
    """Trend + Top Risk + SLA Remediation Tracking."""

    def __init__(self):
        self.scan_history = []  # [{timestamp, severity_counts, asset_id}]

    def record_scan(self, findings, asset_id='', scan_id=''):
        """Ghi snapshot kết quả scan."""
        by_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for f in findings:
            sev = f.get('severity', '').lower()
            if sev in by_severity:
                by_severity[sev] += 1

        self.scan_history.append({
            'scan_id': scan_id,
            'asset_id': asset_id,
            'timestamp': datetime.now().isoformat(),
            'severity_counts': by_severity,
            'total': len(findings),
        })

    def trend_by_severity(self):
        """Biểu đồ severity theo thời gian."""
        return {
            'labels': [h['timestamp'][:16] for h in self.scan_history],
            'series': {
                'critical': [h['severity_counts']['critical'] for h in self.scan_history],
                'high': [h['severity_counts']['high'] for h in self.scan_history],
                'medium': [h['severity_counts']['medium'] for h in self.scan_history],
                'low': [h['severity_counts']['low'] for h in self.scan_history],
            },
        }

    def top_risk_assets(self):
        """Top asset rủi ro cao nhất."""
        by_asset = {}
        for h in self.scan_history:
            aid = h.get('asset_id', 'unknown')
            if aid not in by_asset:
                by_asset[aid] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'scans': 0}
            for sev in by_asset[aid]:
                if sev != 'scans':
                    by_asset[aid][sev] += h['severity_counts'].get(sev, 0)
            by_asset[aid]['scans'] += 1

        # Tính risk score đơn giản
        ranked = []
        for aid, counts in by_asset.items():
            score = counts['critical'] * 25 + counts['high'] * 10 + counts['medium'] * 5 + counts['low']
            ranked.append({'asset_id': aid, 'risk_score': score, **counts})
        ranked.sort(key=lambda x: x['risk_score'], reverse=True)
        return ranked

    def sla_compliance(self):
        """Tính tỷ lệ tuân thủ SLA."""
        return {
            'critical_sla_days': 3,
            'high_sla_days': 7,
            'medium_sla_days': 30,
            'note': 'SLA: Critical fix trong 3 ngày, High 7 ngày, Medium 30 ngày',
        }


class ZeroDayML:
    """Zero-day Detection — anomaly detection cơ bản không cần sklearn."""

    def __init__(self):
        self.baseline = {}  # endpoint -> danh sách metrics
        self.baseline_size = 20

    def learn_baseline(self, endpoint, response_time, error_rate=0.0, memory_delta=0.0):
        """Học baseline bình thường của endpoint."""
        if endpoint not in self.baseline:
            self.baseline[endpoint] = []
        self.baseline[endpoint].append({
            'response_time': response_time,
            'error_rate': error_rate,
            'memory_delta': memory_delta,
        })
        # Giới hạn kích thước baseline
        if len(self.baseline[endpoint]) > self.baseline_size:
            self.baseline[endpoint] = self.baseline[endpoint][-self.baseline_size:]

    def detect_anomaly(self, endpoint, response_time, error_rate=0.0, memory_delta=0.0):
        """Phát hiện bất thường so với baseline."""
        if endpoint not in self.baseline or len(self.baseline[endpoint]) < 5:
            return {'is_anomaly': False, 'reason': 'Cần thêm dữ liệu baseline'}

        samples = self.baseline[endpoint]
        times = [s['response_time'] for s in samples]
        errors = [s['error_rate'] for s in samples]

        median_time = median(times)
        median_error = median(errors)

        # Threshold: response time > 3x median, error > 50%
        anomalies = []
        if response_time > median_time * 3:
            anomalies.append(f'Response time {response_time:.2f}s > 3x baseline ({median_time:.2f}s)')
        if error_rate > max(median_error * 3, 0.5):
            anomalies.append(f'Error rate {error_rate:.2f} > baseline ({median_error:.2f})')
        if memory_delta > 100:
            anomalies.append(f'Memory delta cao: {memory_delta}MB')

        return {
            'is_anomaly': len(anomalies) > 0,
            'anomalies': anomalies,
            'reason': '; '.join(anomalies) if anomalies else 'Bình thường',
            'severity': 'Medium' if anomalies else 'Info',
        }