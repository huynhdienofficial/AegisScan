"""
Threat Intelligence Engine — theo đặc tả v3.1 mục 9 (Feature List #40-45).

- CVE Database (offline cache, hỗ trợ import file JSON)
- CPE Matching Engine: map service/software → CPE
- EPSS: xác suất bị khai thác
- CISA KEV: CVE đã bị khai thác thực tế
- Offline Cache cho scan không cần Internet
- Cache Staleness Warning
"""
import json
import os
from datetime import datetime, timedelta


class ThreatIntelEngine:
    """Quản lý dữ liệu CVE/CPE/EPSS/KEV."""

    def __init__(self, cache_dir=None):
        self.cache_dir = cache_dir or os.path.join(os.path.dirname(__file__), '.threat_cache')
        self.cves = {}  # CVE-ID -> thông tin
        self.kev = set()  # CVE-ID -> đã bị khai thác
        self.epss = {}  # CVE-ID -> EPSS score
        self.cpe_cache = {}  # service/software -> CPE
        self.last_sync = None
        self.sync_interval_days = 7  # cache hết hạn sau 7 ngày

        self._load_cache()

    # ─── Cache Management ─────────────────────────────────────
    def _cache_path(self, name):
        return os.path.join(self.cache_dir, f"{name}.json")

    def _save_cache(self, name, data):
        os.makedirs(self.cache_dir, exist_ok=True)
        with open(self._cache_path(name), 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def _load_cache(self):
        try:
            if os.path.exists(self._cache_path('cves')):
                with open(self._cache_path('cves'), 'r', encoding='utf-8') as f:
                    self.cves = json.load(f)
            if os.path.exists(self._cache_path('kev')):
                with open(self._cache_path('kev'), 'r', encoding='utf-8') as f:
                    self.kev = set(json.load(f))
            if os.path.exists(self._cache_path('epss')):
                with open(self._cache_path('epss'), 'r', encoding='utf-8') as f:
                    self.epss = json.load(f)

            # Last sync
            sync_path = os.path.join(self.cache_dir, 'last_sync.txt')
            if os.path.exists(sync_path):
                with open(sync_path, 'r') as f:
                    self.last_sync = f.read().strip()
        except Exception:
            pass

    def import_nvd_json(self, filepath):
        """Import CVE data từ NVD JSON feed."""
        count = 0
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
            for item in data.get('vulnerabilities', data.get('CVE_Items', [])):
                try:
                    cve_id = item.get('cve', {}).get('id', '')
                    if not cve_id:
                        cve_id = item.get('cve', {}).get('CVE_data_meta', {}).get('ID', '')
                    if not cve_id:
                        continue

                    # Parse CVSS
                    descriptions = item.get('cve', {}).get('descriptions', [])
                    description = next((d.get('value', '') for d in descriptions
                                        if d.get('lang') == 'en'), '')
                    cvss = None
                    metrics = item.get('cve', {}).get('metrics', {})
                    if metrics:
                        cvss_data = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {})
                        cvss = cvss_data.get('baseScore')

                    self.cves[cve_id] = {
                        'description': description[:500],
                        'cvss': cvss,
                        'published': item.get('published', ''),
                        'modified': item.get('lastModified', ''),
                    }
                    count += 1
                except Exception:
                    continue

        self._save_cache('cves', self.cves)
        self._update_last_sync()
        return count

    def import_cisa_kev(self, filepath):
        """Import danh sách CISA KEV."""
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
            for item in data.get('vulnerabilities', []):
                cve_id = item.get('cveID', '')
                if cve_id:
                    self.kev.add(cve_id)
        self._save_cache('kev', list(self.kev))
        self._update_last_sync()
        return len(self.kev)

    def import_epss(self, filepath):
        """Import EPSS scores từ FIRST EPSS feed."""
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
            for item in data.get('data', []):
                cve_id = item.get('cve', '')
                score = item.get('epss')
                if cve_id and score is not None:
                    self.epss[cve_id] = float(score)
        self._save_cache('epss', self.epss)
        self._update_last_sync()
        return len(self.epss)

    def _update_last_sync(self):
        self.last_sync = datetime.now().isoformat()
        os.makedirs(self.cache_dir, exist_ok=True)
        with open(os.path.join(self.cache_dir, 'last_sync.txt'), 'w') as f:
            f.write(self.last_sync)

    # ─── CPE Matching ─────────────────────────────────────────
    @staticmethod
    def normalize_version(version):
        """Chuẩn hóa version string (loại bỏ ký tự thừa)."""
        if not version:
            return ''
        version = str(version).strip().lower()
        # Chỉ giữ chữ số, dấu chấm, gạch ngang
        chars = ''.join(c for c in version if c.isalnum() or c in '.-')
        return chars

    def map_to_cpe(self, software, version=None):
        """
        Map service/software fingerprint → CPE.
        VD: ('openssh', '8.9') → 'cpe:2.3:a:openbsd:openssh:8.9'
        """
        software_lower = software.lower().strip()
        version_norm = self.normalize_version(version)

        # CPE fingerprint mapping cho services phổ biến
        cpe_map = {
            'nginx': 'cpe:2.3:a:f5:nginx:{version}',
            'apache': 'cpe:2.3:a:apache:http_server:{version}',
            'openssh': 'cpe:2.3:a:openbsd:openssh:{version}',
            'mysql': 'cpe:2.3:a:oracle:mysql:{version}',
            'postgresql': 'cpe:2.3:a:postgresql:postgresql:{version}',
            'redis': 'cpe:2.3:a:redis:redis:{version}',
            'mongo': 'cpe:2.3:a:mongodb:mongodb:{version}',
            'nginx/1.18.0': 'cpe:2.3:a:f5:nginx:1.18.0',
        }

        # Tìm CPE trong map
        cpe = None
        if software_lower in cpe_map:
            cpe = cpe_map[software_lower].format(version=version_norm or '*')
        else:
            # Tìm kiếm gần đúng
            for key, pattern in cpe_map.items():
                if key in software_lower or software_lower in key:
                    cpe = pattern.format(version=version_norm or '*')
                    break

        if cpe:
            self.cpe_cache[software_lower] = cpe
        return cpe

    # ─── Queries ──────────────────────────────────────────────
    def lookup_cve(self, cve_id):
        """Tra cứu thông tin CVE."""
        cve_id = cve_id.upper()
        info = self.cves.get(cve_id, {})
        return {
            'cve_id': cve_id,
            'description': info.get('description', 'Không có dữ liệu local'),
            'cvss': info.get('cvss'),
            'published': info.get('published'),
            'in_kev': cve_id in self.kev,
            'epss': self.epss.get(cve_id),
        }

    def find_cves_for_version(self, software, version):
        """
        Tìm CVEs phù hợp với software/version qua CPE matching.
        Trả về danh sách CVE IDs có thể ảnh hưởng.
        """
        cpe = self.map_to_cpe(software, version)
        if not cpe:
            return []

        # Tìm CVE có configurations chứa CPE tương ứng
        # (Trong thực tế cần import NVD configurations — đây là stub cho local cache)
        matches = []
        for cve_id, info in self.cves.items():
            # Heuristic: software name + version trong description
            desc = info.get('description', '').lower()
            if software.lower() in desc and version and version.lower() in desc:
                matches.append(cve_id)
        return matches[:10]

    def is_cache_stale(self):
        """Kiểm tra cache đã hết hạn chưa (> 7 ngày)."""
        if not self.last_sync:
            return True
        try:
            last = datetime.fromisoformat(self.last_sync)
            return (datetime.now() - last) > timedelta(days=self.sync_interval_days)
        except Exception:
            return True

    def get_stats(self):
        """Thống kê dữ liệu threat intel."""
        return {
            'cve_count': len(self.cves),
            'kev_count': len(self.kev),
            'epss_count': len(self.epss),
            'cpe_count': len(self.cpe_cache),
            'last_sync': self.last_sync,
            'is_stale': self.is_cache_stale(),
            'sync_interval_days': self.sync_interval_days,
        }