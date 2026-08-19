"""
Asset Inventory — Danh mục tài sản theo đặc tả v3.1 mục 4.

Định nghĩa Asset, quản lý danh mục tài sản (thêm, import, tìm kiếm),
phát hiện Shadow IT (asset xuất hiện trong scan nhưng không có trong inventory).
"""
import csv
import json
from datetime import datetime
from urllib.parse import urlparse


class Asset:
    """Một Assets — server, web app, API đều là Asset."""

    ASSET_TYPES = ['server', 'web_app', 'api', 'container', 'database', 'other']
    ENVIRONMENTS = ['production', 'staging', 'development', 'test', 'lab']
    CRITICALITY = ['critical', 'high', 'medium', 'low']
    DATA_CLASSIFICATION = ['confidential', 'internal', 'public']
    NETWORK_ZONES = ['internet', 'dmz', 'internal', 'vpn']

    def __init__(self, name, asset_type='server', hostname=None, ip=None, url=None,
                 environment='development', business_criticality='medium',
                 data_classification='internal', owner='', department='',
                 internet_facing=False, network_zone='internal',
                 cloud_provider=None, region=None, tags=None, **kwargs):
        self.asset_id = None  # sinh tự động khi thêm vào inventory
        self.name = name
        self.asset_type = asset_type if asset_type in self.ASSET_TYPES else 'other'
        self.hostname = hostname
        self.ip = ip
        self.url = url
        self.environment = environment if environment in self.ENVIRONMENTS else 'development'
        self.business_criticality = business_criticality if business_criticality in self.CRITICALITY else 'medium'
        self.data_classification = data_classification if data_classification in self.DATA_CLASSIFICATION else 'internal'
        self.owner = owner
        self.department = department
        self.internet_facing = internet_facing
        self.network_zone = network_zone if network_zone in self.NETWORK_ZONES else 'internal'
        self.cloud_provider = cloud_provider
        self.region = region
        self.tags = tags or []
        self.created_at = datetime.now().isoformat()
        self.last_scan = None
        self.last_seen = None
        self.scan_coverage = []
        self.extra = kwargs

    @classmethod
    def from_url(cls, url, **kwargs):
        """Tạo Asset từ URL."""
        parsed = urlparse(url)
        hostname = parsed.hostname
        return cls(
            name=hostname or url,
            asset_type=kwargs.get('asset_type', 'web_app'),
            hostname=hostname,
            url=url,
            **{k: v for k, v in kwargs.items() if k != 'asset_type'}
        )

    def to_dict(self):
        return {
            'asset_id': self.asset_id,
            'name': self.name,
            'asset_type': self.asset_type,
            'hostname': self.hostname,
            'ip': self.ip,
            'url': self.url,
            'environment': self.environment,
            'business_criticality': self.business_criticality,
            'data_classification': self.data_classification,
            'owner': self.owner,
            'department': self.department,
            'internet_facing': self.internet_facing,
            'network_zone': self.network_zone,
            'cloud_provider': self.cloud_provider,
            'region': self.region,
            'tags': self.tags,
            'created_at': self.created_at,
            'last_scan': self.last_scan,
            'last_seen': self.last_seen,
            'scan_coverage': self.scan_coverage,
        }

    @property
    def display_name(self):
        return self.hostname or self.name or self.url or 'Unknown'


class AssetInventory:
    """Danh mục tài sản trung tâm — quản lý Asset, import, search, shadow IT."""

    def __init__(self):
        self.assets = {}  # asset_id -> Asset
        self.by_hostname = {}  # hostname -> asset_id
        self.by_ip = {}  # ip -> asset_id
        self.by_url = {}  # url -> asset_id
        self._next_id = 1
        self.shadow_it = []  # assets phát hiện ngoài inventory

    def add_asset(self, asset):
        """Thêm asset mới vào inventory."""
        asset.asset_id = f"AST-{self._next_id:04d}"
        self._next_id += 1
        self.assets[asset.asset_id] = asset

        if asset.hostname:
            self.by_hostname[asset.hostname.lower()] = asset.asset_id
        if asset.ip:
            self.by_ip[asset.ip] = asset.asset_id
        if asset.url:
            self.by_url[asset.url] = asset.asset_id

        return asset.asset_id

    def get_asset(self, asset_id):
        return self.assets.get(asset_id)

    def find_by_hostname(self, hostname):
        """Tìm asset theo hostname."""
        if not hostname:
            return None
        asset_id = self.by_hostname.get(hostname.lower())
        return self.assets.get(asset_id)

    def find_by_ip(self, ip):
        if not ip:
            return None
        asset_id = self.by_ip.get(ip)
        return self.assets.get(asset_id)

    def find_by_url(self, url):
        if not url:
            return None
        asset_id = self.by_url.get(url)
        return self.assets.get(asset_id)

    def find_or_create(self, hostname=None, ip=None, url=None, **kwargs):
        """Tìm asset đã tồn tại hoặc tạo mới."""
        asset = None
        if hostname:
            asset = self.find_by_hostname(hostname)
        if not asset and ip:
            asset = self.find_by_ip(ip)
        if not asset and url:
            asset = self.find_by_url(url)

        if not asset:
            asset = Asset(
                name=hostname or ip or url or 'Unknown',
                hostname=hostname,
                ip=ip,
                url=url,
                **kwargs
            )
            self.add_asset(asset)
        return asset

    def record_scan(self, asset, scan_id, profile):
        """Ghi nhận lần scan gần nhất cho asset."""
        asset.last_scan = scan_id
        asset.last_seen = datetime.now().isoformat()
        if profile not in asset.scan_coverage:
            asset.scan_coverage.append(profile)

    def detect_shadow_it(self, discovered_hosts):
        """
        Phát hiện Shadow IT — host xuất hiện trong scan nhưng không có trong inventory.
        Theo đặc tả v3.1 mục 4.2.
        """
        shadow = []
        for host in discovered_hosts:
            asset = self.find_by_hostname(host) or self.find_by_ip(host)
            if not asset:
                shadow.append({
                    'hostname': host,
                    'detected_at': datetime.now().isoformat(),
                    'status': 'unclassified'
                })
        self.shadow_it = shadow
        return shadow

    def import_csv(self, filepath):
        """Import asset từ CSV. Cột bắt buộc: name (hoặc hostname/ip/url)."""
        count = 0
        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                asset = Asset(
                    name=row.get('name', ''),
                    asset_type=row.get('asset_type', 'server'),
                    hostname=row.get('hostname'),
                    ip=row.get('ip'),
                    url=row.get('url'),
                    environment=row.get('environment', 'development'),
                    business_criticality=row.get('business_criticality', 'medium'),
                    data_classification=row.get('data_classification', 'internal'),
                    owner=row.get('owner', ''),
                    department=row.get('department', ''),
                    internet_facing=row.get('internet_facing', 'false').lower() in ('true', 'yes', '1'),
                    network_zone=row.get('network_zone', 'internal'),
                    cloud_provider=row.get('cloud_provider'),
                    region=row.get('region'),
                )
                self.add_asset(asset)
                count += 1
        return count

    def export_json(self, filepath):
        """Export inventory ra JSON."""
        data = {
            'total': len(self.assets),
            'assets': [a.to_dict() for a in self.assets.values()],
            'shadow_it': self.shadow_it,
        }
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return filepath

    def get_stats(self):
        """Thống kê inventory."""
        by_type = {}
        by_env = {}
        by_criticality = {}
        internet_facing = 0

        for asset in self.assets.values():
            by_type[asset.asset_type] = by_type.get(asset.asset_type, 0) + 1
            by_env[asset.environment] = by_env.get(asset.environment, 0) + 1
            by_criticality[asset.business_criticality] = by_criticality.get(asset.business_criticality, 0) + 1
            if asset.internet_facing:
                internet_facing += 1

        return {
            'total_assets': len(self.assets),
            'by_type': by_type,
            'by_environment': by_env,
            'by_criticality': by_criticality,
            'internet_facing': internet_facing,
            'shadow_it_count': len(self.shadow_it),
        }