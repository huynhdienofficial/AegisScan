"""
Cloud Security Assessment — theo đặc tả v3.1 §20.2 (Feature List #84).

Quét cấu hình cloud: AWS S3/IAM/EC2, Azure Blob/AD, GCP Storage/IAM.
Mỗi check có ID chuẩn {PROVIDER}-{SERVICE}-{SỐ} để map vào Finding Management.
"""
import json
import re


class CloudScanner:
    """Phân tích cấu hình cloud từ JSON config files."""

    def __init__(self, cloud_provider=None, config_json=None, config_file=None):
        self.cloud_provider = cloud_provider
        self.config_json = config_json or {}
        self.config_file = config_file
        if config_file:
            self._load_file()

    def _load_file(self):
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                self.config_json = json.load(f)
        except Exception:
            self.config_json = {}

    # ─── AWS Checks ───────────────────────────────────────────
    def check_aws(self, config):
        """Kiểm tra AWS configuration."""
        findings = []
        config = config.get('aws', config) if 'aws' in config else config
        iam = config.get('iam', {})
        s3 = config.get('s3', {})
        ec2 = config.get('ec2', {})

        # AWS-IAM-001: Root MFA disabled
        if not iam.get('root_mfa_enabled', False):
            findings.append({
                'check_id': 'AWS-IAM-001',
                'type': 'Root User MFA Disabled',
                'severity': 'Critical',
                'detail': 'AWS root account không bật MFA — nguy cơ chiếm toàn bộ account',
                'confidence': 'High',
            })

        # AWS-IAM-002: IAM user với admin full privileges
        for user in iam.get('users', []):
            if user.get('is_admin', False) and user.get('mfa_enabled', True) is False:
                findings.append({
                    'check_id': 'AWS-IAM-002',
                    'type': 'Admin User Missing MFA',
                    'severity': 'High',
                    'detail': f"IAM user '{user.get('name', 'unknown')}' có quyền admin nhưng không bật MFA",
                    'confidence': 'High',
                })

        # AWS-S3-001: Public S3 bucket
        for bucket in s3.get('buckets', []):
            if bucket.get('public', False):
                findings.append({
                    'check_id': 'AWS-S3-001',
                    'type': 'Public S3 Bucket',
                    'severity': 'High',
                    'detail': f"S3 bucket '{bucket.get('name', 'unknown')}' public — dữ liệu có thể bị lộ",
                    'confidence': 'High',
                })

        # AWS-S3-002: S3 không encryption
        for bucket in s3.get('buckets', []):
            if bucket.get('encryption_enabled', True) is False:
                findings.append({
                    'check_id': 'AWS-S3-002',
                    'type': 'S3 Bucket Not Encrypted',
                    'severity': 'Medium',
                    'detail': f"S3 bucket '{bucket.get('name', 'unknown')}' không bật encryption",
                    'confidence': 'High',
                })

        # AWS-EC2-001: Security group mở port 22/3389 ra Internet
        for sg in ec2.get('security_groups', []):
            for rule in sg.get('rules', []):
                if rule.get('cidr', '') in ('0.0.0.0/0', '::/0'):
                    if rule.get('port') in (22, 3389, 3306, 6379):
                        findings.append({
                            'check_id': 'AWS-EC2-001',
                            'type': 'Open Port To Internet',
                            'severity': 'High',
                            'detail': (
                                f"Security group '{sg.get('name', 'unknown')}' "
                                f"mở port {rule.get('port')} ra 0.0.0.0/0"
                            ),
                            'confidence': 'High',
                        })

        # AWS-RDS-001: RDS không encryption
        for db in config.get('rds', {}).get('instances', []):
            if db.get('storage_encrypted', True) is False:
                findings.append({
                    'check_id': 'AWS-RDS-001',
                    'type': 'RDS Not Encrypted',
                    'severity': 'High',
                    'detail': f"RDS instance '{db.get('id', 'unknown')}' không mã hóa storage",
                    'confidence': 'High',
                })
        return findings

    # ─── Azure Checks ─────────────────────────────────────────
    def check_azure(self, config):
        """Kiểm tra Azure configuration."""
        findings = []
        config = config.get('azure', config) if 'azure' in config else config
        ad = config.get('ad', {})
        storage = config.get('storage', {})
        sql = config.get('sql', {})

        # AZ-AD-001: Azure AD không bật MFA
        if not ad.get('mfa_enabled', False):
            findings.append({
                'check_id': 'AZ-AD-001',
                'type': 'Azure AD MFA Disabled',
                'severity': 'High',
                'detail': 'Azure AD không bật MFA — tăng nguy cơ credential compromise',
                'confidence': 'High',
            })

        # AZ-STORAGE-001: Blob Storage public
        for account in storage.get('accounts', []):
            if account.get('public_access', False):
                findings.append({
                    'check_id': 'AZ-STORAGE-001',
                    'type': 'Azure Blob Public Access',
                    'severity': 'High',
                    'detail': f"Storage '{account.get('name', 'unknown')}' cho phép public access",
                    'confidence': 'High',
                })

        # AZ-SQL-001: SQL Database không encryption
        for db in sql.get('databases', []):
            if db.get('encryption_enabled', True) is False:
                findings.append({
                    'check_id': 'AZ-SQL-001',
                    'type': 'Azure SQL Not Encrypted',
                    'severity': 'High',
                    'detail': f"SQL Database '{db.get('name', 'unknown')}' không bật encryption",
                    'confidence': 'High',
                })
        return findings

    # ─── GCP Checks ───────────────────────────────────────────
    def check_gcp(self, config):
        """Kiểm tra GCP configuration."""
        findings = []
        config = config.get('gcp', config) if 'gcp' in config else config
        iam = config.get('iam', {})
        storage = config.get('storage', {})

        # GCP-IAM-001: Service account key không rotate
        for sa in iam.get('service_accounts', []):
            for key in sa.get('keys', []):
                if key.get('created', '') and key.get('created') < '2020-01-01':
                    findings.append({
                        'check_id': 'GCP-IAM-001',
                        'type': 'Service Account Key Not Rotated',
                        'severity': 'Medium',
                        'detail': f"Service account '{sa.get('email', 'unknown')}' có key cũ chưa rotate",
                        'confidence': 'Medium',
                    })

        # GCP-STORE-001: GCS bucket public
        for bucket in storage.get('buckets', []):
            if bucket.get('public', False):
                findings.append({
                    'check_id': 'GCP-STORE-001',
                    'type': 'Public GCS Bucket',
                    'severity': 'High',
                    'detail': f"GCS bucket '{bucket.get('name', 'unknown')}' public",
                    'confidence': 'High',
                })
        return findings

    # ─── Scan ─────────────────────────────────────────────────
    def scan(self):
        """Chạy toàn bộ cloud scan."""
        if not self.config_json:
            return {'vulnerabilities': [], 'note': 'Không có cloud config để phân tích'}

        provider = self.cloud_provider or self._detect_provider(self.config_json)
        all_findings = []

        if provider == 'aws':
            all_findings = self.check_aws(self.config_json)
        elif provider == 'azure':
            all_findings = self.check_azure(self.config_json)
        elif provider == 'gcp':
            all_findings = self.check_gcp(self.config_json)
        else:
            # Tự detect và check tất cả
            all_findings.extend(self.check_aws(self.config_json))
            all_findings.extend(self.check_azure(self.config_json))
            all_findings.extend(self.check_gcp(self.config_json))

        return {'vulnerabilities': all_findings}

    @staticmethod
    def _detect_provider(config):
        """Phát hiện provider từ cấu trúc JSON."""
        if 'aws' in config or 'iam' in config or 's3' in config:
            return 'aws'
        if 'azure' in config or 'ad' in config or 'storage' in config:
            return 'azure'
        if 'gcp' in config or 'service_accounts' in config:
            return 'gcp'
        return None