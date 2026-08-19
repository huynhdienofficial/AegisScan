"""
Infrastructure Scan Engine — theo đặc tả v3.1 mục 7.

- Port/Service Scan: phát hiện port mở, fingerprint service/version
- TLS Scan: kiểm tra certificate, protocol version
- Network Exposure Awareness: bind address, network zone
"""
import asyncio
import socket
import ssl
from datetime import datetime

COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 111: 'RPCBind', 135: 'MSRPC',
    139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
    6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
    9200: 'Elasticsearch', 27017: 'MongoDB',
}


class PortScanner:
    """Quét port mở trên target."""

    WELL_KNOWN = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP',
        110: 'POP3', 135: 'MSRPC', 139: 'NetBIOS-SSN', 143: 'IMAP', 443: 'HTTPS',
        445: 'Microsoft-DS', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
        5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt',
        9200: 'Elasticsearch', 27017: 'MongoDB', 2375: 'Docker-API',
        2376: 'Docker-API-TLS', 6443: 'Kubernetes-API', 10250: 'Kubelet',
    }

    def __init__(self, host, ports=None, timeout=3, concurrency=50,
                 internet_facing=False, network_zone='internal'):
        self.host = host
        self.ports = ports or list(self.WELL_KNOWN.keys())
        self.timeout = timeout
        self.concurrency = concurrency
        self.internet_facing = internet_facing
        self.network_zone = network_zone

    async def scan_port(self, port):
        """Kiểm tra một port có mở không."""
        try:
            # Dùng socket async
            loop = asyncio.get_event_loop()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = await loop.run_in_executor(None, sock.connect_ex, (self.host, port))
            sock.close()

            if result == 0:
                service = self.WELL_KNOWN.get(port, 'Unknown')
                return {
                    'port': port,
                    'service': service,
                    'state': 'open',
                    'protocol': 'tcp',
                    'internet_facing': self.internet_facing,
                    'network_zone': self.network_zone,
                }
        except Exception:
            pass
        return None

    async def scan(self):
        """Quét tất cả ports theo concurrency."""
        tasks = [self.scan_port(p) for p in self.ports]
        all_results = await asyncio.gather(*tasks)
        return [r for r in all_results if r]

    def scan_sync(self):
        """Chạy đồng bộ (cho CLI)."""
        return asyncio.run(self.scan())

    @classmethod
    def get_findings(cls, host, open_ports, internet_facing=False):
        """Tạo findings từ kết quả quét port."""
        findings = []
        for p in open_ports:
            port = p['port']
            service = p.get('service', 'Unknown')

            if p.get('internet_facing', False) and port in (22, 3306, 5432, 6379, 27017, 2375, 2376, 6433):
                severity = 'High'
                detail = f"Port {port} ({service}) mở ra INTERNET — nguy cơ bị tấn công từ bên ngoài"
            elif port in (23, 3389):
                severity = 'Medium'
                detail = f"Port {port} ({service}) Telnet/RDP — nên hạn chế hoặc dùng VPN"
            elif port in (22, 443, 80, 21):
                severity = 'Info'
                detail = f"Port {port} ({service}) — dịch vụ phổ biến"
            elif port in (3306, 5432, 6379, 9200, 27017, 2375, 2376, 10250):
                severity = 'Medium'
                detail = f"Port {port} ({service}) — dịch vụ cơ sở dữ liệu/container không nên expose công khai"
            else:
                severity = 'Low'
                detail = f"Port {port} ({service}) mở"
            findings.append({
                'type': 'Open Port',
                'severity': severity,
                'detail': f"{detail} | Host: {host}",
                'port': port,
                'service': service,
                'protocol': 'tcp',
            })
        return findings


class TLSScanner:
    """Kiểm tra TLS certificate của HTTPS website."""

    @staticmethod
    def scan(host, port=443):
        """Kiểm tra TLS certificate."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    version = ssock.version()
                    cipher = ssock.cipher()
                    return {
                        'host': host,
                        'tls_version': version,
                        'cipher': cipher[0] if cipher else None,
                        'cert_issuer': cert.get('issuer') if cert else None,
                        'cert_expiry': cert.get('notAfter') if cert else None,
                        'is_valid': True,
                    }
        except ssl.SSLError as e:
            return {'host': host, 'is_valid': False, 'error': str(e)}
        except Exception as e:
            return {'host': host, 'is_valid': False, 'error': str(e)}

    @staticmethod
    def get_findings(tls_info):
        """Tạo findings từ TLS scan."""
        findings = []
        if not tls_info.get('is_valid'):
            findings.append({
                'type': 'TLS Error',
                'severity': 'High',
                'detail': f"TLS kết nối đến {tls_info.get('host')} lỗi: {tls_info.get('error', 'Unknown')}",
            })
            return findings

        version = tls_info.get('tls_version', '')
        if 'TLSv1.1' in version or 'TLSv1' in version and '1.1' in version:
            findings.append({
                'type': 'Old TLS Version',
                'severity': 'High',
                'detail': f"Host {tls_info.get('host')} sử dụng {version} — nên nâng lên TLS 1.2/1.3",
            })
        elif 'TLSv1.2' in version:
            findings.append({
                'type': 'TLS Version',
                'severity': 'Low',
                'detail': f"Host {tls_info.get('host')} sử dụng {version} — có thể nâng lên TLS 1.3",
            })
        else:
            findings.append({
                'type': 'TLS Version',
                'severity': 'Info',
                'detail': f"Host {tls_info.get('host')} sử dụng {version}",
            })
        return findings


class InfraScanner:
    """Tổng hợp infra scan: port + TLS."""

    def __init__(self, host, ports=None, internet_facing=True, network_zone='internet'):
        self.host = host
        self.ports = ports
        self.internet_facing = internet_facing
        self.network_zone = network_zone

    async def scan(self):
        """Chạy toàn bộ infra scan."""
        results = {
            'host': self.host,
            'scanned_at': datetime.now().isoformat(),
            'open_ports': [],
            'tls': None,
            'findings': [],
        }

        # Port scan
        scanner = PortScanner(
            self.host,
            ports=self.ports,
            internet_facing=self.internet_facing,
            network_zone=self.network_zone,
        )
        open_ports = await scanner.scan()
        results['open_ports'] = open_ports
        results['findings'].extend(PortScanner.get_findings(self.host, open_ports, self.internet_facing))

        # TLS scan nếu có HTTPS/443
        has_https = any(p.get('port') == 443 for p in open_ports)
        if has_https or 443 in (self.ports or [443]):
            tls_info = TLSScanner.scan(self.host)
            results['tls'] = tls_info
            results['findings'].extend(TLSScanner.get_findings(tls_info))

        return results

    def scan_sync(self):
        return asyncio.run(self.scan())