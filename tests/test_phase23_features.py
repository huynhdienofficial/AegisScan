import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SMART = ROOT / 'smart_scanner'
sys.path.insert(0, str(SMART))

from scanners.web.jwt_scanner import JWTScanner
from scanners.web.file_upload_scanner import FileUploadScanner
from scanners.web.graphql_scanner import GraphQLScanner
from scanners.web.websocket_scanner import WebSocketScanner
from scanners.secrets_scanner import SecretsScanner, DockerScanner
from threat_intel import ThreatIntelEngine
from utils.rbac import RBACManager, Role


def test_jwt_weak_secret_detection():
    """JWTScanner phát hiện weak secret."""
    import base64
    import hmac
    import hashlib
    import json

    # Tạo JWT với secret yếu 'secret'
    def b64(data):
        return base64.urlsafe_b64encode(json.dumps(data, separators=(',', ':')).encode()).rstrip(b'=').decode()

    header = b64({'alg': 'HS256', 'typ': 'JWT'})
    payload = b64({'sub': 'user1', 'role': 'admin'})
    signing = f"{header}.{payload}"
    sig = base64.urlsafe_b64encode(
        hmac.new(b'secret', signing.encode(), hashlib.sha256).digest()
    ).rstrip(b'=').decode()
    token = f"{signing}.{sig}"

    scanner = JWTScanner(request_handler=None, jwt_token=token)

    # Decode token hoạt động
    h, p, parts = scanner.decode_token(token)
    assert h['alg'] == 'HS256'
    assert p['sub'] == 'user1'
    assert len(parts) == 3

    # Brute force weak secret
    findings = scanner.test_weak_secret(h, p, parts)
    assert len(findings) >= 1
    assert findings[0]['type'] == 'JWT Weak Secret'
    assert findings[0]['severity'] == 'High'


def test_file_upload_scanner_builds_multipart():
    """FileUploadScanner xây dựng multipart đúng cách."""
    scanner = FileUploadScanner(request_handler=None, upload_url='https://x.com/upload')
    body, content_type = scanner._build_multipart('test.php', '<?php echo 1; ?>', 'application/x-php')
    assert b'test.php' in body
    assert b'<?php echo 1; ?>' in body
    assert 'multipart/form-data' in content_type


def test_graphql_scanner_queries():
    """GraphQLScanner tạo query introspection đúng."""
    scanner = GraphQLScanner(request_handler=None, graphql_url='https://x.com/graphql')
    intro = scanner.test_introspection()
    assert intro == []  # Không có request handler → không gửi

    result = scanner.scan()
    assert 'vulnerabilities' in result


def test_websocket_scanner_handles_no_url():
    """WebSocketScanner không có URL → trả về trống."""
    scanner = WebSocketScanner(request_handler=None, ws_url=None)
    result = scanner.scan()
    assert 'note' in result
    assert result['vulnerabilities'] == []


def test_threat_intel_cpe_matching():
    """ThreatIntelEngine map CPE."""
    intel = ThreatIntelEngine(cache_dir=str(ROOT / 'smart_scanner' / '.test_threat_cache'))

    # Map OpenSSH → CPE
    cpe = intel.map_to_cpe('openssh', '8.9p1')
    assert cpe is not None
    assert 'openssh' in cpe

    # Map Nginx → CPE
    cpe2 = intel.map_to_cpe('nginx', '1.18.0')
    assert cpe2 is not None

    # Normalize version
    assert intel.normalize_version(' 8.9p1 ') == '8.9p1'
    assert intel.normalize_version('1.18.0-ubuntu') == '1.18.0-ubuntu'


def test_secrets_scanner_detects_common_secrets():
    """SecretsScanner phát hiện API key, JWT, private key."""
    content = """
    api_key = "AIzaSyD1234567890abcdefghijklmnopqrstuv"
    aws_access = "AKIAIOSFODNN7EXAMPLE"
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    """

    scanner = SecretsScanner(content=content, filename='.env')
    findings = scanner.scan_content(content, '.env')

    types = [f['type'] for f in findings]
    assert any('API Key' in t for t in types)
    assert any('AWS' in t for t in types)


def test_docker_scanner_detects_privileged():
    """DockerScanner phát hiện privileged container."""
    compose = """
    version: "3"
    services:
      app:
        image: nginx
        privileged: true
        volumes:
          - /var/run/docker.sock:/var/run/docker.sock
        network_mode: host
    """
    scanner = DockerScanner(config_text=compose)
    findings = scanner.scan_compose()

    types = [f['type'] for f in findings]
    assert 'Docker Privileged Container' in types
    assert 'Docker Socket Exposed' in types
    assert 'Docker Host Network' in types


def test_rbac_permissions():
    """RBAC phân quyền đúng vai trò."""
    rbac = RBACManager()
    rbac.create_user('viewer1', Role.VIEWER)
    rbac.create_user('analyst1', Role.ANALYST)
    rbac.create_user('approver1', Role.APPROVER)
    rbac.create_user('admin1', Role.ADMIN)

    # Viewer không chạy scan
    assert rbac.check_permission('viewer1', 'scan.run') is False
    assert rbac.check_permission('viewer1', 'finding.view') is True

    # Analyst chạy scan nhưng không suppress
    assert rbac.check_permission('analyst1', 'scan.run') is True
    assert rbac.check_permission('analyst1', 'finding.suppress') is False

    # Approver/Admin có quyền suppress + exploit approve
    assert rbac.check_permission('approver1', 'finding.suppress') is True
    assert rbac.check_permission('approver1', 'exploit.approve') is True
    assert rbac.check_permission('admin1', 'exploit.run') is True

    # Viewer không được khai thác
    result = rbac.approve_exploitation('viewer1', 'https://target.com')
    assert result['approved'] is False

    # Approver phê duyệt được
    result = rbac.approve_exploitation('approver1', 'https://target.com', cve_id='CVE-2024-0001')
    assert result['approved'] is True
    assert result['approval']['approver'] == 'approver1'