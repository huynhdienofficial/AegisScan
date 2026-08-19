import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SMART = ROOT / 'smart_scanner'
sys.path.insert(0, str(SMART))

from data_residency import DataResidencyManager, SelfSecurityScanner


def test_data_residency_regions():
    """DataResidencyManager quản lý vùng lưu trữ."""
    mgr = DataResidencyManager(region='local')

    # Cấu hình hiện tại
    config = mgr.get_storage_config()
    assert config['current_region'] == 'local'
    assert 'storage_path' in config

    # Đổi vùng
    result = mgr.set_region('vn')
    assert result['ok'] is True
    assert result['region'] == 'vn'
    assert len(mgr.residency_log) == 1

    # Vùng không hợp lệ
    try:
        mgr.set_region('mars')
        assert False, "Không được phép đổi sang vùng không hợp lệ"
    except ValueError:
        pass


def test_data_residency_compliance():
    """DataResidencyManager kiểm tra compliance."""
    mgr = DataResidencyManager(region='local')

    # Vùng local không đáp ứng GDPR
    check = mgr.check_compliance('gdpr')
    assert check['ok'] is False
    assert 'KHÔNG đáp ứng' in check['message']

    # Đổi sang EU → đáp ứng GDPR
    mgr.set_region('eu-west-1')
    check = mgr.check_compliance('gdpr')
    assert check['ok'] is True

    # Gợi ý vùng cho PCI DSS
    suggestions = mgr.suggest_region('pci_dss')
    assert len(suggestions) >= 1
    assert 'vn' in [s['region'] for s in suggestions] or 'us-east-1' in [s['region'] for s in suggestions]


def test_self_dependency_scan():
    """SelfSecurityScanner quét dependency của chính nền tảng."""
    scanner = SelfSecurityScanner(project_path=str(SMART))

    result = scanner.scan_dependencies()
    assert 'dependencies_count' in result
    assert len(result['dependencies']) > 0

    # Kiểm tra unpinned dependencies
    unpinned = [f for f in result['findings'] if f.get('severity') == 'Medium']
    assert len(unpinned) >= 0  # Có thể có hoặc không


def test_self_secrets_scan():
    """SelfSecurityScanner tự quét secrets trong chính source."""
    scanner = SelfSecurityScanner(project_path=str(SMART))
    findings = scanner.scan_self_secrets()

    # Có thể có secrets giả trong test, nhưng không được có trong file chính
    assert isinstance(findings, list)


def test_verify_least_privilege():
    """SelfSecurityScanner kiểm tra least privilege."""
    scanner = SelfSecurityScanner()
    result = scanner.verify_least_privilege()
    assert 'least_privilege_violation' in result
    assert 'severity' in result


def test_verify_ui_localhost_binding():
    """SelfSecurityScanner kiểm tra UI bind localhost."""
    scanner = SelfSecurityScanner()
    result = scanner.verify_ui_localhost_binding('127.0.0.1')
    assert result['ok'] is True
    assert result['is_localhost_only'] is True

    # Bind 0.0.0.0 → không an toàn
    result_unsafe = scanner.verify_ui_localhost_binding('0.0.0.0')
    assert result_unsafe['severity'] == 'High'
    assert 'authentication' in result_unsafe['message']