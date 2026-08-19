import sys
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SMART = ROOT / 'smart_scanner'
sys.path.insert(0, str(SMART))

from utils.authorization import AuthorizationRecord, AuthorizationRegistry, HashChainedLog
from utils.rbac import RBACManager, Role
from exploitation import ExploitModule, GlobalKillSwitch
from exploitation_tool import ExploitationTool


def test_authorization_record_scope_and_tier():
    record = AuthorizationRecord('admin1', scope=['*.example.com'], authorization_type='active_scan', ttl_hours=1)
    assert record.covers('https://app.example.com/path')
    assert record.covers('sub.app.example.com')
    assert not record.covers('https://evil.com')

    # active_scan record thoả 'scan' (thấp hơn) nhưng không thoả 'exploitation' (cao hơn)
    assert record.satisfies('scan', 'https://app.example.com')
    assert record.satisfies('active_scan', 'https://app.example.com')
    assert not record.satisfies('exploitation', 'https://app.example.com')


def test_authorization_record_expiry():
    record = AuthorizationRecord('admin1', scope=['example.com'], authorization_type='scan', ttl_hours=1)
    assert record.is_valid()

    future = datetime.now() + timedelta(hours=2)
    assert not record.is_valid(now=future)

    record.revoke()
    assert not record.is_valid()


def test_authorization_registry_requires_rbac_for_high_tier():
    registry = AuthorizationRegistry()  # không gắn RBAC
    try:
        registry.issue('nobody', scope=['example.com'], authorization_type='exploitation')
        assert False, "phải raise PermissionError khi thiếu RBAC cho tier cao"
    except PermissionError:
        pass

    rbac = RBACManager()
    rbac.create_user('viewer1', Role.VIEWER)
    registry2 = AuthorizationRegistry(rbac_manager=rbac)
    try:
        registry2.issue('viewer1', scope=['example.com'], authorization_type='exploitation')
        assert False, "Viewer không được cấp record loại exploitation"
    except PermissionError:
        pass

    rbac.create_user('admin1', Role.ADMIN)
    record = registry2.issue('admin1', scope=['example.com'], authorization_type='exploitation')
    assert record.authorization_type == 'exploitation'


def test_authorization_registry_audit_trail_tamper_evident():
    rbac = RBACManager()
    rbac.create_user('admin1', Role.ADMIN)
    registry = AuthorizationRegistry(rbac_manager=rbac)
    record = registry.issue('admin1', scope=['example.com'], authorization_type='active_scan')
    registry.revoke(record.record_id, revoked_by='admin1')

    assert registry.verify_audit_integrity() is True

    # Sửa âm thầm một entry giữa chain → chain phải bị phát hiện là hỏng
    entries = registry.audit.entries()
    entries[0]['detail'] = 'tampered'
    assert registry.verify_audit_integrity() is False


def test_hash_chained_log_detects_reordering():
    log = HashChainedLog()
    log.append('a', '1')
    log.append('b', '2')
    assert log.verify_chain() is True

    entries = log.entries()
    entries[0], entries[1] = entries[1], entries[0]
    log._entries = entries
    assert log.verify_chain() is False


def test_exploitation_tool_requires_valid_authorization_record():
    from utils.request_handler import RequestHandler
    handler = RequestHandler()

    try:
        ExploitationTool(handler, target_url='https://lab.example.com', exploit_level=2)
        assert False, "exploit_level=2 không được phép chạy thiếu Authorization Record"
    except PermissionError:
        pass

    rbac = RBACManager()
    rbac.create_user('admin1', Role.ADMIN)
    registry = AuthorizationRegistry(rbac_manager=rbac)
    record = registry.issue('admin1', scope=['lab.example.com'], authorization_type='active_scan')

    tool = ExploitationTool(handler, target_url='https://lab.example.com',
                             exploit_level=2, authorization_record=record)
    assert tool.approved_by == 'admin1'

    # exploit_level=1 (signal-only) vẫn không cần record
    tool1 = ExploitationTool(handler, target_url='https://lab.example.com', exploit_level=1)
    assert tool1.authorization_record is None


def test_global_kill_switch_stops_all_modules_for_asset():
    rbac = RBACManager()
    rbac.create_user('admin1', Role.ADMIN)
    registry = AuthorizationRegistry(rbac_manager=rbac)
    record = registry.issue('admin1', scope=['lab.example.com'], authorization_type='active_scan')

    kill_switch = GlobalKillSwitch()
    module = ExploitModule(rbac_manager=rbac, target_url='https://lab.example.com',
                            global_kill_switch=kill_switch, asset_id='asset-1')
    assert module.enable_level(2, approver_username='admin1', authorization_record=record) is True

    kill_switch.stop_asset('asset-1', reason='incident')
    result = module.level2_safe_verification(lambda: [{'type': 'test'}])
    assert result == []

    # Module khác trên asset khác không bị ảnh hưởng
    other_module = ExploitModule(rbac_manager=rbac, target_url='https://lab2.example.com',
                                  global_kill_switch=kill_switch, asset_id='asset-2')
    record2 = registry.issue('admin1', scope=['lab2.example.com'], authorization_type='active_scan')
    assert other_module.enable_level(2, approver_username='admin1', authorization_record=record2) is True
    assert other_module.level2_safe_verification(lambda: [{'type': 'ok'}]) == [{'type': 'ok'}]

    kill_switch.stop_all(reason='org-wide freeze')
    assert other_module.level2_safe_verification(lambda: [{'type': 'ok'}]) == []
