#!/usr/bin/env python3
import argparse
import asyncio
import json
import sys
from urllib.parse import urlparse
from utils.request_handler import RequestHandler
from utils.scope_guard import ScopeGuard, ScanContext
from utils.safety_profiles import SafetyManager

from fingerprint.attack_surface.exploit_manager import ExploitManager

from crawler_core import AsyncCrawlerEngine
from correlation_engine import CorrelationEngine
from storage import SQLiteStorage
from report_exporters import SARIFExporter, CSVExporter
from agents import AgentlessCollector


def get_scope_guard_config(args):
    """Xây dựng cấu hình Scope Guard từ CLI args."""
    allowlist = []
    if args.allowlist:
        allowlist = [item.strip() for item in args.allowlist.split(',')]

    denylist = []
    if args.denylist:
        denylist = [item.strip() for item in args.denylist.split(',')]

    return {
        'allowlist': allowlist,
        'denylist': denylist,
        'local_lab_mode': args.local_lab,
        'dry_run': args.dry_run,
    }


def main():
    parser = argparse.ArgumentParser(description='Smart Security Scanner CLI')
    parser.add_argument('--url', required=True, help='Target URL')
    parser.add_argument('--scan', choices=['sqli', 'xss', 'rce', 'all'], 
                       default='all', help='Scan type')
    parser.add_argument('--output', default='report.json', help='Output file')
    parser.add_argument('--crawl-depth', type=int, default=2, help='Crawl depth')
    parser.add_argument('--concurrency', type=int, default=3, help='Concurrency level')
    
    # Bước 7: Scope Guard, Safety Profile, Rate Limiting
    parser.add_argument('--profile', choices=['passive', 'safe-active', 'authenticated', 'deep-lab', 'ci-fast'],
                       default='safe-active', help='Safety profile (mặc định: safe-active)')
    parser.add_argument('--allowlist', default='', help='Allowlist domains (phân cách bằng dấu phẩy)')
    parser.add_argument('--denylist', default='', help='Denylist domains (phân cách bằng dấu phẩy)')
    parser.add_argument('--local-lab', action='store_true', 
                       help='Bật Local Lab Mode — cho phép quét localhost/LAN')
    parser.add_argument('--dry-run', action='store_true', 
                       help='Dry-run — hiển thị request dự kiến mà không gửi')
    parser.add_argument('--confirm', action='store_true', 
                       help='Xác nhận quyền kiểm thử target (bỏ qua cảnh báo)')
    parser.add_argument('--rps', type=int, default=5, help='Giới hạn Requests Per Second')
    parser.add_argument('--no-verify-ssl', action='store_true',
                        help='Bỏ qua xác minh SSL (dành cho target chứng chỉ lỗi)')
    parser.add_argument('--db', default='scanner.db',
                        help='Đường dẫn SQLite lưu scan history/asset/findings (mặc định: scanner.db)')
    parser.add_argument('--no-storage', action='store_true',
                        help='Tắt lưu scan history vào SQLite (chỉ xuất report file)')
    parser.add_argument('--sarif-output', default='',
                        help='Xuất thêm report dạng SARIF 2.1.0 (tích hợp CI/CD) ra đường dẫn này')
    parser.add_argument('--csv-output', default='',
                        help='Xuất thêm report dạng CSV ra đường dẫn này')
    parser.add_argument('--agentless-ports', default='',
                        help='Infra Scan Engine (Agentless): danh sách port kiểm tra open/banner '
                             'trên hostname của target, phân cách bằng dấu phẩy (vd: 22,443,3306)')

    args = parser.parse_args()
    
    print(f"🛡️ Smart Security Scanner")
    print(f"Target: {args.url}")
    print(f"Profile: {args.profile}")
    print("=" * 50)

    # ─── Bước 7: Scope Guard ──────────────────────────────────────
    scope_config = get_scope_guard_config(args)
    scope_guard = ScopeGuard(scope_config)

    # Kiểm tra quyền truy cập target
    auth_result = scope_guard.authorize_target(args.url, confirm=args.confirm)
    scope_guard.audit_log('authorize', args.url, auth_result)

    if not auth_result['allowed']:
        print(f"❌ {auth_result.get('reason', 'Target bị chặn')}")
        print(f"   Gợi ý: --allowlist để thêm target, --local-lab để quét localhost, --confirm để xác nhận quyền")
        sys.exit(1)

    if auth_result.get('requires_confirmation'):
        print(f"⚠️  {auth_result.get('reason')}")
        print("   Nhấn Enter để xác nhận bạn có quyền kiểm thử target này...")
        input()
        auth_result = scope_guard.authorize_target(args.url, confirm=True)
        if not auth_result['allowed']:
            print(f"❌ {auth_result.get('reason')}")
            sys.exit(1)
        print(f"✅ {auth_result.get('reason')}")

    # ─── Bước 7: Safety Manager ───────────────────────────────────
    safety_manager = SafetyManager(args.profile, scope_guard)
    if args.rps > 0:
        safety_manager.rate_limiter.rps = args.rps
        safety_manager.rate_limiter.burst = max(args.rps, 20)

    if args.dry_run:
        print("🔍 Dry-run mode: Bật — sẽ không gửi request thật")
        profile = safety_manager.profile.to_dict()
        print(f"\n📋 Cấu hình profile: {args.profile}")
        print(f"   - Mô tả: {profile['description']}")
        print(f"   - Cho phép inject payload: {profile['config']['inject_payloads']}")
        print(f"   - Method cho phép: {', '.join(profile['config']['allowed_methods'])}")
        print(f"   - Concurrency: {profile['config']['concurrency']}")
        print(f"   - RPS: {safety_manager.rate_limiter.rps}")
        print(f"   - Timeout: {profile['config']['timeout']}s")
        print(f"   - Max pages: {profile['config']['max_pages']}")
        print(f"   - Yêu cầu xác nhận: {profile['config']['require_confirmation']}")
        print("\n📋 Scope guard cấu hình:")
        print(f"   - Allowlist: {', '.join(sorted(scope_guard.allowlist)) or '(trống)'}")
        print(f"   - Denylist: {', '.join(sorted(scope_guard.denylist)) or '(trống)'}")
        print(f"   - Local Lab Mode: {scope_guard.local_lab_mode}")
        print("\n(Dry-run — không gửi request nào)")
        return

    # Tạo Scan Context
    scan_context = ScanContext(args.url, scope_guard, profile=args.profile)
    scan_context.compute_config_hash({
        'profile': args.profile,
        'scan': args.scan,
        'depth': args.crawl_depth,
        'concurrency': args.concurrency,
    })

    print(f"📋 Scan ID: {scan_context.scan_id}")

    # ─── Storage (SQLite) — trước đây được viết đầy đủ (storage.py) nhưng
    # không được cli.py/app.py gọi ở đâu cả, nên scan history luôn mất khi
    # restart. Wire thật vào đây: lưu Scan record ngay khi bắt đầu (status
    # 'running'), rồi Asset + Findings + cập nhật status khi scan xong.
    storage = None
    asset_id = None
    if not args.no_storage:
        storage = SQLiteStorage(db_path=args.db)
        storage.save_scan({
            'scan_id': scan_context.scan_id,
            'target': args.url,
            'profile': args.profile,
            'started_at': scan_context.started_at,
            'status': 'running',
        })
        parsed_host = urlparse(args.url).hostname or args.url
        asset_id = f"asset-{parsed_host}"
        storage.save_asset({
            'asset_id': asset_id,
            'name': parsed_host,
            'asset_type': 'web app',
            'hostname': parsed_host,
            'url': args.url,
            'last_scan': scan_context.started_at,
            'last_seen': scan_context.started_at,
        })

    # Crawl
    print("📡 Crawling...")
    config = {
        'max_pages': safety_manager.profile.config.get('max_pages', 50),
        'concurrency': args.concurrency,
        'headless': True,
        'max_depth': args.crawl_depth,
    }
    crawler = AsyncCrawlerEngine(config, scope_guard=scope_guard)
    try:
        results = asyncio.run(crawler.start(args.url))
    except PermissionError as e:
        print(f"❌ {str(e)}")
        sys.exit(1)
    
    urls = results['urls']
    parameters = results['parameters']
    forms = results.get('forms', [])
    scope_blocked = results.get('scope_blocked', 0)
    print(f"✅ Found {len(urls)} URLs, {len(parameters)} parameters, {len(forms)} forms")
    if scope_blocked:
        print(f"🚫 {scope_blocked} URL bị chặn bởi scope guard")

    # ─── Infra Scan Engine — Agentless (đặc tả §5) ─────────────────
    # AgentlessCollector đã được viết đầy đủ (agents.py) nhưng trước đây
    # không CLI/UI nào gọi tới — chỉ dùng port/banner-check thực tế trên
    # hostname của target khi user chỉ định --agentless-ports.
    infra_findings = []
    if args.agentless_ports:
        target_host = urlparse(args.url).hostname
        ports = [int(p.strip()) for p in args.agentless_ports.split(',') if p.strip().isdigit()]
        print(f"🔌 Agentless Collector: kiểm tra {len(ports)} port trên {target_host}...")
        for port in ports:
            collector = AgentlessCollector(host=target_host, port=port)
            result = collector.collect()
            state = "OPEN" if result['port_open'] else "closed"
            print(f"   - {target_host}:{port} → {state}")
            if result['port_open']:
                banner = (result.get('service') or {}).get('banner', '')
                infra_findings.append({
                    'type': f'Open Port {port}',
                    'severity': 'Info',
                    'url': f"{target_host}:{port}",
                    'detail': f"Port {port} mở" + (f" — banner: {banner}" if banner else ""),
                    'confidence': 'High',
                })

    # Scan
    print("⚡ Running vulnerability scan...")
    handler = RequestHandler(
        timeout=safety_manager.profile.config.get('timeout', 15),
        max_retries=3,
        safety_manager=safety_manager,
        verify_ssl=not getattr(args, 'no_verify_ssl', False),
    )
    manager = ExploitManager(handler, scan_context=scan_context)
    
    scan_types = ['sqli', 'xss', 'rce'] if args.scan == 'all' else [args.scan]
    vulns = asyncio.run(manager.run_scan(urls, parameters, scan_types, forms=forms))
    
    print(f"✅ Found {len(vulns)} vulnerabilities")

    # Save report
    manager.export_results(args.output)
    print(f"📄 Report saved to {args.output}")

    # ─── Correlation & Deduplication Engine (đặc tả v3.3 §25) ─────
    # Chuẩn hoá findings về Unified Finding Data Model (15 trường) và khớp
    # trùng — tránh cùng một lỗ hổng bị đếm/hiển thị nhiều lần nếu về sau có
    # thêm detection source khác chạy trên cùng target/parameter.
    correlator = CorrelationEngine(asset=args.url)
    unified = correlator.normalize_and_correlate({
        'active_scanner': vulns,
        'agentless_collector': infra_findings,
    })
    total_raw = len(vulns) + len(infra_findings)
    duplicates_merged = total_raw - len(unified)
    if duplicates_merged > 0:
        print(f"🔗 Correlation Engine: gộp {duplicates_merged} finding trùng lặp "
              f"→ còn {len(unified)} finding duy nhất (Unified Finding schema)")
    correlated_output = args.output.rsplit('.', 1)[0] + '.correlated.json'
    with open(correlated_output, 'w', encoding='utf-8') as f:
        json.dump([uf.to_dict() for uf in unified], f, ensure_ascii=False, indent=2)
    print(f"📄 Unified/correlated findings saved to {correlated_output}")

    # ─── SARIF/CSV export (đặc tả v3.1 §13.2 — SARIF cho CI/CD) ────
    # SARIFExporter/CSVExporter đã được viết đầy đủ (report_exporters.py)
    # nhưng trước đây không nơi nào trong CLI/app thật gọi tới — chỉ có test
    # gọi trực tiếp. Wire vào đây trên chính tập unified findings.
    unified_dicts = [uf.to_dict() for uf in unified]
    if args.sarif_output:
        SARIFExporter.save(unified_dicts, args.sarif_output)
        print(f"📄 SARIF report saved to {args.sarif_output}")
    if args.csv_output:
        CSVExporter.export(unified_dicts, args.csv_output)
        print(f"📄 CSV report saved to {args.csv_output}")

    # ─── Lưu findings + đóng scan trong storage ────────────────────
    if storage:
        for i, uf in enumerate(unified):
            storage.save_finding({
                'finding_id': f"{scan_context.scan_id}-{i}",
                'asset_id': asset_id,
                'scan_id': scan_context.scan_id,
                'rule_id': uf.cwe or uf.vulnerability,
                'severity': uf.severity,
                'title': uf.vulnerability,
                'status': 'suspected',
                'evidence': {'detail': uf.evidence, 'location': uf.location,
                             'detection_source': uf.detection_source},
            })
        storage.update_scan(scan_context.scan_id, status='completed',
                             ended_at=scan_context.ended_at or scan_context.started_at)
        stats = storage.get_stats()
        print(f"💾 Storage: {stats['scans']} scans, {stats['assets']} assets, "
              f"{stats['findings']} findings lưu trong {args.db}")

        # ─── Scan History & Delta (đặc tả §11.3) ───────────────────
        previous_scan = storage.get_previous_scan(args.url, exclude_scan_id=scan_context.scan_id)
        if previous_scan:
            delta = storage.compare_scans(previous_scan['scan_id'], scan_context.scan_id)
            s = delta['summary']
            print(f"📈 Delta so với scan trước ({previous_scan['scan_id']}, "
                  f"{previous_scan['started_at']}): "
                  f"+{s['new_count']} New, -{s['fixed_count']} Fixed, "
                  f"={s['unchanged_count']} Unchanged")
        else:
            print("📈 Chưa có scan trước đó trên target này để so sánh delta.")

        storage.close()


    # Summary
    print("\n📊 Summary:")
    print(f"  - Scan ID: {scan_context.scan_id}")
    print(f"  - Safety profile: {args.profile}")
    print(f"  - URLs scanned: {len(urls)}")
    print(f"  - Parameters tested: {len(parameters)}")
    print(f"  - Forms scanned: {len(forms)}")
    print(f"  - Scope blocked: {scope_blocked}")
    safety_stats = safety_manager.get_stats()
    print(f"  - Payloads blocked by safety: {safety_stats['total_blocked']}")
    print(f"  - Vulnerabilities found: {len(vulns)}")
    
    if vulns:
        print("\n📋 Top vulnerabilities:")
        for v in vulns[:5]:
            print(f"  - {v.get('parameter', 'Unknown')}: {v.get('confidence', 'Low')} confidence")

if __name__ == '__main__':
    main()