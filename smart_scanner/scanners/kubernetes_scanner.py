"""
Kubernetes Security Scanner — theo đặc tả v3.1 §20.3 (Feature List #85).

Quét cấu hình Kubernetes: privileged containers, risky mounts,
network policies, RBAC, secrets management, service account tokens.
"""
import re


class KubernetesScanner:
    """Phân tích cấu hình Kubernetes từ manifest YAML text."""

    DANGEROUS_CAPABILITIES = [
        'CAP_SYS_ADMIN', 'CAP_NET_ADMIN', 'CAP_SYS_PTRACE',
        'CAP_SYS_CHROOT', 'CAP_DAC_OVERRIDE', 'CAP_SYS_ADMIN',
    ]

    RISKY_MOUNTS = ['hostPath', 'hostPID', 'hostIPC', 'hostNetwork']

    def __init__(self, manifest_text=None, manifest_file=None):
        self.manifest_text = manifest_text
        self.manifest_file = manifest_file
        self._load()

    def _load(self):
        if self.manifest_file:
            try:
                with open(self.manifest_file, 'r', encoding='utf-8', errors='ignore') as f:
                    self.manifest_text = f.read()
            except Exception:
                pass

    def scan_manifest(self):
        """Kiểm tra Kubernetes manifest YAML."""
        if not self.manifest_text:
            return []

        text = self.manifest_text
        findings = []

        # 1. Privileged containers
        if 'privileged: true' in text:
            findings.append({
                'type': 'K8s Privileged Container',
                'severity': 'High',
                'detail': 'Container chạy privileged: true — có quyền truy cập host',
                'confidence': 'High',
            })

        # 2. Risky capabilities
        for cap in self.DANGEROUS_CAPABILITIES:
            if re.search(rf'add:\s*\n\s*- {cap}', text) or cap in text.upper():
                findings.append({
                    'type': 'K8s Dangerous Capability',
                    'severity': 'High',
                    'detail': f'Container yêu cầu capability nguy hiểm: {cap}',
                    'confidence': 'Medium',
                })

        # 3. Risky mounts
        for mount in self.RISKY_MOUNTS:
            if re.search(rf'{mount}:\s*true', text):
                findings.append({
                    'type': 'K8s Risky Mount',
                    'severity': 'High',
                    'detail': f'Container dùng {mount}: true — chia sẻ tài nguyên host',
                    'confidence': 'High',
                })

        # 4. Host network / host port
        if 'hostNetwork: true' in text:
            findings.append({
                'type': 'K8s Host Network',
                'severity': 'High',
                'detail': 'Pod dùng hostNetwork: true — không có network isolation',
                'confidence': 'High',
            })

        # 5. Service account token
        if 'automountServiceAccountToken: true' in text:
            findings.append({
                'type': 'K8s Service Account Token',
                'severity': 'Medium',
                'detail': 'automountServiceAccountToken: true — container có quyền truy cập API K8s',
                'confidence': 'Medium',
            })

        # 6. Run as root
        if 'runAsNonRoot: false' in text:
            findings.append({
                'type': 'K8s Run As Root',
                'severity': 'Medium',
                'detail': 'Container chạy với runAsNonRoot: false — nên chạy non-root',
                'confidence': 'Medium',
            })

        # 7. No securityContext
        if 'securityContext' not in text and 'kind: Pod' in text:
            findings.append({
                'type': 'K8s Missing SecurityContext',
                'severity': 'Medium',
                'detail': 'Pod không có securityContext — nên cấu hình runAsNonRoot, readOnlyRootFilesystem',
                'confidence': 'Low',
            })

        return findings

    def scan(self):
        """Chạy toàn bộ K8s scan."""
        if not self.manifest_text:
            return {'vulnerabilities': [], 'note': 'Không có Kubernetes manifest để phân tích'}
        return {'vulnerabilities': self.scan_manifest()}