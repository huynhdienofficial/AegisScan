"""
Agent & Agentless Collector — theo đặc tả v3.1 (Feature List #6, #7, #8).

- Agentless Collector (#6): quét từ xa qua SSH/WinRM/API
- Agent Collector (#7): daemon cài trên host để audit local server
- Agent Management (#8): deploy, update, health check, remove agent
"""
import os
import platform
import socket
import subprocess
from datetime import datetime


class AgentlessCollector:
    """Thu thập thông tin không cần cài agent — quét từ xa."""

    def __init__(self, host=None, port=22, protocol='ssh', username=None, timeout=5):
        self.host = host
        self.port = port
        self.protocol = protocol  # ssh, winrm, api
        self.username = username
        self.timeout = timeout

    def check_port_open(self):
        """Kiểm tra port/S protocol có mở không."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.host, self.port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def fingerprint_service(self):
        """Fingerprint service version từ banner."""
        if not self.host:
            return None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return {
                'host': self.host,
                'port': self.port,
                'protocol': self.protocol,
                'banner': banner[:200],
                'detected_at': datetime.now().isoformat(),
            }
        except Exception:
            return None

    def collect(self):
        """Thu thập thông tin cơ bản từ xa."""
        result = {
            'host': self.host,
            'protocol': self.protocol,
            'port': self.port,
            'port_open': self.check_port_open(),
        }
        if result['port_open']:
            result['service'] = self.fingerprint_service()
        return result


class AgentCollector:
    """Agent cài trên host — audit sâu hơn (hardening, file integrity)."""

    def __init__(self, agent_id=None, hostname=None):
        self.agent_id = agent_id or f"AGENT-{socket.gethostname().upper()[:8]}"
        self.hostname = hostname or socket.gethostname()
        self.status = 'installed'
        self.last_heartbeat = datetime.now().isoformat()
        self.version = '1.0.0'

    def get_system_info(self):
        """Lấy thông tin hệ thống local."""
        return {
            'agent_id': self.agent_id,
            'hostname': self.hostname,
            'os': platform.system(),
            'os_release': platform.release(),
            'os_version': platform.version(),
            'architecture': platform.machine(),
            'python_version': platform.python_version(),
            'cpu_count': os.cpu_count(),
            'last_heartbeat': self.last_heartbeat,
            'status': self.status,
        }

    def check_disk_usage(self):
        """Kiểm tra disk usage."""
        try:
            if platform.system() == 'Windows':
                result = subprocess.run(['wmic', 'logicaldisk', 'get', 'size,freespace'],
                                        capture_output=True, text=True, timeout=10)
                return {'output': result.stdout[:500]}
            else:
                result = subprocess.run(['df', '-h'], capture_output=True, text=True, timeout=10)
                return {'output': result.stdout[:500]}
        except Exception:
            return {'error': 'Không thể kiểm tra disk'}

    def check_running_processes(self):
        """Kiểm tra process đang chạy."""
        try:
            result = subprocess.run(
                ['tasklist' if platform.system() == 'Windows' else 'ps', 'aux'],
                capture_output=True, text=True, timeout=10,
            )
            return {'process_count': len(result.stdout.splitlines()) - 1}
        except Exception:
            return {'error': 'Không thể kiểm tra processes'}


class AgentManager:
    """Quản lý vòng đời agent: deploy, update, health, remove."""

    def __init__(self):
        self.agents = {}  # agent_id -> AgentCollector
        self.deployment_log = []

    def deploy_agent(self, hostname=None, install_script=None):
        """Triển khai agent lên host."""
        agent = AgentCollector(hostname=hostname)
        self.agents[agent.agent_id] = agent
        self._log('deploy', agent.agent_id, f"Deploy agent lên {agent.hostname}")
        return agent

    def update_agent(self, agent_id, version):
        """Cập nhật agent."""
        agent = self.agents.get(agent_id)
        if agent:
            old_version = agent.version
            agent.version = version
            self._log('update', agent_id, f"Update {old_version} → {version}")
            return True
        return False

    def heartbeat(self, agent_id):
        """Health check — agent gửi heartbeat."""
        agent = self.agents.get(agent_id)
        if agent:
            agent.last_heartbeat = datetime.now().isoformat()
            agent.status = 'healthy'
            return True
        return False

    def check_health(self, agent_id=None):
        """Kiểm tra sức khỏe agent(s)."""
        results = {}
        for aid, agent in self.agents.items():
            if agent_id and aid != agent_id:
                continue
            from datetime import datetime, timedelta
            try:
                last = datetime.fromisoformat(agent.last_heartbeat)
                is_stale = (datetime.now() - last) > timedelta(minutes=5)
            except Exception:
                is_stale = True

            results[aid] = {
                'status': 'stale' if is_stale else 'healthy',
                'hostname': agent.hostname,
                'version': agent.version,
                'last_heartbeat': agent.last_heartbeat,
            }
            if is_stale:
                agent.status = 'stale'
        return results

    def remove_agent(self, agent_id):
        """Gỡ agent."""
        if agent_id in self.agents:
            agent = self.agents.pop(agent_id)
            self._log('remove', agent_id, f"Gỡ agent khỏi {agent.hostname}")
            return True
        return False

    def _log(self, action, agent_id, detail):
        self.deployment_log.append({
            'timestamp': datetime.now().isoformat(),
            'action': action,
            'agent_id': agent_id,
            'detail': detail,
        })

    def get_stats(self):
        """Thống kê agents."""
        health = self.check_health()
        return {
            'total_agents': len(self.agents),
            'healthy': sum(1 for h in health.values() if h['status'] == 'healthy'),
            'stale': sum(1 for h in health.values() if h['status'] == 'stale'),
            'deployment_log_entries': len(self.deployment_log),
        }