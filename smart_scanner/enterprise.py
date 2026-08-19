"""
Enterprise Integrations — theo đặc tả v3.1 mục 10 (Feature List #70-72).

- SIEM Integration (#70): đẩy finding/alert sang SIEM
- Ticketing Integration (#71): tạo ticket Jira/ServiceNow
- Public API (#72): API cho CI/CD tích hợp
- Notification (#73): Email/Slack/Webhook
"""
import hashlib
import json
from datetime import datetime


class SIEMIntegrator:
    """Đẩy finding sang SIEM."""

    def __init__(self, siem_type='jira', endpoint=None, token=None):
        self.siem_type = siem_type  # splunk, elastic, qradar, ...
        self.endpoint = endpoint
        self.token = token
        self.sent_events = []

    def send_finding(self, finding):
        """Gửi finding sang SIEM."""
        event = {
            'timestamp': datetime.now().isoformat(),
            'type': self.siem_type,
            'finding': {
                'severity': finding.get('severity', ''),
                'title': finding.get('title', finding.get('type', '')),
                'detail': finding.get('detail', '')[:500],
                'url': finding.get('url', ''),
                'target': finding.get('target', ''),
            },
            'event_id': hashlib.sha256(
                f"{finding.get('type', '')}:{finding.get('url', '')}:{datetime.now().isoformat()}".encode()
            ).hexdigest()[:16],
        }
        self.sent_events.append(event)
        return event

    def send_batch(self, findings):
        """Gửi nhiều findings."""
        return [self.send_finding(f) for f in findings]


class TicketingIntegrator:
    """Tạo ticket từ finding (Jira/ServiceNow)."""

    def __init__(self, ticketing_type='jira', project='SEC', url=None, api_token=None):
        self.ticketing_type = ticketing_type  # jira, servicenow
        self.project = project
        self.url = url
        self.api_token = api_token
        self.created_tickets = []

    def create_ticket(self, finding):
        """Tạo ticket mới từ finding."""

        severity = finding.get('severity', 'Low')
        priorities = {'critical': 'P1', 'high': 'P2', 'medium': 'P3', 'low': 'P4'}

        ticket = {
            'ticket_id': f"SEC-{len(self.created_tickets) + 1:05d}",
            'project': self.project,
            'priority': priorities.get(severity.lower(), 'P4'),
            'summary': f"[{severity.upper()}] {finding.get('title', finding.get('type', ''))}",
            'description': finding.get('detail', '')[:2000],
            'url': finding.get('url', ''),
            'status': 'open',
            'created_at': datetime.now().isoformat(),
        }
        self.created_tickets.append(ticket)
        return ticket


class PublicAPI:
    """Public API cho CI/CD integration."""

    def __init__(self, api_key=None):
        self.api_key = api_key
        self.calls = []

    def authenticate(self, key):
        """Xác thực API key."""
        if not self.api_key:
            return False
        return key == self.api_key

    def get_findings(self, findings, format='json'):
        """API: lấy danh sách findings."""
        if format == 'json':
            return json.dumps({
                'count': len(findings),
                'findings': findings,
            }, ensure_ascii=False, indent=2)
        elif format == 'sarif':
            from report_exporters import SARIFExporter
            return json.dumps(SARIFExporter.export(findings), indent=2)
        return ''

    def health_check(self):
        """API health check."""
        return {'status': 'ok', 'timestamp': datetime.now().isoformat()}