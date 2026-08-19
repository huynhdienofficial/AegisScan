import asyncio
import time
import hashlib
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .response_analyzer import ResponseAnalyzer

class FuzzerEngine:
    def __init__(self, request_handler, max_concurrent=5, timeout=10):
        self.request_handler = request_handler
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.results = []
        self.safety_manager = getattr(request_handler, 'safety_manager', None)
        self.blocked_payloads = []

    def _is_payload_safe(self, payload):
        """Kiểm tra payload có an toàn để gửi không."""
        if not self.safety_manager:
            return True
        check = self.safety_manager.check_payload(payload)
        if not check['allowed']:
            self.blocked_payloads.append({
                'payload': payload,
                'reason': check.get('reason', 'Unknown'),
            })
            return False
        return True

    def _get_safe_payloads(self, payloads):
        """Lọc các payload an toàn theo safety profile."""
        if not self.safety_manager:
            return list(payloads)
        return [p for p in payloads if self._is_payload_safe(p)]

    async def fuzz_parameter(self, url, parameter, payloads, method='GET'):
        findings = []
        payloads = self._get_safe_payloads(payloads)
        
        for payload in payloads:
            if method == 'POST':
                fuzz_url = url
                data = {parameter: payload}
            else:
                fuzz_url = self._inject_payload(url, parameter, payload)
                data = None
            
            start_time = time.time()
            response = await self.request_handler.send_request(method, fuzz_url, data=data)
            end_time = time.time()
            response_time = end_time - start_time
            
            indicators = []
            
            if response_time > 5:
                indicators.append({
                    'type': 'Time-based Attack',
                    'detail': f'Response time: {response_time:.2f}s',
                    'confidence': 'High'
                })
            
            if payload in response.text:
                indicators.append({
                    'type': 'Payload Reflection',
                    'detail': f'Payload found in response',
                    'confidence': 'High'
                })
            
            indicators.extend(ResponseAnalyzer.detect_sqli(response.text, payload))
            indicators.extend(ResponseAnalyzer.detect_xss(response.text, payload))
            indicators.extend(ResponseAnalyzer.detect_rce(response.text, payload))
            
            if indicators:
                confidence = ResponseAnalyzer.calculate_confidence(indicators)
                findings.append({
                    'url': fuzz_url,
                    'parameter': parameter,
                    'method': method,
                    'payload': payload,
                    'response_time': response_time,
                    'indicators': indicators,
                    'confidence': confidence,
                    'status_code': response.status_code
                })
        
        return findings

    def _inject_payload(self, url, parameter, payload):
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        query_params[parameter] = [payload]
        new_query = urlencode(query_params, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

    async def fuzz_form(self, form, payloads):
        """Fuzz tất cả inputs của một form (GET hoặc POST)."""
        findings = []
        action_url = form.get('action')
        method = form.get('method', 'POST').upper()

        if not action_url:
            return findings

        inputs = form.get('inputs', []) or []
        payloads = self._get_safe_payloads(payloads)

        # Nếu method là GET, inject payload vào query string
        if method == 'GET':
            for payload in payloads:
                for inp in inputs:
                    param_name = inp.get('name')
                    if not param_name:
                        continue
                    fuzz_url = self._inject_payload(action_url, param_name, payload)

                    start_time = time.time()
                    response = await self.request_handler.send_request('GET', fuzz_url)
                    end_time = time.time()
                    response_time = end_time - start_time

                    indicators = []
                    if response_time > 5:
                        indicators.append({
                            'type': 'Time-based Attack',
                            'detail': f'Response time: {response_time:.2f}s',
                            'confidence': 'High'
                        })
                    if payload in response.text:
                        indicators.append({
                            'type': 'Payload Reflection',
                            'detail': 'Payload found in response',
                            'confidence': 'High'
                        })
                    indicators.extend(
                        ResponseAnalyzer.detect_sqli(response.text, payload)
                        + ResponseAnalyzer.detect_xss(response.text, payload)
                        + ResponseAnalyzer.detect_rce(response.text, payload)
                    )
                    if indicators:
                        findings.append({
                            'url': fuzz_url,
                            'parameter': param_name,
                            'method': 'GET',
                            'payload': payload,
                            'response_time': response_time,
                            'indicators': indicators,
                            'confidence': ResponseAnalyzer.calculate_confidence(indicators),
                            'status_code': response.status_code
                        })
            return findings

        # Form POST - giữ nguyên giá trị ban đầu của form, thay payload vào từng input
        for payload in payloads:
            for inp in inputs:
                param_name = inp.get('name')
                if not param_name:
                    continue

                # Build form data với tất cả inputs, thay payload vào param đang test
                form_data = {}
                for other_inp in inputs:
                    other_name = other_inp.get('name')
                    if other_name and other_name != param_name:
                        form_data[other_name] = other_inp.get('value', '')

                payload_data = dict(form_data)
                payload_data[param_name] = payload

                start_time = time.time()
                response = await self.request_handler.send_request(method, action_url, data=payload_data)
                end_time = time.time()
                response_time = end_time - start_time

                indicators = []
                if response_time > 5:
                    indicators.append({
                        'type': 'Time-based Attack',
                        'detail': f'Response time: {response_time:.2f}s',
                        'confidence': 'High'
                    })
                if payload in response.text:
                    indicators.append({
                        'type': 'Payload Reflection',
                        'detail': 'Payload found in response',
                        'confidence': 'High'
                    })
                indicators.extend(
                    ResponseAnalyzer.detect_sqli(response.text, payload)
                    + ResponseAnalyzer.detect_xss(response.text, payload)
                    + ResponseAnalyzer.detect_rce(response.text, payload)
                )
                if indicators:
                    findings.append({
                        'url': action_url,
                        'parameter': param_name,
                        'method': method,
                        'payload': payload,
                        'response_time': response_time,
                        'indicators': indicators,
                        'confidence': ResponseAnalyzer.calculate_confidence(indicators),
                        'status_code': response.status_code
                    })

        return findings

    async def run(self, urls, parameters, payloads):
        return await self._run_tasks([
            self.fuzz_parameter(url, param, payloads)
            for url in urls
            for param in parameters
        ])

    async def run_forms(self, forms, payloads):
        return await self._run_tasks([
            self.fuzz_form(form, payloads)
            for form in forms
        ])

    async def _run_tasks(self, tasks):
        all_findings = {}
        for i in range(0, len(tasks), self.max_concurrent):
            chunk = tasks[i:i+self.max_concurrent]
            # return_exceptions=True: 1 request loi khong giet ca scan
            results = await asyncio.gather(*chunk, return_exceptions=True)
            for result in results:
                if isinstance(result, Exception):
                    continue
                for finding in result or []:
                    vuln_type = finding.get('indicators', [{}])[0].get('type', 'Unknown')
                    if vuln_type not in all_findings:
                        all_findings[vuln_type] = []
                    all_findings[vuln_type].append(finding)
        
        self.results = all_findings
        return all_findings