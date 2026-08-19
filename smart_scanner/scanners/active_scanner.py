import asyncio
from payloads.sqli_payloads import SQLIPayloads
from payloads.xss_payloads import XSSPayloads
from payloads.rce_payloads import RCEPayloads
from utils.fuzzer_engine import FuzzerEngine

class ActiveScanner:
    def __init__(self, request_handler, max_concurrent=5, timeout=10):
        self.request_handler = request_handler
        self.fuzzer = FuzzerEngine(request_handler, max_concurrent, timeout)
        self.vulnerabilities = []

    async def scan_sqli(self, urls, parameters, forms=None):
        print(f"🔍 Scanning SQL Injection...")
        payloads = SQLIPayloads.get_all_payloads()
        findings = await self.fuzzer.run(urls, parameters, payloads)
        
        sqli_vulns = []
        for vuln_type, vuln_data in findings.items():
            if 'SQL' in vuln_type or 'SLEEP' in vuln_type:
                sqli_vulns.extend(vuln_data)
        
        # Quét thêm qua forms
        if forms:
            form_findings = await self.fuzzer.run_forms(forms, payloads)
            for vuln_type, vuln_data in form_findings.items():
                if 'SQL' in vuln_type or 'SLEEP' in vuln_type or 'Time-based Attack' in vuln_type:
                    for v in vuln_data:
                        if v.get('method') == 'POST' or any(seg in v.get('payload', '') for seg in ["'", "SLEEP", "1=1", "UNION"]):
                            sqli_vulns.append(v)
        
        self.vulnerabilities.extend(sqli_vulns)
        return sqli_vulns

    async def scan_xss(self, urls, parameters, forms=None):
        print(f"🔍 Scanning XSS...")
        payloads = XSSPayloads.get_all_payloads()
        findings = await self.fuzzer.run(urls, parameters, payloads)
        
        xss_vulns = []
        for vuln_type, vuln_data in findings.items():
            if 'XSS' in vuln_type or 'Reflected' in vuln_type:
                xss_vulns.extend(vuln_data)
        
        # Quét thêm qua forms
        if forms:
            form_findings = await self.fuzzer.run_forms(forms, payloads)
            for vuln_type, vuln_data in form_findings.items():
                if 'XSS' in vuln_type or 'Reflected' in vuln_type or 'DOM-based' in vuln_type:
                    xss_vulns.extend(vuln_data)
                else:
                    for v in vuln_data:
                        if any(seg in v.get('payload', '') for seg in ['<script', 'onerror=', 'onload=', 'javascript:']):
                            if v.get('method') == 'POST':
                                xss_vulns.append(v)
        
        self.vulnerabilities.extend(xss_vulns)
        return xss_vulns

    async def scan_rce(self, urls, parameters, forms=None):
        print(f"🔍 Scanning RCE...")
        payloads = RCEPayloads.get_all_payloads()
        findings = await self.fuzzer.run(urls, parameters, payloads)
        
        rce_vulns = []
        for vuln_type, vuln_data in findings.items():
            if 'Command Injection' in vuln_type or 'RCE' in vuln_type:
                rce_vulns.extend(vuln_data)
        
        # Quét thêm qua forms
        if forms:
            form_findings = await self.fuzzer.run_forms(forms, payloads)
            for vuln_type, vuln_data in form_findings.items():
                if 'Command Injection' in vuln_type or 'RCE' in vuln_type:
                    rce_vulns.extend(vuln_data)
                else:
                    for v in vuln_data:
                        if v.get('method') == 'POST' and any(
                            seg in v.get('payload', '') for seg in [';', '|', '&', 'sleep', 'whoami', 'id', 'dir', 'ls']
                        ):
                            rce_vulns.append(v)
        
        self.vulnerabilities.extend(rce_vulns)
        return rce_vulns

    async def scan_all(self, urls, parameters, forms=None):
        all_vulns = []
        tasks = [
            self.scan_sqli(urls, parameters, forms),
            self.scan_xss(urls, parameters, forms),
            self.scan_rce(urls, parameters, forms)
        ]
        results = await asyncio.gather(*tasks)
        for result in results:
            all_vulns.extend(result)
        return all_vulns