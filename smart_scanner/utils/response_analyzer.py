import re


class ResponseAnalyzer:
    @staticmethod
    def analyze_response(status_code, response_text, payload):
        analysis = {
            'status_code': status_code,
            'is_blocked': False,
            'blocked_reason': None,
            'confidence': 'Low',
            'indicators': [],
        }

        blocked_keywords = [
            'waf', 'access denied', 'captcha', 'verify you are not a bot',
            'bot detected', 'blocked by security', 'cloudflare', 'ddos protection'
        ]

        if status_code in {403, 429} or any(keyword in (response_text or '').lower() for keyword in blocked_keywords):
            analysis['is_blocked'] = True
            analysis['blocked_reason'] = 'WAF/anti-bot'
            analysis['confidence'] = 'Low'
            return analysis

        indicators = []
        indicators.extend(ResponseAnalyzer.detect_sqli(response_text, payload))
        indicators.extend(ResponseAnalyzer.detect_xss(response_text, payload))
        indicators.extend(ResponseAnalyzer.detect_rce(response_text, payload))

        if indicators:
            analysis['indicators'] = indicators
            analysis['confidence'] = ResponseAnalyzer.calculate_confidence(indicators)

        return analysis

    @staticmethod
    def detect_sqli(response_text, payload):
        indicators = []
        sql_errors = [
            r"SQL syntax",
            r"mysql_fetch",
            r"ORA-[0-9]{5}",
            r"PostgreSQL.*ERROR",
            r"Warning.*mysql",
            r"you have an error in your sql syntax",
            r"unclosed quotation mark",
            r"quoted string not properly terminated"
        ]

        for pattern in sql_errors:
            if re.search(pattern, response_text, re.IGNORECASE):
                indicators.append({
                    'type': 'SQL Error Message',
                    'pattern': pattern,
                    'confidence': 'High'
                })
        return indicators

    @staticmethod
    def detect_xss(response_text, payload):
        indicators = []
        if payload in response_text:
            indicators.append({
                'type': 'Reflected XSS',
                'detail': 'Payload reflected',
                'confidence': 'High'
            })

        dangerous_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'onerror=',
            r'onload='
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                indicators.append({
                    'type': 'DOM-based XSS',
                    'pattern': pattern,
                    'confidence': 'Medium'
                })

        return indicators

    @staticmethod
    def detect_rce(response_text, payload):
        indicators = []
        command_patterns = [
            (r"uid=\d+\([^)]+\)", "User ID found"),
            (r"root:[^:]*:[^:]*:", "Password file"),
            (r"Windows\s+NT", "Windows OS"),
            (r"/etc/passwd", "Password file path"),
            (r"drwxr-xr-x", "Linux directory")
        ]

        for pattern, description in command_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                indicators.append({
                    'type': 'Command Injection',
                    'detail': description,
                    'confidence': 'High'
                })

        return indicators

    @staticmethod
    def calculate_confidence(indicators):
        if not indicators:
            return 'Low'
        high_count = sum(1 for i in indicators if i.get('confidence') == 'High')
        if high_count >= 2:
            return 'High'
        elif high_count >= 1:
            return 'Medium'
        return 'Low'