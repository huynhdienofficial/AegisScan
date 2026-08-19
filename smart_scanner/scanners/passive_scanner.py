class SecurityHeaderScanner:
    REQUIRED_HEADERS = {
        "content-security-policy",
        "strict-transport-security",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy"
    }

    @staticmethod
    def scan(headers):
        findings = []
        existing = {h.lower() for h in headers.keys()}
        missing = SecurityHeaderScanner.REQUIRED_HEADERS - existing

        for item in missing:
            findings.append({
                "severity": "Medium",
                "type": "Missing Security Header",
                "detail": f"Thiếu header: {item}"
            })
        return findings

class CookieScanner:
    @staticmethod
    def scan(cookies):
        findings = []
        for cookie in cookies:
            if not cookie.get("secure"):
                findings.append({
                    "severity": "High",
                    "type": "Insecure Cookie",
                    "detail": f"Cookie '{cookie.get('name', 'unknown')}' thiếu cờ Secure"
                })
            if not cookie.get("httpOnly"):
                findings.append({
                    "severity": "Medium",
                    "type": "Insecure Cookie",
                    "detail": f"Cookie '{cookie.get('name', 'unknown')}' thiếu cờ HttpOnly"
                })
        return findings