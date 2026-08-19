"""
Phân tích rủi ro chi tiết cho từng loại lỗ hổng.
Giải thích mức độ nguy hiểm, ảnh hưởng, và khuyến nghị khắc phục.
"""


class RiskAnalyzer:
    """Phân tích chi tiết mức độ nguy hiểm của từng finding."""

    VULNERABILITY_INFO = {
        'SQL': {
            'name': 'SQL Injection (SQLi)',
            'severity': 'Critical',
            'color': '#dc2626',
            'impact': 'Cao',
            'cwe': 'CWE-89',
            'owasp': 'A03:2021 - Injection',
            'description': (
                'Kẻ tấn công có thể chèn mã SQL trái phép vào các truy vấn cơ sở dữ liệu. '
                'Điều này cho phép chúng đọc, sửa, xóa dữ liệu nhạy cảm, hoặc thậm chí '
                'giành quyền điều khiển toàn bộ hệ thống database.'
            ),
            'risks': [
                'Đánh cắp dữ liệu nhạy cảm (username, password, thông tin khách hàng)',
                'Xóa hoặc sửa dữ liệu gây mất tính toàn vẹn',
                'Vượt qua xác thực đăng nhập (Authentication Bypass)',
                'Thực thi lệnh hệ điều hành (trong một số trường hợp)',
                'Chiếm quyền điều khiển toàn bộ máy chủ database'
            ],
            'recommendations': [
                'Sử dụng Parameterized Queries / Prepared Statements',
                'Sử dụng ORM (SQLAlchemy, Django ORM, Hibernate...) thay vì nối chuỗi SQL',
                'Validate và sanitize tất cả dữ liệu đầu vào',
                'Nguyên tắc Least Privilege cho tài khoản database',
                'Sử dụng WAF (Web Application Firewall) như layer phòng thủ thêm'
            ],
            'example': "payload: ' OR 1=1--  →  bypass đăng nhập",
        },
        'XSS': {
            'name': 'Cross-Site Scripting (XSS)',
            'severity': 'High',
            'color': '#f97316',
            'impact': 'Trung bình-Cao',
            'cwe': 'CWE-79',
            'owasp': 'A03:2021 - Injection',
            'description': (
                'Kẻ tấn công có thể chèn mã JavaScript độc hại vào trang web, khiến trình duyệt '
                'của người dùng thực thi mã này. Mã độc có thể đánh cắp thông tin đăng nhập, '
                'phiên làm việc (session), hoặc thao túng nội dung trang.'
            ),
            'risks': [
                'Đánh cắp session cookie → chiếm tài khoản người dùng',
                'Đánh cắp thông tin nhập liệu (keylogger)',
                'Phát tán mã độc đến người dùng khác (stored XSS)',
                'Thao túng/tống tiền người dùng (phishing)',
                'Thực hiện các hành động thay mặt người dùng (CSRF)'
            ],
            'recommendations': [
                'Encode tất cả dữ liệu đầu ra theo context (HTML, JS, URL, CSS...)',
                'Sử dụng Content Security Policy (CSP) để chặn script không mong muốn',
                'Validate và sanitize đầu vào (không phụ thuộc hoàn toàn)',
                'Thiết lập HttpOnly + Secure + SameSite=Strict cho cookies',
                'Sử dụng framework có Auto-Escaping (React, Vue, Angular...)'
            ],
            'example': "payload: <script>alert(1)</script>  →  script chạy trong browser nạn nhân",
        },
        'Command Injection': {
            'name': 'Command Injection (RCE)',
            'severity': 'Critical',
            'color': '#dc2626',
            'impact': 'Rất cao',
            'cwe': 'CWE-78',
            'owasp': 'A03:2021 - Injection',
            'description': (
                'Kẻ tấn công có thể thực thi lệnh hệ điều hành trên máy chủ web. '
                'Đây là lỗ hổng nghiêm trọng nhất — cho phép chiếm quyền điều khiển '
                'toàn bộ máy chủ, đọc file nhạy cảm, cài backdoor, hoặc tấn công hệ thống khác.'
            ),
            'risks': [
                'Thực thi lệnh tùy ý trên máy chủ (RCE - Remote Code Execution)',
                'Đọc file nhạy cảm (/etc/passwd, .env, cấu hình)',
                'Cài đặt backdoor/malware trên máy chủ',
                'Đánh cắp toàn bộ dữ liệu hệ thống',
                'Dùng máy chủ làm bàn đạp tấn công hệ thống khác'
            ],
            'recommendations': [
                'KHÔNG BAO GIỜ dùng os.system(), exec(), shell=True với input người dùng',
                'Sử dụng thư viện an toàn cho từng tác vụ cụ thể',
                'Chạy ứng dụng với quyền tối thiểu (non-root)',
                'Container/sandbox hóa môi trường thực thi',
                'Sử dụng allowlist cho các chức năng hệ thống'
            ],
            'example': "payload: ; whoami  →  hiển thị user đang chạy trên server",
        },
        'Time-based Attack': {
            'name': 'Time-based Blind Injection',
            'severity': 'High',
            'color': '#f97316',
            'impact': 'Trung bình',
            'cwe': 'CWE-89 / CWE-78',
            'owasp': 'A03:2021 - Injection',
            'description': (
                'Lỗ hổng tiêm mã mù (blind) được phát hiện qua chênh lệch thời gian phản hồi. '
                'Kẻ tấn công sử dụng SLEEP() hoặc các hàm delay để trích xuất dữ liệu từng ký tự '
                'một mà không cần thấy lỗi hiển thị.'
            ),
            'risks': [
                'Trích xuất dữ liệu từng bit (blind extraction)',
                'Xác nhận lỗ hổng để leo thang tấn công',
                'Gây quá tải database bằng SLEEP payloads'
            ],
            'recommendations': [
                'Sử dụng Parameterized Queries',
                'Giới hạn timeout database query',
                'Đặt rate limiting để giảm tốc độ trích xuất'
            ],
            'example': "payload: ' AND SLEEP(5)--  →  server chậm phản hồi 5 giây",
        },
        'Payload Reflection': {
            'name': 'Payload Reflection (XSS)',
            'severity': 'Medium',
            'color': '#eab308',
            'impact': 'Trung bình',
            'cwe': 'CWE-79',
            'owasp': 'A03:2021 - Injection',
            'description': (
                'Dữ liệu người dùng nhập vào được phản hồi trực tiếp trong trang HTML. '
                'Đây là dấu hiệu của Reflected XSS — đầu vào không được encode đúng cách.'
            ),
            'risks': [
                'Xác nhận tồn tại lỗ hổng phản chiếu dữ liệu',
                'Có thể bị khai thác thành Reflected XSS',
                'Clickjacking kết hợp phishing'
            ],
            'recommendations': [
                'HTML-encode tất cả dữ liệu đầu ra',
                'Sử dụng framework với auto-escaping',
                'Xóa bỏ/thay thế ký tự nguy hiểm (<, >, ", \', &)'
            ],
            'example': "payload: <script>alert(1)</script>  →  echo trong HTML response",
        },
        'SQL Error Message': {
            'name': 'SQL Error Information Disclosure',
            'severity': 'Medium',
            'color': '#eab308',
            'impact': 'Thấp-Trung bình',
            'cwe': 'CWE-209',
            'owasp': 'A05:2021 - Security Misconfiguration',
            'description': (
                'Ứng dụng hiển thị lỗi SQL chi tiết (syntax error, table name, column name) '
                'trong response. Thông tin này giúp kẻ tấn công hiểu cấu trúc database.'
            ),
            'risks': [
                'Lộ cấu trúc database (table/column names)',
                'Hỗ trợ kẻ tấn công xây dựng payload chính xác',
                'Tiết lộ công nghệ sử dụng (MySQL, PostgreSQL...)'
            ],
            'recommendations': [
                'Tắt hiển thị lỗi chi tiết trong production',
                'Log lỗi chi tiết ra file, không hiển thị cho người dùng',
                'Hiển thị error page generic cho người dùng'
            ],
            'example': "Response chứa: 'You have an error in your SQL syntax near...'",
        },
        'Missing Security Header': {
            'name': 'Thiếu Security Headers',
            'severity': 'Medium',
            'color': '#eab308',
            'impact': 'Thấp',
            'cwe': 'CWE-693',
            'owasp': 'A05:2021 - Security Misconfiguration',
            'description': (
                'Trang web thiếu các header bảo mật quan trọng như CSP, HSTS, X-Frame-Options. '
                'Đây không phải lỗ hổng trực tiếp nhưng làm tăng bề mặt tấn công.'
            ),
            'risks': [
                'Không có CSP → dễ bị XSS hơn',
                'Không có HSTS → dễ bị SSL Stripping',
                'Không có X-Frame-Options → dễ bị Clickjacking',
                'Không có X-Content-Type-Options → MIME sniffing'
            ],
            'recommendations': [
                'Thêm Content-Security-Policy header',
                'Thêm Strict-Transport-Security (HSTS)',
                'Thêm X-Frame-Options: DENY hoặc SAMEORIGIN',
                'Thêm X-Content-Type-Options: nosniff',
                'Thêm Referrer-Policy + Permissions-Policy'
            ],
            'example': "Headers cần có: CSP, HSTS, X-Frame-Options, X-Content-Type-Options",
        },
        'Insecure Cookie': {
            'name': 'Cookie bảo mật kém',
            'severity': 'High',
            'color': '#f97316',
            'impact': 'Trung bình',
            'cwe': 'CWE-614',
            'owasp': 'A05:2021 - Security Misconfiguration',
            'description': (
                'Cookie không có các cờ bảo mật cần thiết (Secure, HttpOnly, SameSite). '
                'Cookie có thể bị đánh cắp qua MITM hoặc XSS.'
            ),
            'risks': [
                'Thiếu Secure → cookie gửi qua HTTP không mã hóa',
                'Thiếu HttpOnly → cookie bị đọc bởi JavaScript (XSS)',
                'Thiếu SameSite → dễ bị CSRF'
            ],
            'recommendations': [
                'Thêm Secure flag → chỉ gửi qua HTTPS',
                'Thêm HttpOnly flag → chặn JS đọc cookie',
                'Thêm SameSite=Strict/Lax → chống CSRF',
                'Sử dụng prefix __Host- / __Secure- cho cookie quan trọng'
            ],
            'example': "Cookie: sessionid=abc123  →  cần thành Set-Cookie: sessionid=abc123; Secure; HttpOnly; SameSite=Strict",
        },
    }

    @classmethod
    def get_vuln_info(cls, vuln_type):
        """Lấy thông tin chi tiết cho loại lỗ hổng."""
        for key, info in cls.VULNERABILITY_INFO.items():
            if key.lower() in vuln_type.lower():
                return info
        return None

    @classmethod
    def analyze_finding(cls, finding):
        """Phân tích chi tiết một finding và trả về đánh giá."""
        indicators = finding.get('indicators', [])
        payload = finding.get('payload', '')
        confidence = finding.get('confidence', 'Low')

        # Xác định loại lỗ hổng chính
        vuln_type = indicators[0].get('type', 'Unknown') if indicators else 'Unknown'

        # Tìm thông tin mô tả
        info = cls.get_vuln_info(vuln_type)

        if not info:
            info = {
                'name': vuln_type,
                'severity': confidence,
                'color': '#eab308',
                'impact': 'Không xác định',
                'cwe': 'N/A',
                'owasp': 'N/A',
                'description': 'Loại lỗ hổng chưa được phân loại chi tiết.',
                'risks': ['Cần kiểm tra thêm'],
                'recommendations': ['Phân tích thêm'],
                'example': f'payload: {payload}',
            }

        # Phân tích thêm dựa trên payload
        extra_analysis = cls._analyze_payload(payload)

        return {
            'type': vuln_type,
            'name': info['name'],
            'severity': info['severity'],
            'confidence': confidence,
            'color': info['color'],
            'impact': info['impact'],
            'cwe': info['cwe'],
            'owasp': info['owasp'],
            'description': info['description'],
            'risks': info['risks'],
            'recommendations': info['recommendations'],
            'example': info['example'],
            'extra_analysis': extra_analysis,
        }

    @classmethod
    def _analyze_payload(cls, payload):
        """Phân tích thêm dựa trên payload."""
        analysis = []

        if not payload:
            return analysis

        # SQLi
        if any(k in payload.upper() for k in ['OR 1=1', 'UNION', 'SLEEP', 'SELECT', 'BENCHMARK', 'PG_SLEEP', 'WAITFOR']):
            analysis.append({
                'type': 'sqli',
                'label': '🔥 SQL Injection',
                'explain': (
                    f'Payload `{payload}` chứa các cú pháp SQL nguy hiểm. '
                    'Nếu ứng dụng nối chuỗi SQL trực tiếp, kẻ tấn công có thể '
                    'đọc/sửa/xóa dữ liệu database.'
                ),
                'severity': 'Critical'
            })

        # XSS
        if any(k in payload.lower() for k in ['<script', 'onerror=', 'onload=', 'javascript:', 'alert(']):
            analysis.append({
                'type': 'xss',
                'label': '⚠️ Cross-Site Scripting (XSS)',
                'explain': (
                    f'Payload `{payload}` chứa mã JavaScript. Nếu browser nạn nhân '
                    'thực thi, kẻ tấn công có thể đánh cắp session, đăng nhập thay, '
                    'hoặc phát tán mã độc.'
                ),
                'severity': 'High'
            })

        # Command Injection
        if any(k in payload.lower() for k in ['; ls', '; whoami', '| ls', '&&', '||', '& dir', '; id', 'sleep 5']):
            analysis.append({
                'type': 'rce',
                'label': '💀 Command Injection (RCE)',
                'explain': (
                    f'Payload `{payload}` chứa các ký tự đặc biệt (`;`, `|`, `&`) — '
                    'dấu hiệu của lỗ hổng thực thi lệnh hệ điều hành. Đây là lỗ hổng '
                    'nghiêm trọng nhất, cho phép chiếm quyền máy chủ.'
                ),
                'severity': 'Critical'
            })

        # Path Traversal
        if any(k in payload for k in ['../', '/etc/passwd', '..\\']):
            analysis.append({
                'type': 'path_traversal',
                'label': '📂 Path Traversal',
                'explain': (
                    f'Payload `{payload}` chứa đường dẫn traversal. Nếu ứng dụng không '
                    'kiểm tra, kẻ tấn công có thể đọc file ngoài thư mục cho phép.'
                ),
                'severity': 'High'
            })

        return analysis

    @classmethod
    def assess_overall_risk(cls, findings, passive_findings=None):
        """Đánh giá rủi ro tổng thể với giải thích chi tiết.

        Điểm số delegate sang MultiFactorRiskEngine.calculate_from_findings
        (report_exporters.py) — nguồn tính risk score DUY NHẤT trong toàn bộ
        repo. Trước đây hàm này tự trừ điểm tuyến tính theo số lượng finding
        (critical*25 + high*15 + ...), là 1 trong 4 công thức khác nhau từng
        tồn tại song song, có thể cho điểm khác hẳn công thức MultiFactorRiskEngine
        dùng ở nơi khác cho CÙNG một tập finding.
        """
        from report_exporters import MultiFactorRiskEngine

        passive_findings = passive_findings or []

        # Gắn severity đã suy luận (từ VULNERABILITY_INFO) vào từng active
        # finding trước khi đưa vào MultiFactorRiskEngine, vì engine dùng
        # chung chỉ biết đọc field 'severity'/'confidence' thô.
        active_with_severity = []
        for f in findings:
            confidence = f.get('confidence', 'Low')
            indicators = f.get('indicators', [])
            vuln_type = indicators[0].get('type', 'Unknown') if indicators else 'Unknown'
            info = cls.get_vuln_info(vuln_type)
            severity = info['severity'] if info else confidence
            active_with_severity.append({**f, 'severity': severity})

        all_findings = active_with_severity + list(passive_findings)
        result = MultiFactorRiskEngine.calculate_from_findings(all_findings)
        counts = result['counts']
        critical, high, medium, low = counts['critical'], counts['high'], counts['medium'], counts['low']

        # Quy ước cũ của module này: score cao = an toàn (ngược risk_score).
        score = round(max(0.0, 100.0 - result['risk_score']))

        # Xác định mức độ
        if score >= 90:
            rating = 'A - An Toàn'
            summary = 'Trang web tương đối an toàn. Không phát hiện lỗ hổng nghiêm trọng.'
        elif score >= 75:
            rating = 'B - Nguy Cơ Thấp'
            summary = 'Có một số vấn đề nhỏ cần cải thiện, nhưng chưa nguy hiểm.'
        elif score >= 50:
            rating = 'C - Trung Bình'
            summary = 'Phát hiện các lỗ hổng cần xử lý sớm. Có nguy cơ bị tấn công.'
        else:
            rating = 'D - Nguy Cơ Cao'
            summary = '⚠️ NGHIÊM TRỌNG: Phát hiện lỗ hổng nguy hiểm. Cần khắc phục ngay lập tức!'

        # Tạo danh sách vấn đề chính
        main_issues = []
        for f in findings[:5]:
            analyzed = cls.analyze_finding(f)
            main_issues.append(analyzed)

        return {
            'score': score,
            'rating': rating,
            'summary': summary,
            'metrics': {
                'critical': critical,
                'high': high,
                'medium': medium,
                'low': low,
            },
            'main_issues': main_issues,
        }