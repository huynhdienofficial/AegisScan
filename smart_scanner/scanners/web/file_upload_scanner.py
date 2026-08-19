"""
File Upload Vulnerability Testing — theo đặc tả v3.1 §19.7 (Feature List #81).

Kiểm tra upload shell trá hình qua double extension, null byte, MIME/Content-Type bypass.
Evidence-only: không lưu webshell thật trên hệ thống đích.
"""
import base64
import hashlib
import json
import time


class FileUploadScanner:
    """Quét lỗ hổng file upload."""

    def __init__(self, request_handler, upload_url=None, upload_field='file'):
        self.request_handler = request_handler
        self.upload_url = upload_url
        self.upload_field = upload_field
        self.findings = []

    # Payload test files — chỉ dùng để test xác nhận, không phải webshell thật
    TEST_FILES = [
        {
            'name': 'test.php',
            'content': '<?php echo "TEST_UPLOAD"; ?>',
            'content_type': 'application/x-php',
            'desc': 'PHP shell trá hình (direct)',
            'severity': 'High',
        },
        {
            'name': 'test.jpg.php',
            'content': 'GIF89a<?php echo "TEST_UPLOAD"; ?>',
            'content_type': 'image/jpeg',
            'desc': 'Double extension bypass (.jpg.php)',
            'severity': 'High',
        },
        {
            'name': 'test.php%00.jpg',
            'content': '<?php echo "TEST_UPLOAD"; ?>',
            'content_type': 'image/jpeg',
            'desc': 'Null byte injection bypass',
            'severity': 'High',
        },
        {
            'name': 'test.jpeg',
            'content': 'GIF89a',
            'content_type': 'image/jpeg',
            'desc': 'Magic number chỉ là ảnh (control test)',
            'severity': 'Info',
        },
    ]

    def _build_multipart(self, filename, content, content_type):
        """Xây dựng multipart/form-data request thủ công."""
        boundary = f"----WebKitFormBoundary{hashlib.md5(str(int(time.time())).encode()).hexdigest()[:16]}"
        parts = [
            f"--{boundary}\r\n",
            f'Content-Disposition: form-data; name="{self.upload_field}"; filename="{filename}"\r\n',
            f"Content-Type: {content_type}\r\n\r\n",
            content,
            "\r\n",
            f"--{boundary}--\r\n",
        ]
        body = ''.join(parts).encode('utf-8')
        content_type_header = f"multipart/form-data; boundary={boundary}"
        return body, content_type_header

    async def scan(self):
        """Chạy toàn bộ file upload scan.

        LƯU Ý: `request_handler.send_request()` là async (aiohttp) — trước
        đây hàm này KHÔNG `await`, nên `resp` chỉ là coroutine chưa chạy và
        scanner luôn kết luận "an toàn" bất kể server thật có chấp nhận file
        test hay không. Đã sửa: chuyển sang async/await.
        """
        if not self.upload_url:
            return {'vulnerabilities': [], 'note': 'Không có upload URL để test'}

        all_findings = []
        for test_file in self.TEST_FILES:
            body, content_type = self._build_multipart(
                test_file['name'], test_file['content'], test_file['content_type']
            )

            try:
                resp = await self.request_handler.send_request(
                    'POST',
                    self.upload_url,
                    data=body,
                    headers={'Content-Type': content_type},
                )
                status = getattr(resp, 'status_code', 0)
                text = getattr(resp, 'text', '')

                # File PHP được chấp nhận (status 200/201/302) → lỗ hổng
                if test_file['severity'] == 'Info':
                    continue  # Control test — không tạo finding

                if status in (200, 201, 202, 204, 302, 303):
                    all_findings.append({
                        'type': 'File Upload Bypass',
                        'severity': test_file['severity'],
                        'detail': (
                            f"{test_file['desc']}: file '{test_file['name']}' "
                            f"được server chấp nhận (HTTP {status})"
                        ),
                        'confidence': 'Medium',
                        'payload': test_file['name'],
                        'url': self.upload_url,
                    })
                elif 'error' in text.lower() and 'type' in text.lower():
                    # Server chặn đúng loại file → an toàn
                    pass
            except Exception:
                continue

        return {'vulnerabilities': all_findings}