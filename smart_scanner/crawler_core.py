import asyncio
import re
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

from utils.scope_guard import ScopeGuard


class URLNormalizer:
    @staticmethod
    def normalize(url, base_url):
        if not url:
            return None

        full_url = urljoin(base_url, url)
        parsed = urlparse(full_url)

        if not parsed.scheme or not parsed.netloc:
            return None

        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path.rstrip('/') if parsed.path not in ('', '/') else '/'

        query_params = parse_qs(parsed.query, keep_blank_values=True)
        ignore_params = ['utm_source', 'utm_medium', 'utm_campaign', 'fbclid']
        sorted_params = {key: value for key, value in sorted(query_params.items()) if key not in ignore_params}
        query = urlencode(sorted_params, doseq=True)

        return urlunparse((scheme, netloc, path, parsed.params, query, ''))


class AsyncCrawlerEngine:
    def __init__(self, config, status_callback=None, scope_guard=None):
        self.config = config or {}
        self.config.setdefault('max_depth', self.config.get('max_depth', 3))
        self.config.setdefault('max_pages', self.config.get('max_pages', 20))
        self.config.setdefault('concurrency', self.config.get('concurrency', 3))
        self.config.setdefault('headless', self.config.get('headless', True))
        self.status_callback = status_callback
        self.scope_guard = scope_guard or ScopeGuard()
        self.visited_urls = set()
        self.pending_urls = set()
        self.discovered_forms = []
        self.discovered_params = set()
        self.is_running = False
        self.urls = []
        self.depth_map = {}
        self.scope_blocked = 0

    async def log(self, message):
        if self.status_callback:
            await self.status_callback(message)
        else:
            print(message)

    def is_in_scope(self, url, target_url):
        if not url:
            return False

        target_domain = urlparse(target_url).netloc
        url_domain = urlparse(url).netloc

        static_extensions = ['.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.ico', '.pdf', '.woff', '.svg', '.woff2']
        if any(url.lower().endswith(ext) for ext in static_extensions):
            return False

        # Kiểm tra scope guard (allowlist, denylist, local lab mode)
        if not self.scope_guard.is_allowed(url):
            self.scope_blocked += 1
            return False

        return target_domain == url_domain

    def extract_csrf_token(self, html):
        if not html:
            return None

        patterns = [
            r'name=["\']csrf_token["\'][^>]*value=["\']([^"\']+)',
            r'name=["\']_csrf["\'][^>]*value=["\']([^"\']+)',
            r'csrf-token["\']\s*content=["\']([^"\']+)',
            r'csrfToken["\']\s*[:=]["\']([^"\']+)',
        ]

        for pattern in patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(1)
        return None

    def build_request_headers(self):
        headers = {
            'User-Agent': self.config.get('user_agent', "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Upgrade-Insecure-Requests': '1',
        }
        headers.update(self.config.get('extra_headers', {}))
        return headers

    async def extract_forms(self, html, url):
        soup = BeautifulSoup(html, 'html.parser')
        forms = []
        for form_tag in soup.find_all('form'):
            action = form_tag.get('action', '')
            method = form_tag.get('method', 'GET').upper()
            inputs = []
            for input_tag in form_tag.find_all(['input', 'textarea', 'select']):
                name = input_tag.get('name')
                if name:
                    inputs.append({
                        'name': name,
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', '')
                    })
                    self.discovered_params.add(name)

            forms.append({
                'source_page': url,
                'action': urljoin(url, action),
                'method': method,
                'inputs': inputs
            })
        return forms

    async def crawl_page(self, context, url, target_url, depth=0):
        if not url or url in self.visited_urls:
            return

        # Kiểm tra scope guard
        if not self.scope_guard.is_allowed(url):
            self.scope_blocked += 1
            await self.log(f"🚫 URL ngoài scope: {url}")
            return

        max_pages = self.config.get('max_pages', 20)
        if len(self.visited_urls) >= max_pages:
            return

        self.visited_urls.add(url)
        self.depth_map[url] = depth
        self.urls.append(url)
        await self.log(f"🔍 Đang thu thập: {url}")

        page = await context.new_page()
        try:
            headers = self.build_request_headers()
            await context.set_extra_http_headers(headers)
            await page.goto(url, wait_until='networkidle', timeout=15000)
            await asyncio.sleep(self.config.get('delay', 0.3))

            html = await page.content()
            forms = await self.extract_forms(html, url)
            self.discovered_forms.extend(forms)

            csrf_token = self.extract_csrf_token(html)
            if csrf_token:
                self.config.setdefault('csrf_token', csrf_token)

            if depth >= self.config.get('max_depth', 3):
                return

            soup = BeautifulSoup(html, 'html.parser')
            for a_tag in soup.find_all('a', href=True):
                norm_url = URLNormalizer.normalize(a_tag['href'], url)
                if norm_url and self.is_in_scope(norm_url, target_url) and norm_url not in self.visited_urls:
                    self.pending_urls.add(norm_url)

            parsed_url = urlparse(url)
            if parsed_url.query:
                for param in parse_qs(parsed_url.query).keys():
                    self.discovered_params.add(param)

        except Exception as e:
            await self.log(f"❌ Lỗi tại {url}: {str(e)}")
        finally:
            await page.close()

    async def start(self, target_url):
        self.is_running = True
        self.visited_urls.clear()
        self.pending_urls.clear()
        self.discovered_forms.clear()
        self.discovered_params.clear()
        self.urls.clear()
        self.scope_blocked = 0

        normalized_target = URLNormalizer.normalize(target_url, target_url)
        if not normalized_target:
            raise ValueError(f"URL không hợp lệ: {target_url}")

        # Kiểm tra scope guard cho target chính
        if not self.scope_guard.is_allowed(normalized_target):
            raise PermissionError(
                f"Target bị chặn bởi Scope Guard: {normalized_target}. "
                f"Vui lòng kiểm tra allowlist hoặc bật Local Lab Mode."
            )

        self.pending_urls.add(normalized_target)
        await self.log("🚀 Khởi chạy Headless Browser...")

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=self.config.get('headless', True))
            context = await browser.new_context(
                user_agent=self.config.get('user_agent', "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"),
                extra_http_headers=self.build_request_headers(),
                java_script_enabled=True,
            )

            if self.config.get('auth_enabled'):
                await self.log("🔑 Đang tiến hành đăng nhập...")
                login_page = await context.new_page()
                try:
                    await login_page.goto(self.config.get('login_url'))
                    csrf_token = self.extract_csrf_token(await login_page.content())
                    if csrf_token:
                        self.config['csrf_token'] = csrf_token

                    if self.config.get('username') and self.config.get('password'):
                        await login_page.fill(f"input[name='{self.config.get('user_field')}']", self.config.get('username'))
                        await login_page.fill(f"input[name='{self.config.get('pass_field')}']", self.config.get('password'))
                        if self.config.get('csrf_field'):
                            await login_page.fill(f"input[name='{self.config.get('csrf_field')}']", csrf_token or '')
                        await login_page.click("input[type='submit'], button[type='submit'], button")
                        await asyncio.sleep(3)
                        await self.log("✅ Đăng nhập hoàn tất")
                except Exception as e:
                    await self.log(f"⚠️ Đăng nhập thất bại: {str(e)}")
                finally:
                    await login_page.close()

            while self.pending_urls and len(self.visited_urls) < self.config.get('max_pages', 20) and self.is_running:
                chunk = [self.pending_urls.pop() for _ in range(min(len(self.pending_urls), self.config.get('concurrency', 3)))]
                tasks = [self.crawl_page(context, url, normalized_target, depth=self.depth_map.get(url, 0) + 1) for url in chunk]
                await asyncio.gather(*tasks)

            await browser.close()

        await self.log("🏁 Quá trình thu thập đã kết thúc!")
        self.is_running = False
        return {
            'urls': list(self.visited_urls),
            'parameters': list(self.discovered_params),
            'forms': self.discovered_forms,
            'scope_blocked': self.scope_blocked,
        }