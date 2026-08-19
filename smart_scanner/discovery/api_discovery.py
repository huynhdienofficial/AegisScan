from urllib.parse import urlparse

class APIDiscovery:
    def __init__(self):
        self.api_endpoints = set()

    async def attach(self, page):
        page.on("request", lambda request: self.capture_request(request))
        page.on("response", lambda response: self.capture_response(response))

    def capture_request(self, request):
        url = request.url
        keywords = ["/api/", "/graphql", "/rest/", "/v1/", "/v2/", "/v3/", "/json", "/xml"]
        
        if any(k in url.lower() for k in keywords):
            self.api_endpoints.add((request.method, url))

    def capture_response(self, response):
        content_type = response.headers.get("content-type", "")
        if "application/json" in content_type or "application/xml" in content_type:
            self.api_endpoints.add((response.request.method, response.url))

    def get_discovered_apis(self):
        return [{"method": m, "url": u} for m, u in self.api_endpoints]