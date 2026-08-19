class TechnologyDetector:
    @staticmethod
    def detect(headers, html):
        detected_tech = []
        server = headers.get("server", "")

        if "nginx" in server.lower():
            detected_tech.append({"name": "Nginx", "type": "Web Server"})
        if "apache" in server.lower():
            detected_tech.append({"name": "Apache", "type": "Web Server"})
        if "IIS" in server:
            detected_tech.append({"name": "Microsoft IIS", "type": "Web Server"})

        if "__NEXT_DATA__" in html:
            detected_tech.append({"name": "Next.js", "type": "Frontend Framework"})
        if "wp-content" in html or "wp-includes" in html:
            detected_tech.append({"name": "WordPress", "type": "CMS"})
        if "laravel_session" in html or "laravel" in html.lower():
            detected_tech.append({"name": "Laravel", "type": "Backend Framework"})
        if "django" in html.lower():
            detected_tech.append({"name": "Django", "type": "Backend Framework"})
        if "react" in html.lower():
            detected_tech.append({"name": "React", "type": "Frontend Framework"})
        if "vue" in html.lower():
            detected_tech.append({"name": "Vue.js", "type": "Frontend Framework"})
            
        return detected_tech