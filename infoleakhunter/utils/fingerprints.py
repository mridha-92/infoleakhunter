from __future__ import annotations

import re
from typing import Any


class TechFingerprinter:
    PATTERNS: dict[str, list[tuple[re.Pattern[str], str]]] = {
        "server": [
            (re.compile(r"nginx/([\d.]+)", re.I), "Nginx"),
            (re.compile(r"apache(?:/([\d.]+))?", re.I), "Apache"),
            (re.compile(r"iis/([\d.]+)", re.I), "IIS"),
            (re.compile(r"openresty/([\d.]+)", re.I), "OpenResty"),
            (re.compile(r"cloudflare", re.I), "Cloudflare"),
            (re.compile(r"awselb", re.I), "AWS ELB"),
            (re.compile(r"gunicorn", re.I), "Gunicorn"),
            (re.compile(r"uvicorn", re.I), "Uvicorn"),
            (re.compile(r"waitress", re.I), "Waitress"),
            (re.compile(r"caddy", re.I), "Caddy"),
            (re.compile(r"lighttpd", re.I), "Lighttpd"),
            (re.compile(r"tomcat", re.I), "Tomcat"),
            (re.compile(r"jetty", re.I), "Jetty"),
            (re.compile(r"wildfly", re.I), "WildFly"),
            (re.compile(r"jboss", re.I), "JBoss"),
            (re.compile(r"weblogic", re.I), "WebLogic"),
            (re.compile(r"websphere", re.I), "WebSphere"),
        ],
        "x-powered-by": [
            (re.compile(r"php/([\d.]+)", re.I), "PHP"),
            (re.compile(r"asp\.net", re.I), "ASP.NET"),
            (re.compile(r"express", re.I), "Express"),
            (re.compile(r"django", re.I), "Django"),
            (re.compile(r"flask", re.I), "Flask"),
            (re.compile(r"rails", re.I), "Rails"),
            (re.compile(r"laravel", re.I), "Laravel"),
            (re.compile(r"symfony", re.I), "Symfony"),
            (re.compile(r"cakephp", re.I), "CakePHP"),
            (re.compile(r"codeigniter", re.I), "CodeIgniter"),
            (re.compile(r"yii", re.I), "Yii"),
            (re.compile(r"node\.?js", re.I), "Node.js"),
            (re.compile(r"python", re.I), "Python"),
            (re.compile(r"java", re.I), "Java"),
            (re.compile(r"ruby", re.I), "Ruby"),
            (re.compile(r"go", re.I), "Go"),
        ],
        "html": [
            (re.compile(r"<meta[^>]+name=\"?generator\"?[^>]+content=\"?([^\">]+)", re.I), "CMS Generator"),
            (re.compile(r"wp-content", re.I), "WordPress"),
            (re.compile(r"wp-includes", re.I), "WordPress"),
            (re.compile(r"joomla", re.I), "Joomla"),
            (re.compile(r"drupal", re.I), "Drupal"),
            (re.compile(r"magento", re.I), "Magento"),
            (re.compile(r"shopify", re.I), "Shopify"),
            (re.compile(r"prestashop", re.I), "PrestaShop"),
            (re.compile(r"modx", re.I), "MODX"),
            (re.compile(r"wix", re.I), "Wix"),
            (re.compile(r"squarespace", re.I), "Squarespace"),
            (re.compile(r"webflow", re.I), "Webflow"),
            (re.compile(r"ghost", re.I), "Ghost"),
            (re.compile(r"hubspot", re.I), "HubSpot"),
            (re.compile(r"laravel", re.I), "Laravel"),
            (re.compile(r"csrf-token", re.I), "CSRF Protection"),
            (re.compile(r"__VIEWSTATE", re.I), "ASP.NET ViewState"),
        ],
        "cookies": [
            (re.compile(r"PHPSESSID", re.I), "PHP"),
            (re.compile(r"JSESSIONID", re.I), "Java/J2EE"),
            (re.compile(r"ASPSESSIONID", re.I), "ASP"),
            (re.compile(r"ASP\.NET_SessionId", re.I), "ASP.NET"),
            (re.compile(r"laravel_session", re.I), "Laravel"),
            (re.compile(r"ci_session", re.I), "CodeIgniter"),
            (re.compile(r"django_session", re.I), "Django"),
            (re.compile(r"flask", re.I), "Flask"),
            (re.compile(r"rails", re.I), "Rails"),
            (re.compile(r"wordpress", re.I), "WordPress"),
            (re.compile(r"wp-settings", re.I), "WordPress"),
        ],
    }

    def __init__(self) -> None:
        self.detected: dict[str, list[str]] = {}

    def fingerprint(self, headers: dict[str, str], body: str = "", cookies: dict[str, str] | None = None) -> dict[str, list[str]]:
        results: dict[str, list[str]] = {}

        for header_name, patterns in self.PATTERNS.items():
            if header_name == "server":
                value = headers.get("Server", "")
                for pattern, tech in patterns:
                    if pattern.search(value):
                        results.setdefault("servers", []).append(tech)

            elif header_name == "x-powered-by":
                value = headers.get("X-Powered-By", "")
                for pattern, tech in patterns:
                    if pattern.search(value):
                        results.setdefault("frameworks", []).append(tech)

            elif header_name == "html":
                for pattern, tech in patterns:
                    if pattern.search(body):
                        results.setdefault("cms", []).append(tech)

            elif header_name == "cookies" and cookies:
                for cookie_name in cookies:
                    for pattern, tech in patterns:
                        if pattern.search(cookie_name):
                            results.setdefault("frameworks", []).append(tech)

        for h in ["X-AspNet-Version", "X-AspNetMvc-Version", "X-Drupal-Cache", "X-Drupal-Dynamic-Cache",
                   "X-Drupal-Route", "X-Varnish", "X-Cache", "X-Cache-Hit", "CF-Ray", "CF-Cache-Status"]:
            if h in headers:
                results.setdefault("infrastructure", []).append(f"{h}: {headers[h]}")

        self.detected = results
        return results

    def get_summary(self) -> str:
        lines = []
        for category, items in self.detected.items():
            lines.append(f"{category.title()}: {', '.join(set(items))}")
        return "; ".join(lines)
