import argparse
import httpx
import asyncio
import csv
import hashlib
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import urllib3
import sys
import time
import re
import random
import socket
import logging
import difflib
from typing import List, Dict, Optional, Set, Tuple, Callable
from tqdm import tqdm

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    C_GREEN = Fore.GREEN
    C_RED = Fore.RED
    C_YELLOW = Fore.YELLOW
    C_CYAN = Fore.CYAN
    C_MAGENTA = Fore.MAGENTA
    C_BLUE = Fore.BLUE
    C_WHITE = Fore.WHITE
    C_RESET = Style.RESET_ALL
except ImportError:
    C_GREEN = C_RED = C_YELLOW = C_CYAN = C_MAGENTA = C_BLUE = C_WHITE = C_RESET = ""

def print_rainbow(text):
    if not C_GREEN:
        print(text)
        return
    colors = [Fore.RED, Fore.YELLOW, Fore.GREEN, Fore.CYAN, Fore.BLUE, Fore.MAGENTA]
    for i, line in enumerate(text.splitlines()):
        rainbow_line = ""
        # Desplazamos el color inicial por cada línea para un efecto diagonal
        for j, char in enumerate(line):
            color = colors[(i + j) % len(colors)]
            rainbow_line += color + char
        print(rainbow_line)

CONTRALORIA_BANNER = r"""
  ____ ___  _   _ _____ ____     _     _     ___  ____  ___    _     
 / ___/ _ \| \ | |_   _|  _ \   / \   | |   / _ \|  _ \|_ _|  / \    
| |  | | | |  \| | | | | |_) | / _ \  | |  | | | | |_) || |  / _ \   
| |__| |_| | |\  | | | |  _ < / ___ \ | |__| |_| |  _ < | | / ___ \  
 \____\___/|_| \_| |_| |_| \_/_/   \_\|_____\___/|_| \_\___/_/   \_\ 
                                                                     
 ___ _   _ _____ _____ ____  _   _     _                             
|_ _| \ | |_   _| ____|  _ \| \ | |   / \                            
 | ||  \| | | | |  _| | |_) |  \| |  / _ \                           
 | || |\  | | | | |___|  _ <| |\  | / ___ \                          
|___|_| \_| |_| |_____|_| \_|_| \_|/_/   \_\                         
"""

# Desactivar advertencias SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Rutas por defecto (las más críticas y comunes)
DEFAULT_ROUTES = [
    "/wp-login.php",
    "/wp-admin/",
    "/wp-admin/index.php",
    "/wp-admin/options.php",
    "/wp-admin/options-general.php",
    "/wp-admin/options-writing.php",
    "/wp-admin/options-reading.php",
    "/wp-admin/users.php",
    "/wp-admin/user-edit.php",
    "/wp-admin/profile.php",
    "/wp-admin/plugins.php",
    "/wp-admin/plugin-install.php",
    "/wp-admin/admin-ajax.php",
    "/wp-admin/themes.php",
    "/wp-admin/theme-editor.php",
    "/wp-admin/plugin-editor.php",
    "/wp-admin/post.php",
    "/wp-admin/post-new.php",
    "/wp-admin/edit.php",
    "/wp-admin/upload.php",
    "/wp-admin/media-new.php",
    "/wp-json/",
    "/wp-json/wp/v2/users",
    "/wp-json/wp/v2/posts",
    "/xmlrpc.php",
    "/wp-cron.php",
    "/wp-comments-post.php",
    "/readme.html",
    "/license.txt",
    "/wp-config.php.bak",
    "/wp-config.bak",
    "/wp-config.php.save",
    "/wp-config.php.old",
    "/wp-config.php.txt",
    "/wp-config.old",
    "/wp-config.save",
    "/debug.log",
    "/.env",
    "/.git/config",
    "/wp-config.php.swp",
    "/wp-config.php~",
    "/wp-config.txt",
    "/backup.sql",
    "/database.sql",
    "/dump.sql",
    "/info.php",
    "/phpinfo.php",
    "/test.php",
    "/i.php",
    "/php.php",
    "/p.php",
    "/status.php",
    "/check.php",
    "/.htaccess",
    "/.user.ini",
    "/php.ini",
    "/web.config",
    "/error_log",
    "/error.log",
    "/robots.txt",
    "/sitemap.xml",
    "/composer.json",
    "/package.json",
    "/wp-config.php.dist",
    "/.ssh/id_rsa",
    "/.ssh/id_rsa.pub",
    "/wp-cli.yml",
    "/.wp-cli/config.yml"
]

KEYWORDS = [
    "ajax action",
    "rest_cannot_view",
    "login_error",
    "wp-core",
    "phpinfo()",
    "PHP Version",
    "System Information",
    "Configuration",
    "Environment Variables",
    "MYSQL_ROOT_PASSWORD",
    "DB_PASSWORD",
    "SSH_PRIVATE_KEY"
]

WAF_SIGNATURES = {
    "Cloudflare": ["cloudflare", "__cfduid", "cf-ray"],
    "Sucuri": ["sucuri/cloudproxy", "x-sucuri-id"],
    "Wordfence": ["wordfence"],
    "Akamai": ["akamai", "x-akamai-transformed"],
    "Imperva": ["incapsula", "x-iinfo"]
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1"
]

TEXT_CONTENT_TYPES = (
    "text/",
    "application/json",
    "application/xml",
    "application/xhtml+xml",
    "application/javascript",
    "application/x-javascript",
)

ARCHIVE_CONTENT_TYPES = (
    "application/zip",
    "application/x-zip-compressed",
    "application/gzip",
    "application/x-gzip",
    "application/x-tar",
    "application/sql",
    "application/octet-stream",
)

# Firmas de plugins populares para detección pasiva mejorada
PLUGINS_SIGNATURES = {
    "Contact Form 7": ["wp-contact-form-7", "contact-form-7"],
    "Yoast SEO": ["yoast-seo", "wp-seo"],
    "Elementor": ["elementor"],
    "WooCommerce": ["woocommerce"],
    "Wordfence": ["wordfence"],
    "All in One SEO": ["all-in-one-seo"],
    "Jetpack": ["jetpack"],
    "W3 Total Cache": ["w3-total-cache"],
    "Akismet": ["akismet"],
    "WPForms": ["wpforms"],
    "UpdraftPlus": ["updraftplus"]
}

# Diccionario de plugins populares para escaneo activo
POPULAR_PLUGINS = [
    "contact-form-7", "woocommerce", "elementor", "yoast-seo", "wpforms-lite",
    "classic-editor", "all-in-one-wp-migration", "wordpress-seo", "jetpack", "akismet",
    "wordfence", "advanced-custom-fields", "updraftplus", "wp-super-cache", "w3-total-cache",
    "really-simple-ssl", "google-analytics-for-wordpress", "duplicate-post", "mailchimp-for-wp",
    "wp-mail-smtp", "ninja-forms", "loco-translate", "wp-fastest-cache", "regenerate-thumbnails",
    "broken-link-checker", "cookie-law-info", "essential-addons-for-elementor-lite", "tablepress",
    "tinymce-advanced", "duplicator", "wp-pagenavi", "disable-comments", "wp-statistics",
    "wp-file-manager", "autoptimize", "easy-updates-manager", "smart-slider-3", "mailpoet",
    "custom-post-type-ui", "insert-headers-and-footers", "post-types-order", "page-builder-by-siteorigin",
    "simple-page-ordering", "svg-support", "polylang", "redirection", "shortcodes-ultimate",
    "backwpup", "admin-menu-editor", "ultimate-member", "header-footer-elementor", "wps-hide-login",
    "smtp-mailer", "seo-by-rank-math", "better-search-replace", "user-role-editor", "siteorigin-panels",
    "all-in-one-wp-security-and-firewall", "super-socializer", "woocommerce-pdf-invoices-packing-slips",
    "yith-woocommerce-wishlist", "mailchimp-for-woocommerce", "stripe", "woocommerce-services",
    "facebook-for-woocommerce", "wp-smushit", "contact-form-cfdb7", "custom-css-js", "add-to-any",
    "lazy-load", "regenerate-thumbnails-advanced", "secure-db-connection", "xml-sitemap-feed",
    "acf-quick-edit-fields", "wp-maintenance-mode", "maintenance", "coming-soon", "meta-slider",
    "hustle-pro", "loginizer", "wp-crontrol", "query-monitor", "schema-markup-rich-snippets",
    "health-check", "wp-optimize", "ssl-zen", "simple-custom-css", "custom-sidebars",
    "foobox-image-lightbox-free", "sticky-menu-or-anything-on-scroll", "post-grid",
    "wp-restaurant-price-list", "amp", "real-media-library-lite", "elementskit-lite",
    "woo-gutenberg-products-block", "envira-gallery-lite", "simple-social-buttons"
]

class WPAuditor:
    def __init__(self, base_url, wordlist_path=None, output_csv=None, threads=5, delay=0, jitter=0, nvd_key=None, verify_ssl=False, on_progress=None, req_timeout=6):
        self.base_url = base_url.rstrip("/") + "/"
        self.output_csv = output_csv
        self.threads = threads
        self.delay = delay
        self.jitter = jitter
        self.nvd_key = nvd_key
        self.verify_ssl = verify_ssl
        self.on_progress = on_progress
        self.req_timeout = max(3, int(req_timeout))  # Timeout configurable (default 6s)
        
        # Cabeceras base legítimas.
        self.headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept-Language": "en-US,en;q=0.9,es;q=0.8",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Connection": "keep-alive",
            "Referer": self.base_url
        }
        
        # El cliente asíncrono se inicializa en run() o externamente para controlar su ciclo de vida
        self.client = None
        
        self.soft_404_len = -1
        self.soft_404_signatures = []
        self.results = []
        self.detected_technologies = []
        self.detected_plugins_passive = []
        self.request_cache = {}
        self.cve_cache = {}
        self.cooldown_until = 0
        self.generic_redirect_patterns = set() # Para detectar Redirect-404 (falsos positivos de redirección)
        self.filtered_redirects = 0 # Contador de ruidos filtrados
        self.is_wordpress = False  # Se establece en True durante recon() si se confirma WordPress
        self.req_timeout = max(3, int(req_timeout))  # Timeout configurable (default 6s)
        self._nvd_rate_limited = False  # Pausa reactiva NVD solo si recibe 429
        
        if wordlist_path:
            self.routes = self.load_wordlist(wordlist_path)
        else:
            self.routes = list(dict.fromkeys(DEFAULT_ROUTES))
            # Expandir con backups dinámicos
            self.routes.extend(self.generate_backup_routes())
            self.routes = list(dict.fromkeys(self.routes))

    def log_progress(self, message: str):
        if self.on_progress:
            try:
                self.on_progress(message)
            except Exception:
                pass

    def load_wordlist(self, path: str) -> List[str]:
        try:
            with open(path, "r", encoding="utf-8") as f:
                return [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except Exception as e:
            print(f"{C_RED}[!] Error leyendo wordlist: {e}{C_RESET}")
            sys.exit(1)

    def generate_backup_routes(self) -> List[str]:
        """Genera rutas de backup basadas en el nombre del dominio"""
        domain = urlparse(self.base_url).netloc.split(":")[0]
        site_name = domain.split(".")[0]
        extensions = [".zip", ".tar.gz", ".sql", ".sql.gz", ".bak", ".old", ".tar"]
        names = [site_name, domain, "backup", "wordpress", "wp", "db", "site"]
        
        backups = []
        for name in names:
            for ext in extensions:
                backups.append(f"/{name}{ext}")
                backups.append(f"/backup-{name}{ext}")
        return list(set(backups))

    async def analyze_robots_txt(self):
        """Extrae rutas de robots.txt y las añade al escaneo si no están."""
        url = urljoin(self.base_url, "robots.txt")
        try:
            r = await self.safe_request("GET", url, timeout=5)
            if r and r.status_code == 200:
                print(f"    {C_CYAN}[*] Analizando robots.txt para extraer rutas...{C_RESET}")
                disallowed = re.findall(r'Disallow:\s*(.*)', r.text, re.IGNORECASE)
                added_count = 0
                for path in disallowed:
                    path = path.strip()
                    if path and path != "/" and path not in self.routes:
                        self.routes.append(path)
                        added_count += 1
                if added_count > 0:
                    print(f"        {C_GREEN}[+] Se añadieron {added_count} rutas nuevas desde robots.txt{C_RESET}")
        except Exception:
            pass

    async def test_wp_cli(self):
        """Verifica exposición de configuración de WP-CLI."""
        print(f"\n{C_CYAN}[*] --- Fase Extra: Configuración de WP-CLI ---{C_RESET}")
        paths = ["wp-cli.yml", ".wp-cli/config.yml"]
        found = False
        for path in paths:
            url = urljoin(self.base_url, path)
            try:
                r = await self.safe_request("GET", url, timeout=5)
                if r and r.status_code == 200 and ("path:" in r.text or "url:" in r.text):
                    print(f"    {C_RED}[!] ¡Alerta! Configuración de WP-CLI expuesta en: {url}{C_RESET}")
                    self.results.append({"Module": "WP-CLI", "Endpoint": url, "Status": r.status_code, "Size": len(r.content), "Findings": "Configuración WP-CLI expuesta"})
                    found = True
            except Exception:
                pass
        if not found:
            print(f"    {C_GREEN}[+] No se detectó configuración de WP-CLI expuesta.{C_RESET}")

    def get_title(self, html):
        try:
            soup = BeautifulSoup(html, "html.parser")
            return soup.title.string.strip() if soup.title and soup.title.string else ""
        except Exception:
            return ""

    def analyze_keywords(self, text):
        found = []
        for kw in KEYWORDS:
            if kw in text:
                found.append(kw)
        return ", ".join(found)

    async def sleep_with_jitter(self):
        if self.delay > 0:
            actual_delay = self.delay
            if self.jitter > 0:
                # Calculate delay with +/- jitter percentage
                variation = self.delay * (self.jitter / 100.0)
                actual_delay = random.uniform(max(0, self.delay - variation), self.delay + variation)
            await asyncio.sleep(actual_delay)

    async def sleep_if_cooling_down(self):
        wait_time = self.cooldown_until - time.time()
        if wait_time > 0:
            await asyncio.sleep(wait_time)

    def apply_response_backoff(self, response: httpx.Response):
        if response.status_code not in (429, 503):
            return

        retry_after = response.headers.get("Retry-After")
        wait_seconds = 4
        if retry_after:
            try:
                wait_seconds = min(max(int(retry_after), 2), 30)
            except ValueError:
                wait_seconds = 8

        self.cooldown_until = max(self.cooldown_until, time.time() + wait_seconds)
        print(f"    {C_YELLOW}[-] Servidor pide bajar ritmo ({response.status_code}). Pausa prudente de {wait_seconds}s.{C_RESET}")

    def request_headers(self, extra: Optional[Dict] = None) -> Dict:
        """Cabeceras por peticion sin suplantar IP ni identidad de proxy."""
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        if extra:
            headers.update(extra)
        return headers

    def header_value_int(self, headers: Dict, name: str) -> Optional[int]:
        value = headers.get(name)
        if not value:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def is_textual_response(self, headers: Dict) -> bool:
        content_type = headers.get("Content-Type", "").lower()
        return any(content_type.startswith(prefix) for prefix in TEXT_CONTENT_TYPES)

    def is_archive_like_response(self, url: str, headers: Dict) -> bool:
        content_type = headers.get("Content-Type", "").lower().split(";")[0].strip()
        path = urlparse(url).path.lower()
        archive_ext = path.endswith((".zip", ".tar", ".tar.gz", ".tgz", ".gz", ".sql", ".sql.gz", ".bak", ".old"))
        return archive_ext or content_type in ARCHIVE_CONTENT_TYPES

    def should_fetch_body(self, url: str, headers: Dict, max_bytes: int = 262144) -> bool:
        if not self.is_textual_response(headers):
            return False
        content_length = self.header_value_int(headers, "Content-Length")
        if content_length is not None and content_length > max_bytes:
            return False
        if self.is_archive_like_response(url, headers) and "text/html" in headers.get("Content-Type", "").lower():
            return False
        return True

    async def head_or_get_headers(self, url: str, **kwargs) -> Optional[httpx.Response]:
        """Usa HEAD para existencia y cae a GET si el servidor no soporta HEAD."""
        response = await self.safe_request("HEAD", url, **kwargs)
        if response and response.status_code not in (405, 501):
            return response
        fallback_kwargs = dict(kwargs)
        fallback_headers = dict(fallback_kwargs.get("headers") or {})
        fallback_headers.setdefault("Range", "bytes=0-65535")
        fallback_kwargs["headers"] = fallback_headers
        return await self.safe_request("GET", url, **fallback_kwargs)

    def check_waf(self, headers: Dict) -> str:
        headers_str = str(headers).lower()
        for waf, signatures in WAF_SIGNATURES.items():
            for sig in signatures:
                if sig in headers_str:
                    return f"{C_YELLOW}{waf}{C_RESET}"
        return "No detectado"

    def detect_wp_version(self, html):
        match = re.search(r'<meta name="generator" content="WordPress (.*?)"', html, re.IGNORECASE)
        if match:
            return match.group(1)
        # Fallback: buscar la versión en los parámetros de scripts/estilos estáticos
        match_ver = re.search(r'wp-includes/.*?\?ver=([\d\.]+)', html)
        if match_ver:
            return f"{match_ver.group(1)} (Extraída de scripts estáticos)"
        return "Desconocida"

    def extract_asset_versions(self, html: str) -> Dict[str, str]:
        """Extrae versiones pasivas de assets /wp-content/plugins/<slug>/...?ver=x."""
        versions = {}
        pattern = re.compile(r'/wp-content/plugins/([^/]+)/[^"\']+[?&]ver=([A-Za-z0-9._-]+)', re.IGNORECASE)
        for plugin, version in pattern.findall(html):
            versions.setdefault(plugin, version)
        return versions

    def add_technology(self, technologies: List[Dict], name: str, category: str, evidence: str,
                       version: str = "", confidence: int = 80, icon: str = "", color: str = "64748b"):
        """Agrega una tecnologia evitando duplicados por nombre/categoria."""
        name = (name or "").strip()
        if not name:
            return

        normalized_name = name.lower()
        normalized_category = category.lower()
        for tech in technologies:
            if tech["name"].lower() == normalized_name and tech["category"].lower() == normalized_category:
                if confidence > tech["confidence"]:
                    tech["confidence"] = confidence
                    tech["evidence"] = evidence
                if version and not tech.get("version"):
                    tech["version"] = version
                return

        technologies.append({
            "name": name,
            "category": category,
            "version": version or "",
            "confidence": max(0, min(confidence, 100)),
            "evidence": evidence,
            "icon": icon,
            "color": color,
        })

    def build_technology_inventory(self, headers: Dict, html: str, server_header: str, powered_by: str,
                                   waf: str, wp_version: str, php_version: str, themes: Set[str],
                                   plugins_info: List[str], js_contents: List[Tuple[str, str]] = None) -> List[Dict]:
        technologies = []
        html_lower = html.lower()
        headers_lower = str(headers).lower()
        js_lower = ""
        if js_contents:
            js_lower = "\n".join(content.lower() for _, content in js_contents)

        server_catalog = [
            ("nginx", "Nginx", "nginx", "009639"),
            ("apache", "Apache", "apache", "d22128"),
            ("litespeed", "LiteSpeed", "litespeed", "1f7a8c"),
            ("microsoft-iis", "Microsoft IIS", "microsoft", "0078d7"),
            ("openresty", "OpenResty", "openresty", "00a3a3"),
        ]
        for signature, label, icon, color in server_catalog:
            if signature in server_header.lower():
                self.add_technology(technologies, label, "Servidor web", f"Header Server: {server_header}", confidence=95, icon=icon, color=color)
                break

        if powered_by != "Desconocido" and "php" not in powered_by.lower():
            icon = "php" if "php" in powered_by.lower() else ""
            color = "777bb4" if icon else "64748b"
            self.add_technology(technologies, powered_by, "Backend", f"Header X-Powered-By: {powered_by}", confidence=85, icon=icon, color=color)

        if php_version != "Desconocida":
            self.add_technology(technologies, "PHP", "Lenguaje backend", f"Version detectada en headers: {php_version}", version=php_version, confidence=90, icon="php", color="777bb4")

        if wp_version != "Desconocida":
            version = wp_version.replace(" (ExtraÃ­da de scripts estÃ¡ticos)", "")
            self.add_technology(technologies, "WordPress", "CMS", f"Meta generator o assets de WordPress: {wp_version}", version=version, confidence=95, icon="wordpress", color="21759b")
        elif "wp-content" in html_lower or "wp-includes" in html_lower:
            self.add_technology(technologies, "WordPress", "CMS", "Rutas wp-content/wp-includes presentes en el HTML", confidence=85, icon="wordpress", color="21759b")

        clean_waf = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', waf)
        if clean_waf and "no detectado" not in clean_waf.lower():
            waf_icon = "cloudflare" if "cloudflare" in clean_waf.lower() else ""
            waf_color = "f38020" if waf_icon else "e11d48"
            self.add_technology(technologies, clean_waf, "WAF / Proxy", "Firmas detectadas en headers HTTP", confidence=90, icon=waf_icon, color=waf_color)

        if "cloudflare" in headers_lower:
            self.add_technology(technologies, "Cloudflare", "CDN / Proxy", "Headers HTTP contienen Cloudflare", confidence=95, icon="cloudflare", color="f38020")

        library_signatures = [
            ("jquery", "jQuery", "Frontend JS", "jquery", "0769ad"),
            ("bootstrap", "Bootstrap", "Framework CSS", "bootstrap", "7952b3"),
            ("react", "React", "Frontend JS", "react", "61dafb"),
            ("vue", "Vue.js", "Frontend JS", "vuedotjs", "4fc08d"),
            ("angular", "Angular", "Frontend JS", "angular", "dd0031"),
            ("gtag/js", "Google Analytics", "Analitica", "googleanalytics", "e37400"),
            ("google-analytics.com", "Google Analytics", "Analitica", "googleanalytics", "e37400"),
            ("googletagmanager.com", "Google Tag Manager", "Analitica", "googletagmanager", "246fdb"),
            ("recaptcha", "Google reCAPTCHA", "Seguridad", "googlerecaptcha", "4285f4"),
            ("font-awesome", "Font Awesome", "Iconos", "fontawesome", "538dd7"),
        ]
        for signature, label, category, icon, color in library_signatures:
            is_present = signature in html_lower
            if not is_present and js_lower:
                if signature == "react" and ("react.production" in js_lower or "react.development" in js_lower or ("react" in js_lower and "reactdom" in js_lower)):
                    is_present = True
                elif signature == "jquery" and "jquery" in js_lower:
                    is_present = True
                elif signature in js_lower:
                    is_present = True
            
            if is_present:
                self.add_technology(technologies, label, category, f"Firma de librería/asset detectada: {signature}", confidence=75, icon=icon, color=color)

        # Detección de frameworks avanzados y tecnologías no-WordPress (tanto por headers/cookies como por HTML)
        advanced_catalog = [
            # Nombre, Categoría, Icono, Color (SimpleIcons), Confianza, Header Signatures, HTML/JS Signatures
            ("Streamlit", "Framework UI (Python)", "streamlit", "FF4B4B", 90,
             ["streamlit"], ["window.streamlit", "class=\"stapp\"", "id=\"root\" class=\"stapp\"", "streamlit-container", "/static/js/main."]),
            
            ("Flask", "Framework Backend (Python)", "flask", "000000", 85,
             ["werkzeug", "flask", "gunicorn"], ["flask", "werkzeug"]),
            
            ("Django", "Framework Backend (Python)", "django", "092E20", 90,
             ["csrftoken", "sessionid"], ["csrfmiddlewaretoken", "name=\"csrfmiddlewaretoken\""]),
            
            ("Laravel", "Framework Backend (PHP)", "laravel", "FF2D20", 90,
             ["laravel_session", "laravel_token"], ["name=\"_token\"", "laravel-assets", "laravel_session"]),
            
            ("Next.js", "Framework React", "nextdotjs", "000000", 95,
             [], ["/_next/static/", "__next_data__", "id=\"__next\""]),
            
            ("Nuxt.js", "Framework Vue", "nuxtdotjs", "00C58E", 95,
             [], ["__nuxt__", "data-n-head"]),
            
            ("Gatsby", "Framework React (Estático)", "gatsby", "663399", 95,
             [], ["id=\"___gatsby\"", "gatsby-image-wrapper"]),

            ("Express", "Framework Backend (Node.js)", "express", "000000", 85,
             ["express", "connect.sid"], []),
             
            ("ASP.NET", "Framework Backend", "dotnet", "512BD4", 90,
             ["asp.net", "x-aspnet"], ["__viewstate", "__eventvalidation", "aspnet_sessionid"]),

            ("Ruby on Rails", "Framework Backend", "rubyonrails", "CC0000", 90,
             ["_session_id", "x-runtime", "x-rack-cache"], ["csrf-param", "csrf-token", "rails-assets"]),

            ("Spring Boot", "Framework Backend (Java)", "springboot", "6DB33F", 85,
             ["jsessionid"], ["thymeleaf", "spring-boot"]),
        ]

        for name, category, icon, color, confidence, header_sigs, html_sigs in advanced_catalog:
            header_matched = False
            for sig in header_sigs:
                if sig.lower() in headers_lower:
                    header_matched = True
                    self.add_technology(technologies, name, category, f"Header HTTP/Cookie contiene firma: {sig}", confidence=confidence, icon=icon, color=color)
                    break
            
            if not header_matched:
                for sig in html_sigs:
                    if sig.lower() in html_lower or (js_lower and sig.lower() in js_lower):
                        self.add_technology(technologies, name, category, f"HTML/JS contiene firma: {sig}", confidence=confidence - 5, icon=icon, color=color)
                        break

        # Detección de HTTP/3 a partir de la cabecera Alt-Svc
        alt_svc = headers.get("Alt-Svc", headers.get("alt-svc", ""))
        if "h3" in alt_svc.lower():
            self.add_technology(technologies, "HTTP/3", "Protocolo de Red", "Cabecera Alt-Svc contiene soporte h3", confidence=100, icon="", color="0052cc")

        # Detección de Open Graph
        if "property=\"og:" in html_lower or "property='og:" in html_lower or "name=\"twitter:" in html_lower:
            self.add_technology(technologies, "Open Graph", "Miscelánea", "Metaetiquetas og: o twitter: presentes en el HTML", confidence=95, icon="", color="0077b5")

        # Detección de Google Fonts / Google Font API
        if "fonts.googleapis.com" in html_lower or "fonts.gstatic.com" in html_lower or "fonts.googleapis.com" in js_lower or "fonts.gstatic.com" in js_lower:
            self.add_technology(technologies, "Google Font API", "Tipografía", "Tipografías cargadas desde fonts.googleapis.com o fonts.gstatic.com", confidence=95, icon="googlefonts", color="4285f4")

        # Detección de Google Maps
        if "maps.google.com" in html_lower or "maps.googleapis.com" in html_lower or "google.com/maps/embed" in html_lower or "/maps/api/js" in html_lower or "google.com/maps/embed" in js_lower or "maps.googleapis.com" in js_lower:
            self.add_technology(technologies, "Google Maps", "Mapa / Geolocalización", "Enlace, script o iframe de Google Maps detectado", confidence=95, icon="googlemaps", color="4285f4")

        # Detección de Hostinger
        is_hostinger = False
        hostinger_sigs = ["x-hostinger-tracking", "x-hostinger-hosting", "hostinger"]
        for h in hostinger_sigs:
            if h in headers_lower:
                is_hostinger = True
                break
        if not is_hostinger:
            for k, v in headers.items():
                if "hostinger" in str(v).lower():
                    is_hostinger = True
                    break
        if is_hostinger:
            self.add_technology(technologies, "Hostinger", "Alojamiento", "Firma o cabecera de Hostinger en headers HTTP", confidence=95, icon="hostinger", color="673de6")

        # Detección de Tailwind CSS
        if "--tw-" in html_lower or "tailwind.config" in html_lower or "tailwind.css" in html_lower or "tailwindcss" in html_lower or (js_lower and ("tailwindcss" in js_lower or "--tw-" in js_lower)):
            self.add_technology(technologies, "Tailwind CSS", "Framework CSS", "Atributos CSS (--tw-) o cargador de Tailwind detectados", confidence=90, icon="tailwindcss", color="06b6d4")

        # Detección de Material UI (MUI)
        if re.search(r'class=["\'][^"\']*Mui[A-Z]', html) or "mui-theme" in html_lower or "@mui/material" in html_lower or (js_lower and ("@mui/" in js_lower or "mui.com/production-error" in js_lower)):
            self.add_technology(technologies, "Material UI", "UI Frameworks", "Clases CSS o firmas JS de Material UI detectadas", confidence=90, icon="mui", color="007fff")

        # Detección de Emotion (CSS-in-JS)
        if "data-emotion=" in html_lower or "data-emotion-css=" in html_lower or (js_lower and ("@emotion/" in js_lower or "emotion-css" in js_lower)):
            self.add_technology(technologies, "Emotion", "Librería CSS-in-JS", "Uso de estilo data-emotion o firmas de Emotion detectadas", confidence=95, icon="emotion", color="db7093")

        # Detección de React Router
        if "reactrouter" in html_lower or "react-router" in html_lower or "router-conn" in html_lower or (js_lower and ("react-router" in js_lower or "routercontext" in js_lower)):
            self.add_technology(technologies, "React Router", "Librería JS", "Carga de referencias o chunks de React Router en el HTML/assets", confidence=85, icon="reactrouter", color="ca4245")

        # Detección de otros frameworks frontend JS
        if "svelte-" in html_lower or "__svelte" in html_lower or (js_lower and "svelte-" in js_lower):
            self.add_technology(technologies, "Svelte", "Frontend JS", "Uso de atributos o clases svelte- detectado", confidence=90, icon="svelte", color="ff3e00")

        if "x-data=" in html_lower or "x-init=" in html_lower or "alpine" in html_lower or (js_lower and "alpine.js" in js_lower):
            self.add_technology(technologies, "Alpine.js", "Frontend JS", "Presencia de directivas x-data o librerías de Alpine.js", confidence=95, icon="alpinedotjs", color="8bc0d0")

        if "preact" in html_lower or (js_lower and "preact" in js_lower):
            self.add_technology(technologies, "Preact", "Frontend JS", "Firmas encontradas en el HTML/assets: preact", confidence=85, icon="preact", color="673ab8")

        if "solid-js" in html_lower or "solidjs" in html_lower or (js_lower and ("solid-js" in js_lower or "solidjs" in js_lower)):
            self.add_technology(technologies, "SolidJS", "Frontend JS", "Referencias a SolidJS encontradas en HTML/bundles", confidence=85, icon="solid", color="4f74b9")

        # Astro
        if "astro-" in html_lower or "astro-island" in html_lower or (js_lower and "astro" in js_lower):
            self.add_technology(technologies, "Astro", "Framework Frontend", "Etiquetas astro- o componentes astro-island en el HTML/JS", confidence=95, icon="astro", color="ff5d01")

        # Remix
        if "remix-run" in html_lower or "window.__remixManifest" in html_lower or (js_lower and "remix" in js_lower):
            self.add_technology(technologies, "Remix", "Framework Frontend", "Presencia de configuración window.__remixManifest en el HTML/JS", confidence=95, icon="remix", color="000000")

        # Alojamiento Vercel
        if "x-vercel-id" in headers_lower or "x-vercel-cache" in headers_lower or headers.get("Server", "").lower() == "vercel":
            self.add_technology(technologies, "Vercel", "Alojamiento / CDN", "Cabeceras HTTP x-vercel o servidor Vercel detectados", confidence=95, icon="vercel", color="000000")

        # Alojamiento Netlify
        if "x-nf-request-id" in headers_lower or "netlify" in headers_lower or headers.get("Server", "").lower() == "netlify":
            self.add_technology(technologies, "Netlify", "Alojamiento / CDN", "Cabecera x-nf-request-id o servidor Netlify detectados", confidence=95, icon="netlify", color="00c7b7")

        # GitHub Pages
        if "x-github-request-id" in headers_lower or "github.io" in html_lower or headers.get("Server", "").lower() == "github.io":
            self.add_technology(technologies, "GitHub Pages", "Alojamiento", "Servidor o URL del dominio github.io detectados", confidence=95, icon="github", color="181717")

        # AWS
        aws_sigs = ["amz-sdk-js", "x-amz-cf-id", "x-amz-request-id", "amazonaws.com"]
        aws_matched = False
        for sig in aws_sigs:
            if sig in headers_lower or sig in html_lower or (js_lower and sig in js_lower):
                aws_matched = True
                break
        if aws_matched:
            self.add_technology(technologies, "Amazon Web Services", "Alojamiento / Infraestructura", "Detección de firmas y cabeceras x-amz de AWS", confidence=85, icon="amazonwebservices", color="232f3e")

        plugin_icons = {
            "woocommerce": ("WooCommerce", "woocommerce", "96588a"),
            "elementor": ("Elementor", "elementor", "92003b"),
            "yoast": ("Yoast SEO", "yoast", "a61e69"),
            "wordfence": ("Wordfence", "", "f59e0b"),
            "jetpack": ("Jetpack", "", "00be28"),
            "contact-form-7": ("Contact Form 7", "", "0ea5e9"),
            "wpforms": ("WPForms", "", "f97316"),
            "akismet": ("Akismet", "automattic", "00aadc"),
        }
        for plugin in plugins_info:
            raw_name = re.sub(r'\s*\(.*?\)', '', plugin).strip()
            version_match = re.search(r'\(v([^,\)]+)', plugin)
            version = version_match.group(1).strip() if version_match else ""
            slug = raw_name.lower()
            friendly_name, icon, color = plugin_icons.get(slug, (raw_name.replace("-", " ").title(), "", "64748b"))
            self.add_technology(technologies, friendly_name, "Plugin WordPress", f"Detectado en rutas/assets de plugins: {raw_name}", version=version, confidence=80, icon=icon, color=color)

        for theme in themes:
            self.add_technology(technologies, theme, "Tema WordPress", f"Ruta wp-content/themes/{theme}/ detectada", confidence=80, icon="wordpress", color="21759b")

        return sorted(technologies, key=lambda item: (item["category"], item["name"]))

    def build_soft_404_signature(self, response: httpx.Response) -> Dict:
        body = response.content or b""
        sample = body[:1200]
        text_sample = sample.decode("utf-8", errors="ignore")
        return {
            "status": response.status_code,
            "length": len(body),
            "title": self.get_title(text_sample),
            "hash": hashlib.sha256(sample).hexdigest(),
            "sample": text_sample,
        }

    async def establish_soft_404_signatures(self, samples: int = 4):
        self.soft_404_signatures = []
        for _ in range(samples):
            random_path = f"test-404-check-{random.randint(100000,999999)}-{random.randint(100000,999999)}/"
            response = await self.safe_request("GET", urljoin(self.base_url, random_path), timeout=self.req_timeout)
            if not response:
                continue
            if response.status_code == 200:
                self.soft_404_signatures.append(self.build_soft_404_signature(response))
            elif response.status_code in (301, 302):
                loc = response.headers.get("Location", "")
                pattern = loc.split("?")[0] if "?" in loc else loc
                self.generic_redirect_patterns.add(pattern)
                self.generic_redirect_patterns.add(pattern.replace("https://", "").replace("http://", ""))

        if self.soft_404_signatures:
            first = self.soft_404_signatures[0]
            self.soft_404_len = first["length"]
            self.soft_404_content = first["sample"].encode("utf-8", errors="ignore")

    async def safe_request(self, method: str, url: str, **kwargs) -> Optional[httpx.Response]:
        """Realiza una petición con reintentos y manejo de errores asíncronos."""
        cache_response = kwargs.pop("cache_response", True)
        method_upper = method.upper()
        cache_key = None
        
        # httpx usa follow_redirects en lugar de allow_redirects
        follow_redirects = kwargs.pop("follow_redirects", kwargs.pop("allow_redirects", True))
        kwargs["follow_redirects"] = follow_redirects
        
        # Asegurar cabeceras legítimas y preservar/inyectar User-Agent del navegador
        req_headers = kwargs.get("headers", {})
        if not req_headers:
            req_headers = self.headers.copy()
        else:
            # Heredar campos de self.headers (como User-Agent) si no están en las custom
            merged = self.headers.copy()
            merged.update(req_headers)
            req_headers = merged
        kwargs["headers"] = req_headers
        
        if cache_response and method_upper in ("GET", "HEAD"):
            cache_key = (
                method_upper,
                url,
                bool(follow_redirects),
                tuple(sorted((kwargs.get("headers") or {}).items())),
            )
            if cache_key in self.request_cache:
                return self.request_cache[cache_key]

        max_retries = 2
        for attempt in range(max_retries):
            try:
                await self.sleep_if_cooling_down()
                await self.sleep_with_jitter()
                
                if not self.client:
                    async with httpx.AsyncClient(verify=self.verify_ssl) as client:
                        response = await client.request(method, url, **kwargs)
                else:
                    response = await self.client.request(method, url, **kwargs)
                    
                self.apply_response_backoff(response)
                if cache_key and response.status_code not in (429, 503):
                    self.request_cache[cache_key] = response
                return response
            except (httpx.RequestError, socket.timeout) as e:
                if attempt == max_retries - 1:
                    print(f"    {C_RED}[ERR] Fallo final en {url}: {type(e).__name__} {e}{C_RESET}")
                    return None
                await asyncio.sleep(2 ** attempt)
        return None

    def is_soft_404(self, content: bytes) -> bool:
        """Determina si una respuesta es un Soft-404 por similitud estructural."""
        if not self.soft_404_signatures and (not hasattr(self, 'soft_404_content') or not self.soft_404_content):
            return False
        if self.soft_404_signatures:
            sample = content[:1200]
            sample_text = sample.decode("utf-8", errors="ignore")
            sample_hash = hashlib.sha256(sample).hexdigest()
            title_curr = self.get_title(sample_text)
            for signature in self.soft_404_signatures:
                size_diff = abs(len(content) - signature["length"])
                if sample_hash == signature["hash"]:
                    return True
                if size_diff < 80:
                    return True
                if title_curr and signature["title"] and title_curr == signature["title"] and size_diff < 750:
                    return True
                if size_diff < 500:
                    ratio = difflib.SequenceMatcher(None, sample_text, signature["sample"]).ratio()
                    if ratio > 0.85:
                        return True
            return False
        
        # Comparación rápida por tamaño primero (tolerancia aumentada)
        size_diff = abs(len(content) - self.soft_404_len)
        if size_diff < 80:
            return True
            
        # Comparación de similitud si el tamaño es cercano
        if size_diff < 500:
            # Comparar títulos primero ya que es sumamente rápido
            try:
                title_curr = self.get_title(content[:3000].decode('utf-8', errors='ignore'))
                title_soft = self.get_title(self.soft_404_content[:3000].decode('utf-8', errors='ignore'))
                if title_curr and title_soft and title_curr == title_soft:
                    return True
            except Exception:
                pass
                
            # Usar una muestra de contenido reducida para acelerar difflib
            sample_size = 800
            try:
                s = difflib.SequenceMatcher(None, content[:sample_size].decode('utf-8', errors='ignore'), 
                                            self.soft_404_content[:sample_size].decode('utf-8', errors='ignore'))
                if s.ratio() > 0.85:
                    return True
            except Exception:
                pass
        return False

    async def check_cve_wpvulnerability(self, software: str, version: str) -> Optional[str]:
        """Consulta la base de datos de WPVulnerability.net para WordPress core, plugins y temas."""
        if not version or "desconocid" in version.lower() or "extraída" in version.lower():
            return ""

        # Determinar tipo y slug
        is_wp_core = software.lower() == "wordpress"
        is_theme = "theme" in software.lower() or (hasattr(self, "detected_themes") and software in self.detected_themes)
        
        # Limpiar slug
        slug = software.lower().strip()
        if "theme" in slug:
            slug = slug.replace("wordpress theme", "").strip()
        elif "plugin" in slug:
            slug = slug.replace("wordpress plugin", "").strip()
        
        slug = slug.replace(" ", "-")

        cache_key = (f"{slug}_wpv", version.lower().strip())
        if cache_key in self.cve_cache:
            print(f"    {C_CYAN}[*] CVEs (WPVulnerability) para {software} (v{version}) reutilizados desde cache local.{C_RESET}")
            return self.cve_cache[cache_key]

        print(f"    {C_CYAN}[*] Consultando CVEs para {software} (v{version}) en WPVulnerability...{C_RESET}")

        if is_wp_core:
            url = f"https://www.wpvulnerability.net/core/{version}/"
        elif is_theme:
            url = f"https://www.wpvulnerability.net/theme/{slug}/"
        else:
            url = f"https://www.wpvulnerability.net/plugin/{slug}/"

        headers = self.request_headers()
        try:
            r = await self.safe_request("GET", url, headers=headers, timeout=10)
            if r and r.status_code == 200:
                data = r.json()
                if data.get("error") == 0:
                    payload = data.get("data", {})
                    vulns = payload.get("vulnerability", []) if is_wp_core else payload.get("vulnerabilities", [])
                    
                    if not vulns:
                        print(f"        {C_GREEN}[+] WPVulnerability: No se encontraron vulnerabilidades para {software} {version}.{C_RESET}")
                        self.cve_cache[cache_key] = "Sin CVEs conocidos"
                        return "Sin CVEs conocidos"

                    findings = []
                    active_vulns = []
                    
                    if is_wp_core:
                        active_vulns = vulns
                    else:
                        for v in vulns:
                            operator = v.get("operator", {})
                            if self.is_version_vulnerable_wpv(version, operator):
                                active_vulns.append(v)
                                
                    if not active_vulns:
                        print(f"        {C_GREEN}[+] WPVulnerability: No se encontraron vulnerabilidades activas en la versión {version}.{C_RESET}")
                        self.cve_cache[cache_key] = "Sin CVEs conocidos"
                        return "Sin CVEs conocidos"
                        
                    print(f"        {C_RED}[!] WPVulnerability: Se encontraron {len(active_vulns)} vulnerabilidades aplicables.{C_RESET}")
                    
                    for v in active_vulns[:3]:
                        name = v.get("name", "Vulnerabilidad sin nombre")
                        sources = v.get("source", [])
                        cve_id = "CVE-Desconocido"
                        link = ""
                        if sources:
                            cve_id = sources[0].get("id", "CVE-Desconocido")
                            link = sources[0].get("link", "")
                            
                        score = "N/A"
                        impact = v.get("impact", {})
                        if impact:
                            cvss3 = impact.get("cvss3", {})
                            if cvss3:
                                score = str(cvss3.get("score", "N/A"))
                            else:
                                cvss2 = impact.get("cvss2", {})
                                if cvss2:
                                    score = str(cvss2.get("score", "N/A"))
                                    
                        finding_str = f"[{software}] {cve_id} (CVSS: {score}) - {name}"
                        if link:
                            finding_str += f" | {link}"
                        findings.append(finding_str)
                        print(f"        {C_YELLOW}--> [{software}] {cve_id} | Peligrosidad: {score} | {name}{C_RESET}")
                        
                    if len(active_vulns) > 3:
                        findings.append(f"... y {len(active_vulns)-3} más")
                        
                    self.cve_cache[cache_key] = "CVEs: " + " | ".join(findings)
                    return self.cve_cache[cache_key]
            elif r and r.status_code in [403, 404]:
                print(f"        [-] WPVulnerability: Recurso no registrado (Status: {r.status_code}). Intentando fallbacks...")
        except Exception as e:
            print(f"        [-] Error al consultar WPVulnerability: {e}. Intentando fallbacks...")
            
        return None

    def is_version_vulnerable_wpv(self, version_str: str, op: dict) -> bool:
        """Determina si una versión de plugin es vulnerable en base a operadores."""
        if not version_str or not op:
            return False
            
        def parse_v(v_str):
            parts = []
            for part in re.split(r'[^0-9]', str(v_str)):
                if part.isdigit():
                    parts.append(int(part))
            return tuple(parts)
            
        try:
            v = parse_v(version_str)
            
            min_v_str = op.get("min_version")
            if min_v_str:
                min_v = parse_v(min_v_str)
                min_op = op.get("min_operator") or "ge"
                if min_op == "gt" and not (v > min_v):
                    return False
                elif min_op == "ge" and not (v >= min_v):
                    return False
                elif min_op == "eq" and not (v == min_v):
                    return False
            
            max_v_str = op.get("max_version")
            if max_v_str:
                max_v = parse_v(max_v_str)
                max_op = op.get("max_operator") or "le"
                if max_op == "lt" and not (v < max_v):
                    return False
                elif max_op == "le" and not (v <= max_v):
                    return False
                elif max_op == "eq" and not (v == max_v):
                    return False
            
            return True
        except Exception:
            return True

    async def check_cve_osv(self, software: str, version: str) -> Optional[str]:
        """Consulta la base de datos de OSV (Open Source Vulnerabilities) de Google."""
        if not version or "desconocid" in version.lower() or "extraída" in version.lower():
            return ""

        cache_key = (software.lower().strip() + "_osv", version.lower().strip())
        if cache_key in self.cve_cache:
            print(f"    {C_CYAN}[*] CVEs (OSV) para {software} (v{version}) reutilizados desde cache local.{C_RESET}")
            return self.cve_cache[cache_key]

        print(f"    {C_CYAN}[*] Consultando CVEs para {software} (v{version}) en OSV.dev...{C_RESET}")

        if software.lower() == "wordpress":
            package_name = "wordpress/wordpress"
            ecosystem = "Packagist"
        else:
            package_name = software.lower().strip()
            ecosystem = "Packagist"

        payload = {
            "version": version.strip(),
            "package": {
                "name": package_name,
                "ecosystem": ecosystem
            }
        }
        url = "https://api.osv.dev/v1/query"
        
        try:
            r = await self.safe_request("POST", url, json=payload, cache_response=False)
            if r and r.status_code == 200:
                data = r.json()
                vulns = data.get("vulns", [])
                if not vulns:
                    return None
                    
                findings = []
                for v in vulns[:3]:
                    vuln_id = v.get("id", "Desconocido")
                    summary = v.get("summary", v.get("details", ""))
                    score = "N/A"
                    severity_list = v.get("severity", [])
                    if severity_list:
                        for sev in severity_list:
                            if "CVSS" in str(sev.get("type", "")):
                                score = str(sev.get("score", "N/A"))
                                break
                    aliases = v.get("aliases", [])
                    cve_alias = next((a for a in aliases if a.startswith("CVE-")), None)
                    display_id = cve_alias if cve_alias else vuln_id
                    link = f"https://osv.dev/vulnerability/{vuln_id}"
                    
                    findings.append(f"[{software}] {display_id} (CVSS: {score}) - {summary[:50]}")
                    print(f"        {C_YELLOW}--> [{software}] {display_id} | Peligrosidad: {score} | {link}{C_RESET}")
                    
                if len(vulns) > 3:
                    findings.append(f"... y {len(vulns)-3} más")
                    
                self.cve_cache[cache_key] = "CVEs: " + " | ".join(findings)
                return self.cve_cache[cache_key]
        except Exception:
            pass
            
        return None

    async def check_cve_nvd(self, software: str, version: str) -> str:
        """Consulta vulnerabilidades de forma segura usando WPVulnerability, OSV y NVD de forma escalonada."""
        if not version or "desconocid" in version.lower() or "extraída" in version.lower():
            return ""

        # 1. Probar WPVulnerability API (Específica de WordPress)
        wpv_res = await self.check_cve_wpvulnerability(software, version)
        if wpv_res is not None:
            return wpv_res

        # 2. Probar OSV.dev (General de Open Source)
        osv_res = await self.check_cve_osv(software, version)
        if osv_res is not None:
            return osv_res

        # 3. Fallback a NVD (API NIST oficial)
        return await self.check_cve_nvd_real(software, version)

    async def check_cve_nvd_real(self, software: str, version: str) -> str:
        """Consulta la NVD de NIST para buscar vulnerabilidades (CVEs) asociadas (Fallback)."""
        if not version or "desconocid" in version.lower() or "extraída" in version.lower():
            return ""

        cache_key = (software.lower().strip(), version.lower().strip())
        if cache_key in self.cve_cache:
            print(f"    {C_CYAN}[*] CVEs (NVD Fallback) para {software} (v{version}) reutilizados desde cache local.{C_RESET}")
            return self.cve_cache[cache_key]
            
        print(f"    {C_CYAN}[*] Consultando CVEs para {software} (v{version}) en NVD (NIST Fallback)...{C_RESET}")
        
        search_query = f"{software} {version}".strip()
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={search_query}"
        
        findings = []
        try:
            if self._nvd_rate_limited:
                await asyncio.sleep(6)
                self._nvd_rate_limited = False
            headers = {}
            if self.nvd_key:
                headers["apiKey"] = self.nvd_key
            r = await self.safe_request("GET", url, headers=headers, timeout=15)
            
            if r and r.status_code == 200:
                data = r.json()
                vulns = data.get("vulnerabilities", [])
                if not vulns:
                    print(f"        {C_GREEN}[+] No se encontraron CVEs críticos publicados para {software} {version}.{C_RESET}")
                    self.cve_cache[cache_key] = "Sin CVEs conocidos"
                    return self.cve_cache[cache_key]
                
                print(f"        {C_RED}[!] ¡Alerta! Se encontraron {len(vulns)} vulnerabilidades publicadas.{C_RESET}")
                
                for v in vulns[:3]:
                    cve_id = v.get("cve", {}).get("id", "Desconocido")
                    metrics = v.get("cve", {}).get("metrics", {})
                    score = "N/A"
                    if "cvssMetricV31" in metrics:
                        score = str(metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore", "N/A"))
                    elif "cvssMetricV30" in metrics:
                        score = str(metrics["cvssMetricV30"][0].get("cvssData", {}).get("baseScore", "N/A"))
                    elif "cvssMetricV2" in metrics:
                        score = str(metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore", "N/A"))
                        
                    link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                    
                    finding_str = f"[{software}] {cve_id} (CVSS: {score}) - {link}"
                    findings.append(finding_str)
                    print(f"        {C_YELLOW}--> [{software}] {cve_id} | Peligrosidad: {score} | {link}{C_RESET}")
                
                if len(vulns) > 3:
                    findings.append(f"... y {len(vulns)-3} más")
                
                self.cve_cache[cache_key] = "CVEs: " + " | ".join(findings)
                return self.cve_cache[cache_key]
            elif r and r.status_code in [403, 429]:
                print(f"        {C_YELLOW}[-] Rate limit de NVD superado. Pausa reactiva activada...{C_RESET}")
                self._nvd_rate_limited = True
                self.cve_cache[cache_key] = "Búsqueda omitida (Rate Limit API)"
                return self.cve_cache[cache_key]
            else:
                status_code = r.status_code if r else "None"
                print(f"        {C_YELLOW}[-] NVD API devolvió estado {status_code}{C_RESET}")
                self.cve_cache[cache_key] = "Error en API NVD"
                return self.cve_cache[cache_key]
        except Exception as e:
            print(f"        {C_YELLOW}[-] Error de conexión con NVD: {e}{C_RESET}")
            self.cve_cache[cache_key] = "Error consultando NVD"
            return self.cve_cache[cache_key]

    async def crawl_secondary_pages(self, html_home: str, limit: int = 4) -> Tuple[Set[str], Set[str]]:
        """Extrae enlaces internos de la página principal y busca plugins/temas en ellos."""
        print(f"    {C_CYAN}[*] Buscando enlaces internos para escaneo secundario (Profundidad 1)...{C_RESET}")
        try:
            soup = BeautifulSoup(html_home, "html.parser")
        except Exception:
            return set(), set()
            
        links = set()
        parsed_base = urlparse(self.base_url)
        base_domain = parsed_base.netloc
        
        for a in soup.find_all("a", href=True):
            href = a["href"].split("#")[0].strip()
            if not href:
                continue
            
            parsed_href = urlparse(href)
            is_internal = False
            full_url = ""
            
            if not parsed_href.netloc:
                is_internal = True
                full_url = urljoin(self.base_url, href)
            elif parsed_href.netloc == base_domain:
                is_internal = True
                full_url = href
                
            if is_internal:
                path = parsed_href.path.lower()
                if any(x in path for x in ["wp-admin", "wp-login", "wp-json", "xmlrpc", "feed", "robots.txt", "sitemap"]):
                    continue
                if path.endswith((".pdf", ".zip", ".jpg", ".jpeg", ".png", ".gif", ".css", ".js", ".doc", ".docx", ".xls", ".xlsx")):
                    continue
                
                full_url_clean = full_url.split("?")[0].rstrip("/")
                if full_url_clean != self.base_url.rstrip("/"):
                    links.add(full_url)

        links = list(links)
        if not links:
            print(f"        {C_YELLOW}[-] No se encontraron enlaces internos adicionales en la página principal.{C_RESET}")
            return set(), set()
            
        sample_links = random.sample(links, min(len(links), limit))
        print(f"        {C_GREEN}[+] Encontrados {len(links)} enlaces internos. Analizando {len(sample_links)} de ellos...{C_RESET}")
        
        detected_plugins = set()
        detected_themes = set()
        
        async def fetch_page(url):
            try:
                headers = self.request_headers()
                res = await self.safe_request("GET", url, timeout=self.req_timeout, cache_response=False)
                if res and res.status_code == 200:
                    return res.text
            except Exception:
                pass
            return ""

        # Paralelizar las peticiones de crawling
        results = await asyncio.gather(*(fetch_page(url) for url in sample_links))
        for html in results:
            if html:
                p = re.findall(r'/wp-content/plugins/([^/]+)/', html)
                t = re.findall(r'/wp-content/themes/([^/]+)/', html)
                detected_plugins.update(p)
                detected_themes.update(t)
                    
        if detected_plugins or detected_themes:
            print(f"        {C_GREEN}[+] Detectados en páginas secundarias: {', '.join(detected_plugins) if detected_plugins else 'Ninguno'} | Temas: {', '.join(detected_themes) if detected_themes else 'Ninguno'}{C_RESET}")
        return detected_plugins, detected_themes

    async def recon(self):
        print(f"\n{C_CYAN}[*] --- Fase 1: Reconocimiento Base e Inteligencia ---{C_RESET}")
        try:
            await self.analyze_robots_txt()
            r = await self.safe_request("GET", self.base_url, timeout=self.req_timeout)
            if not r:
                return
            server_header = r.headers.get("Server", "Desconocido")
            powered_by = r.headers.get("X-Powered-By", "Desconocido")
            waf = self.check_waf(r.headers)
            wp_version = self.detect_wp_version(r.text)
            
            # Detección mejorada de OS y PHP
            os_info = "Desconocido"
            php_version = "Desconocida"
            
            # Intentar extraer OS del header Server
            os_match = re.search(r'\((.*?)\)', server_header)
            if os_match:
                os_info = os_match.group(1)
            else:
                for os_sig in ["Ubuntu", "CentOS", "Debian", "Windows", "Linux", "Unix", "FreeBSD"]:
                    if os_sig.lower() in server_header.lower():
                        os_info = os_sig
                        break
 
            # Intentar extraer PHP de X-Powered-By o Server
            php_match = re.search(r'PHP/([\d\.]+)', f"{server_header} {powered_by}")
            if php_match:
                php_version = php_match.group(1)
            elif "php" in powered_by.lower():
                php_version = powered_by
 
            # Detección pasiva de Plugins y Temas (Extendido)
            plugins = set(re.findall(r'/wp-content/plugins/([^/]+)/', r.text))
            themes = set(re.findall(r'/wp-content/themes/([^/]+)/', r.text))
            
            # Crawling de profundidad 1 (páginas secundarias)
            secondary_plugins, secondary_themes = await self.crawl_secondary_pages(r.text)
            plugins.update(secondary_plugins)
            themes.update(secondary_themes)
            
            asset_versions = self.extract_asset_versions(r.text)
            self.detected_themes = list(themes)

            # Confirmar si el sitio es WordPress
            wp_signatures = [
                wp_version and "Desconocida" not in wp_version,
                bool(plugins),
                bool(themes),
                "/wp-content/" in r.text,
                "/wp-includes/" in r.text,
                "wp-json" in r.text,
            ]
            self.is_wordpress = any(wp_signatures)
            if self.is_wordpress:
                print(f"    {C_GREEN}[+] WordPress CONFIRMADO en el objetivo.{C_RESET}")
            else:
                print(f"    {C_YELLOW}[!] WordPress NO detectado. Las fases específicas de WP serán omitidas.{C_RESET}")
            
            # Buscar firmas de plugins en el HTML
            for plugin_name, sigs in PLUGINS_SIGNATURES.items():
                for sig in sigs:
                    if sig in r.text:
                        plugins.add(sig)
                        break
            
            print(f"    {C_GREEN}[+] Servidor{C_RESET}     : {server_header}")
            print(f"    {C_GREEN}[+] Sist. Operat.{C_RESET}: {os_info}")
            print(f"    {C_GREEN}[+] Versión PHP{C_RESET}  : {php_version}")
            if powered_by != "Desconocido":
                print(f"    {C_CYAN}[i]{C_RESET} Tecnologías     : {powered_by}")
            print(f"    {C_CYAN}[i]{C_RESET} WAF / Proxy     : {waf}")
            print(f"    {C_CYAN}[i]{C_RESET} Versión WP      : {wp_version}")
            print(f"    {C_CYAN}[i]{C_RESET} Temas Activos   : {', '.join(themes) if themes else 'No detectados pasivamente'}")
            
            # Evaluación de CVEs para el Core de WordPress
            wp_cve_info = ""
            if wp_version and "Desconocida" not in wp_version and "Extraída" not in wp_version:
                wp_cve_info = await self.check_cve_nvd("WordPress", wp_version)
            
            # Extracción activa de versiones de plugins vía readme.txt
            plugins_info = []
            plugins_cve_info = []
            if plugins:
                print(f"    {C_CYAN}[*] Intentando extraer versiones de los plugins detectados...{C_RESET}")
                
                async def process_plugin(plugin):
                    passive_version = asset_versions.get(plugin)
                    if passive_version:
                        p_info = f"{plugin} (v{passive_version}, pasiva)"
                        print(f"        {C_GREEN}[+] {plugin} -> Versión pasiva: {passive_version}{C_RESET}")
                        p_cve = await self.check_cve_nvd(plugin, passive_version)
                        return p_info, p_cve, passive_version
                        
                    readme_url = urljoin(self.base_url, f"wp-content/plugins/{plugin}/readme.txt")
                    try:
                        r_plugin = await self.safe_request("GET", readme_url, timeout=self.req_timeout)
                        if r_plugin and r_plugin.status_code == 200 and "Stable tag:" in r_plugin.text:
                            stable_tag = re.search(r'Stable tag:\s*([^\r\n]+)', r_plugin.text)
                            version = stable_tag.group(1).strip() if stable_tag else "Desconocida"
                            p_info = f"{plugin} (v{version})"
                            print(f"        {C_GREEN}[+] {plugin} -> Versión: {version}{C_RESET}")
                            p_cve = await self.check_cve_nvd(plugin, version)
                            return p_info, p_cve, version
                        else:
                            return plugin, None, None
                    except Exception:
                        return plugin, None, None

                # Consultar en paralelo las versiones de plugins y sus vulnerabilidades correspondientes
                plugin_results = await asyncio.gather(*(process_plugin(p) for p in plugins))
                for p_info, p_cve, p_ver in plugin_results:
                    plugins_info.append(p_info)
                    if p_cve and "Sin CVEs" not in p_cve and "Error" not in p_cve and "omitida" not in p_cve:
                        plugins_cve_info.append(f"{p_info.split(' ')[0]} (v{p_ver}): {p_cve}")
            else:
                print(f"    {C_GREEN}[+] Plugins{C_RESET}      : No detectados pasivamente")
                
            if plugins_info:
                print(f"    {C_GREEN}[+] Plugins{C_RESET}      : {', '.join(plugins_info)}")

            # Extraer y descargar scripts locales en paralelo para análisis profundo de tecnologías
            script_srcs = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', r.text, re.IGNORECASE)
            js_urls = []
            for src in script_srcs:
                if not src.startswith("http") or urlparse(src).netloc == urlparse(self.base_url).netloc:
                    js_urls.append(urljoin(self.base_url, src))
            
            js_urls = list(set(js_urls))[:6] # Limitar a los 6 scripts locales más relevantes
            local_js_contents = []
            if js_urls:
                js_results = await asyncio.gather(*(self.safe_request("GET", url, timeout=5) for url in js_urls), return_exceptions=True)
                for url, js_r in zip(js_urls, js_results):
                    if js_r and not isinstance(js_r, Exception) and js_r.status_code == 200:
                        local_js_contents.append((url, js_r.text))

            self.detected_plugins_passive = list(plugins)
            self.detected_technologies = self.build_technology_inventory(
                r.headers,
                r.text,
                server_header,
                powered_by,
                waf,
                wp_version,
                php_version,
                themes,
                plugins_info,
                local_js_contents
            )
            
            if self.detected_technologies:
                non_wp_techs = [f"{tech['name']} ({tech['category']})" for tech in self.detected_technologies if tech['category'] != "Plugin WordPress" and tech['category'] != "Tema WordPress" and tech['name'] != "WordPress"]
                if non_wp_techs:
                    print(f"    {C_GREEN}[+] Tecnologías detectadas:{C_RESET} {', '.join(non_wp_techs)}")
            
            # Test de Soft-404
            await self.establish_soft_404_signatures(samples=2)
            if self.soft_404_signatures:
                print(f"\n    {C_YELLOW}[!] Advertencia: El servidor devuelve HTTP 200 OK para páginas inexistentes (Soft-404).{C_RESET}")
                print(f"    {C_YELLOW}[!] El escáner de rutas filtrará automáticamente falsos positivos por similitud estructural.{C_RESET}")
            
            # Test de Redirect-404 (Falsos positivos por redirección a login o similares)
            test_paths = [
                f"wp-admin/test-redirect-{random.randint(1000,9999)}.php",
                f"non-existent-at-root-{random.randint(1000,9999)}.php"
            ]
            print(f"    {C_CYAN}[*] Verificando comportamiento de redirecciones para rutas inexistentes...{C_RESET}")
            
            async def check_redirect_path(tp):
                url_tp = urljoin(self.base_url, tp)
                try:
                    r_tp = await self.safe_request("GET", url_tp, timeout=self.req_timeout, allow_redirects=False)
                    if r_tp and r_tp.status_code in [301, 302]:
                        loc = r_tp.headers.get('Location', '')
                        pattern = loc.split('?')[0] if '?' in loc else loc
                        self.generic_redirect_patterns.add(pattern)
                        self.generic_redirect_patterns.add(pattern.replace("https://", "").replace("http://", ""))
                        if "wp-login.php" in loc:
                             print(f"        {C_YELLOW}[i] Detectada redirección forzosa al login en {tp}{C_RESET}")
                        else:
                             print(f"        {C_YELLOW}[i] Detectada redirección genérica en {tp} -> {pattern}{C_RESET}")
                except Exception:
                    pass

            await asyncio.gather(*(check_redirect_path(tp) for tp in test_paths))
            
            recon_findings = f"OS: {os_info} | PHP: {php_version} | WP: {wp_version} | WAF: {waf}"
            if wp_cve_info:
                recon_findings += f" | WP Vulnerabilities: {wp_cve_info}"
            if plugins_cve_info:
                recon_findings += f" | Plugins Vulnerabilities: {', '.join(plugins_cve_info)}"

            self.results.append({
                "Module": "Recon",
                "Endpoint": self.base_url,
                "Status": r.status_code,
                "Size": len(r.content),
                "Findings": recon_findings
            })
            
            # Añadir filas independientes para los CVEs en la tabla final
            if wp_cve_info and "CVEs:" in wp_cve_info:
                for cve_str in wp_cve_info.replace("CVEs: ", "").split(" | "):
                    if "CVE-" in cve_str:
                        self.results.append({
                            "Module": "CVE-Scanner",
                            "Endpoint": "WordPress Core",
                            "Status": "VULNERABLE",
                            "Size": 0,
                            "Findings": cve_str.strip()
                        })
                        
            for plugin_cve in plugins_cve_info:
                if "CVEs:" in plugin_cve:
                    plugin_name = plugin_cve.split(":")[0].strip()
                    cves_text = plugin_cve.split("CVEs:")[1].strip()
                    for cve_str in cves_text.split(" | "):
                        if "CVE-" in cve_str:
                            self.results.append({
                                "Module": "CVE-Scanner",
                                "Endpoint": f"Plugin: {plugin_name}",
                                "Status": "VULNERABLE",
                                "Size": 0,
                                "Findings": cve_str.strip()
                            })
        except Exception as e:
            print(f"{C_RED}[!] Error en recon: {e}{C_RESET}")

    async def check_plugin_active(self, slug: str, sem: asyncio.Semaphore) -> Optional[Tuple[str, str]]:
        """Verifica activamente si un plugin existe y trata de extraer su versión."""
        readme_url = urljoin(self.base_url, f"wp-content/plugins/{slug}/readme.txt")
        headers = self.request_headers()
        async with sem:
            try:
                r = await self.safe_request("GET", readme_url, timeout=self.req_timeout, allow_redirects=False, headers=headers)
                if r and r.status_code == 200 and not self.is_soft_404(r.content):
                    if "Stable tag:" in r.text or "=== " in r.text or "Contributors:" in r.text:
                        stable_tag = re.search(r'Stable tag:\s*([^\r\n]+)', r.text)
                        version = stable_tag.group(1).strip() if stable_tag else "Desconocida"
                        return slug, version
            except Exception:
                pass
                
            plugin_dir_url = urljoin(self.base_url, f"wp-content/plugins/{slug}/")
            try:
                r = await self.safe_request("HEAD", plugin_dir_url, timeout=self.req_timeout, allow_redirects=False, headers=headers)
                if r and r.status_code in [200, 403, 405] and not self.is_soft_404(b""):
                    return slug, "Desconocida"
            except Exception:
                pass
                
            return None

    async def test_active_plugins(self):
        """Realiza una enumeración activa (fuerza bruta) de los 100 plugins más populares de WordPress."""
        self.log_progress("Iniciando escaneo activo de plugins populares...")
        print(f"\n{C_CYAN}[*] --- Fase: Escaneo Activo de Plugins Populares ({len(POPULAR_PLUGINS)} plugins) ---{C_RESET}")
        
        if not self.is_wordpress:
            print(f"    {C_YELLOW}[!] Omitiendo: El objetivo no ha sido confirmado como WordPress.{C_RESET}")
            return

        # Filtrar los que ya descubrimos de forma pasiva (o por crawling)
        passive_slugs = [p.split("(")[0].strip().lower() for p in self.detected_plugins_passive]
        plugins_to_scan = [p for p in POPULAR_PLUGINS if p.lower() not in passive_slugs]
        
        if not plugins_to_scan:
            print(f"    {C_GREEN}[+] Todos los plugins populares ya fueron detectados en la fase pasiva.{C_RESET}")
            return
            
        print(f"    {C_CYAN}[*] Escaneando {len(plugins_to_scan)} plugins en paralelo...{C_RESET}")
        
        detected = []
        active_workers = min(self.threads * 2, 20) if self.threads > 1 else 1
        sem = asyncio.Semaphore(active_workers)
        
        tasks = [self.check_plugin_active(slug, sem) for slug in plugins_to_scan]
        results = await asyncio.gather(*tasks)
        for res in results:
            if res:
                slug, version = res
                print(f"        {C_GREEN}[+] Plugin detectado activamente: {slug} (v{version}){C_RESET}")
                detected.append((slug, version))
                    
        if not detected:
            print(f"    {C_GREEN}[+] No se detectaron plugins adicionales en el escaneo activo.{C_RESET}")
            return
            
        print(f"    {C_GREEN}[+] Se detectaron {len(detected)} plugins adicionales activamente.{C_RESET}")
        
        # Consultar vulnerabilidades para los nuevos plugins encontrados
        for slug, version in detected:
            findings = f"Plugin detectado activamente: {slug} (v{version})"
            
            plugin_cve = await self.check_cve_nvd(slug, version)
            if plugin_cve and "Sin CVEs" not in plugin_cve and "Error" not in plugin_cve and "omitida" not in plugin_cve:
                findings += f" | Vulnerabilidades: {plugin_cve}"
                if "CVEs:" in plugin_cve:
                    cves_text = plugin_cve.split("CVEs:")[1].strip()
                    for cve_str in cves_text.split(" | "):
                        if "CVE-" in cve_str:
                            self.results.append({
                                "Module": "CVE-Scanner",
                                "Endpoint": f"Plugin: {slug}",
                                "Status": "VULNERABLE",
                                "Size": 0,
                                "Findings": cve_str.strip()
                            })
                            
            self.results.append({
                "Module": "Active Plugins",
                "Endpoint": urljoin(self.base_url, f"wp-content/plugins/{slug}/"),
                "Status": 200,
                "Size": 0,
                "Findings": findings
            })
            
            plugin_icons = {
                "woocommerce": ("WooCommerce", "woocommerce", "96588a"),
                "elementor": ("Elementor", "elementor", "92003b"),
                "yoast": ("Yoast SEO", "yoast", "a61e69"),
                "wordfence": ("Wordfence", "", "f59e0b"),
                "jetpack": ("Jetpack", "", "00be28"),
                "contact-form-7": ("Contact Form 7", "", "0ea5e9"),
                "wpforms": ("WPForms", "", "f97316"),
                "akismet": ("Akismet", "automattic", "00aadc"),
            }
            friendly_name, icon, color = plugin_icons.get(slug, (slug.replace("-", " ").title(), "", "64748b"))
            self.add_technology(
                self.detected_technologies,
                friendly_name,
                "Plugin WordPress",
                f"Detectado activamente en ruta de plugin: {slug}",
                version=version if version != "Desconocida" else "",
                confidence=90,
                icon=icon,
                color=color
            )

    async def test_xmlrpc(self):
        print(f"\n{C_CYAN}[*] --- Fase 2: Endpoint Sensibles (XML-RPC) ---{C_RESET}")
        url = urljoin(self.base_url, "xmlrpc.php")
        try:
            await self.sleep_with_jitter()
            # Primero probamos GET para ver si el archivo existe
            r_get = await self.safe_request("GET", url, timeout=self.req_timeout)
            if not r_get:
                return
            status_get = r_get.status_code
            findings = ""
            
            # Si no es 404, procedemos a probar POST, ya que muchos devuelven 405 o 403 en GET
            if status_get != 404:
                if "XML-RPC server accepts POST requests only" in r_get.text:
                    print(f"{C_RED}[+] XML-RPC habilitado en {url} (Status GET: {status_get}){C_RESET}")
                else:
                    print(f"{C_YELLOW}[*] Probando XML-RPC vía POST en {url} (Status GET: {status_get}){C_RESET}")
                
                # Enviar payload para listar métodos
                payload = """<?xml version="1.0" encoding="utf-8"?>
<methodCall>
  <methodName>system.listMethods</methodName>
  <params></params>
</methodCall>"""
                await self.sleep_with_jitter()
                try:
                    headers = {"Content-Type": "text/xml"}
                    r_post = await self.safe_request("POST", url, content=payload, timeout=self.req_timeout + 2, headers=headers)
                    
                    # Fallback para 415 Unsupported Media Type
                    if r_post and r_post.status_code == 415:
                        headers["Content-Type"] = "application/xml"
                        await self.sleep_with_jitter()
                        r_post = await self.safe_request("POST", url, content=payload, timeout=self.req_timeout + 2, headers=headers)

                    if r_post and r_post.status_code == 200 and ("methodResponse" in r_post.text or "params" in r_post.text or "<array>" in r_post.text):
                        print(f"    {C_GREEN}[+] XML-RPC está ACTIVO y RESPONDIENDO a consultas POST.{C_RESET}")
                        findings = "XML-RPC Activo y Funcional"
                        
                        if "system.multicall" in r_post.text:
                            print(f"    {C_RED}--> ¡Alerta! Método system.multicall expuesto (Riesgo de Fuerza Bruta Amplificada){C_RESET}")
                            findings += " | system.multicall expuesto"
                        if "pingback.ping" in r_post.text:
                            print(f"    {C_RED}--> ¡Alerta! Método pingback.ping expuesto (Riesgo de DDoS / SSRF){C_RESET}")
                            findings += " | pingback.ping expuesto"
                            
                            # Intento activo de SSRF (Pingback loopback test)
                            print(f"    {C_CYAN}[*] Probando vulnerabilidad SSRF vía pingback.ping (Localhost:3306)...{C_RESET}")
                            ssrf_payload = f"""<?xml version="1.0" encoding="utf-8"?>
<methodCall>
  <methodName>pingback.ping</methodName>
  <params>
    <param><value><string>http://127.0.0.1:3306/</string></value></param>
    <param><value><string>{url}</string></value></param>
  </params>
</methodCall>"""
                            await self.sleep_with_jitter()
                            try:
                                r_ssrf = await self.safe_request("POST", url, content=ssrf_payload, timeout=self.req_timeout, headers={"Content-Type": "text/xml"})
                                if r_ssrf and "faultCode" in r_ssrf.text:
                                    fault_string = re.search(r'<name>faultString</name>\s*<value><string>(.*?)</string>', r_ssrf.text)
                                    if fault_string:
                                        msg = fault_string.group(1).lower()
                                        if any(x in msg for x in ["cannot be found", "no route", "refused", "timeout", "connect"]):
                                            print(f"    {C_YELLOW}[!] SSRF Posible: El servidor respondió al escaneo (Info: {msg}).{C_RESET}")
                                            findings += " | SSRF Activo (Port Scan Posible)"
                                        else:
                                            print(f"    {C_YELLOW}[-] Pingback SSRF fue procesado pero devolvió: {msg}{C_RESET}")
                                elif r_ssrf:
                                    print(f"    {C_RED}[+] ¡VULNERABLE! SSRF Confirmado: El servidor procesó el pingback hacia localhost.{C_RESET}")
                                    findings += " | SSRF Confirmado (Vulnerable)"
                            except Exception as e:
                                print(f"    {C_YELLOW}[-] Error al probar SSRF: {e}{C_RESET}")
                                
                        # Extracción de métodos de plugins (Terceros)
                        all_methods = re.findall(r'<string>(.*?)</string>', r_post.text)
                        plugin_methods = [m for m in all_methods if m.strip() and not any(m.startswith(x) for x in ["wp.", "system.", "pingback.", "metaWeblog.", "mt.", "blogger.", "demo."])]
                        if plugin_methods:
                            print(f"    {C_RED}--> ¡Alerta! Métodos de terceros/Plugins expuestos ({len(plugin_methods)} encontrados):{C_RESET}")
                            for pm in plugin_methods[:5]:
                                print(f"        {C_YELLOW}- {pm}{C_RESET}")
                            findings += f" | Plugins Methods: {len(plugin_methods)}"
                            
                        # Chequear métodos que permiten listar información
                        info_methods = ["wp.getUsers", "wp.getUsersBlogs", "wp.getAuthors", "wp.getProfile", "wp.getOptions", "wp.getComments", "wp.getTaxonomies"]
                        exposed_info_methods = [m for m in info_methods if m in r_post.text]
                        if exposed_info_methods:
                            print(f"    {C_RED}--> ¡Alerta! Métodos de enumeración expuestos: {', '.join(exposed_info_methods)}{C_RESET}")
                            findings += f" | Listado Info: {', '.join(exposed_info_methods)}"
                            
                            # Intentar enumerar usuarios si wp.getAuthors o wp.getUsers están
                            target_method = next((m for m in ["wp.getAuthors", "wp.getUsers"] if m in exposed_info_methods), None)
                            if target_method:
                                print(f"    {C_CYAN}[*] Intentando extraer usuarios mediante {target_method}...{C_RESET}")
                                dump_payload = f"""<?xml version="1.0" encoding="utf-8"?>
<methodCall><methodName>{target_method}</methodName><params><param><value><int>1</int></value></param><param><value><string></string></value></param><param><value><string></string></value></param></params></methodCall>"""
                                await self.sleep_with_jitter()
                                try:
                                    r_dump = await self.safe_request("POST", url, content=dump_payload, timeout=self.req_timeout, headers={"Content-Type": "text/xml"})
                                    if r_dump and "faultCode" not in r_dump.text and ("<struct>" in r_dump.text or "<array>" in r_dump.text):
                                        extracted = re.findall(r'<name>display_name</name>\s*<value><string>(.*?)</string>', r_dump.text)
                                        if not extracted: extracted = re.findall(r'<string>(.*?)</string>', r_dump.text)
                                        extracted = [x for x in extracted if x.strip() and x != "1" and "http" not in x]
                                        if extracted:
                                            unique_ext = list(set(extracted))[:10]
                                            print(f"        {C_RED}--> Usuarios encontrados: {', '.join(unique_ext)}{C_RESET}")
                                            findings += f" | {target_method} Vulnerable"
                                except Exception: pass

                    elif r_post and r_post.status_code == 405:
                        print(f"    {C_YELLOW}[-] POST a XML-RPC devolvió 405 (Bloqueado por el servidor o WAF).{C_RESET}")
                        findings = "XML-RPC Bloqueado (405 POST)"
                    elif r_post and r_post.status_code == 403:
                        print(f"    {C_YELLOW}[-] POST a XML-RPC devolvió 403 (Prohibido/WAF).{C_RESET}")
                        findings = "XML-RPC Prohibido (403 POST)"
                    else:
                        status_p = r_post.status_code if r_post else "None"
                        print(f"    {C_YELLOW}[-] XML-RPC no respondió como se esperaba (Status: {status_p}).{C_RESET}")
                        findings = f"XML-RPC Inactivo (Status POST: {status_p})"
                except Exception as post_e:
                    print(f"    {C_YELLOW}--> Error al realizar POST a XML-RPC: {post_e}{C_RESET}")
                    findings = "Error en POST XML-RPC"
            else:
                print(f"{C_GREEN}[+] XML-RPC no encontrado (404) en {url}{C_RESET}")
                findings = "No encontrado"
            
            self.results.append({
                "Module": "XML-RPC",
                "Endpoint": url,
                "Status": status_get,
                "Size": len(r_get.content) if r_get else 0,
                "Findings": findings
            })
        except Exception as e:
            print(f"{C_RED}[!] Error en XML-RPC: {e}{C_RESET}")

    async def test_rest_users(self):
        self.log_progress("Iniciando pruebas de REST API (Usuarios)...")
        print(f"\n{C_CYAN}[*] --- Fase 3: REST API (Usuarios) ---{C_RESET}")
        url_main = urljoin(self.base_url, "wp-json/wp/v2/users")
        url_user1 = urljoin(self.base_url, "wp-json/wp/v2/users/1")
        url_posts = urljoin(self.base_url, "wp-json/wp/v2/posts?author=1")
        
        findings = []
        status_main = 404
        r_main_content_len = 0
        try:
            # 1. Probar endpoint principal de usuarios
            r_main = await self.safe_request("GET", url_main, timeout=self.req_timeout)
            if not r_main:
                return
            status_main = r_main.status_code
            r_main_content_len = len(r_main.content)
            if r_main.status_code == 200 and "id" in r_main.text and "slug" in r_main.text:
                print(f"    {C_RED}[!] ¡Alerta! Enumeración global de usuarios expuesta en {url_main}{C_RESET}")
                findings.append("Enumeración global expuesta (/users)")
            
            # 2. Probar usuario individual (ID 1)
            r_u1 = await self.safe_request("GET", url_user1, timeout=self.req_timeout)
            if not r_u1:
                r_u1 = r_main
            if r_u1.status_code == 200 and "slug" in r_u1.text:
                print(f"    {C_RED}[!] ¡Alerta! Exposición de usuario ID 1 en {url_user1}{C_RESET}")
                findings.append("Usuario ID 1 expuesto (/users/1)")
                
            # 3. Probar posts filtrados por autor (ID 1)
            r_posts = await self.safe_request("GET", url_posts, timeout=self.req_timeout)
            if not r_posts:
                r_posts = r_main
            if r_posts.status_code == 200 and "id" in r_posts.text and ("author" in r_posts.text or "yoast" in r_posts.text):
                print(f"    {C_RED}[!] ¡Alerta! Enumeración indirecta de autor vía posts en {url_posts}{C_RESET}")
                findings.append("Enumeración vía posts por autor (/posts?author=1)")
                
            if findings:
                findings_str = " | ".join(findings)
            else:
                print(f"    {C_YELLOW}[-] REST API Usuarios protegida o inaccesible (Status principal: {status_main}){C_RESET}")
                findings_str = "Protegida o inaccesible"
                
            self.results.append({
                "Module": "REST Users",
                "Endpoint": url_main,
                "Status": status_main,
                "Size": r_main_content_len,
                "Findings": findings_str
            })
        except Exception as e:
            print(f"    {C_RED}[!] Error en REST Users: {e}{C_RESET}")

    async def test_author_enum(self):
        print(f"\n{C_CYAN}[*] --- Fase 4: Enumeración de Autor (?author=1) ---{C_RESET}")
        url = urljoin(self.base_url, "?author=1")
        try:
            r = await self.safe_request("GET", url, timeout=self.req_timeout, follow_redirects=True)
            if not r:
                return
            status = r.status_code
            findings = ""
            if "/author/" in str(r.url):
                print(f"{C_RED}[!] Enumeración por author redirect activa -> {r.url}{C_RESET}")
                findings = f"Author redirect: {r.url}"
            else:
                print(f"{C_YELLOW}[-] No se detectó redirect típico de autor.{C_RESET}")

            self.results.append({
                "Module": "Author Enum",
                "Endpoint": url,
                "Status": status,
                "Size": len(r.content),
                "Findings": findings
            })
        except Exception as e:
            print(f"{C_RED}[!] Error en Author Enum: {e}{C_RESET}")

    async def test_login_enum(self):
        print(f"\n{C_CYAN}[*] --- Fase 5: Enumeración de Usuarios por Login Error ---{C_RESET}")
        url = urljoin(self.base_url, "wp-login.php")
        try:
            # Enviar un usuario que seguramente no existe
            fake_user = f"usuario_inexistente_{random.randint(1000,9999)}"
            data_fake = {"log": fake_user, "pwd": "badpassword", "wp-submit": "Log In"}
            r_fake = await self.safe_request("POST", url, data=data_fake, timeout=self.req_timeout, cache_response=False)
            if not r_fake:
                return
            
            # Enviar un usuario clásico (admin) para ver la diferencia de error
            data_admin = {"log": "admin", "pwd": "badpassword", "wp-submit": "Log In"}
            r_admin = await self.safe_request("POST", url, data=data_admin, timeout=self.req_timeout, cache_response=False)
            if not r_admin:
                return
            
            findings = ""
            if "login_error" in r_fake.text or 'id="login_error"' in r_fake.text:
                if "incorrecta" in r_admin.text.lower() or "incorrect" in r_admin.text.lower() or "is incorrect" in r_admin.text.lower():
                    # Si al poner 'admin' nos dice contraseña incorrecta, sabemos que 'admin' existe.
                    # Al poner 'usuario_inexistente' dirá 'Invalid username'. Esto confirma la enumeración.
                    print(f"    {C_RED}[!] ¡VULNERABLE! Enumeración de usuarios activa en wp-login.php por diferencias en los mensajes de error.{C_RESET}")
                    findings = "Enumeración por wp-login.php confirmada"
                else:
                    print(f"    {C_YELLOW}[-] Login protegido o respuestas de error estandarizadas.{C_RESET}")
            else:
                 print(f"    {C_YELLOW}[-] No se pudo determinar comportamiento de login (Status: {r_admin.status_code}){C_RESET}")
                 
            self.results.append({
                "Module": "Login Enum",
                "Endpoint": url,
                "Status": r_admin.status_code,
                "Size": len(r_admin.content),
                "Findings": findings
            })
        except Exception as e:
            print(f"    {C_RED}[!] Error probando Login Enum: {e}{C_RESET}")

    async def test_wp_cron(self):
        print(f"\n{C_CYAN}[*] --- Fase 6: Pruebas de DoS en wp-cron.php ---{C_RESET}")
        url = urljoin(self.base_url, "wp-cron.php")
        try:
            # 1. Medición Base (1 sola petición)
            await self.sleep_with_jitter()
            t_start = time.time()
            r_base = await self.safe_request("GET", url, timeout=15)
            t_base = time.time() - t_start
            
            if r_base and r_base.status_code == 200:
                print(f"    {C_RED}[!] ¡Alerta! wp-cron.php está accesible públicamente.{C_RESET}")
                print(f"    {C_CYAN}[*] Tiempo de respuesta base: {t_base:.2f}s{C_RESET}")
                
                # 2. Test de Estrés Ligero (Ráfaga concurrente)
                print(f"    {C_YELLOW}[*] Realizando test de estrés ligero (8 peticiones concurrentes)...{C_RESET}")
                
                async def burst_request():
                    ts = time.time()
                    try:
                        r = await self.safe_request("GET", url, timeout=20, cache_response=False)
                        if r:
                            return time.time() - ts
                    except Exception:
                        pass
                    return None

                tasks = [burst_request() for _ in range(8)]
                results = await asyncio.gather(*tasks)
                burst_times = [res for res in results if res is not None]
                
                if burst_times:
                    avg_burst = sum(burst_times) / len(burst_times)
                    impacto = (avg_burst / t_base) if t_base > 0 else 0
                    
                    print(f"    {C_CYAN}[*] Tiempo medio bajo carga: {avg_burst:.2f}s{C_RESET}")
                    
                    if impacto > 1.5:
                        print(f"    {C_RED}[!!!] ALERTA: El tiempo de respuesta aumentó un {((impacto-1)*100):.1f}% bajo carga.{C_RESET}")
                        print(f"    {C_RED}      Esto confirma vulnerabilidad alta a DoS por saturación de hilos PHP.{C_RESET}")
                        findings = f"wp-cron expuesto | Impacto DoS: {impacto:.1f}x ralentización"
                    else:
                        print(f"    {C_GREEN}[+] El servidor maneja bien la carga concurrente (Impacto: {impacto:.1f}x).{C_RESET}")
                        findings = "wp-cron expuesto (Poco impacto en test de estrés)"
                else:
                    findings = "wp-cron expuesto (No se pudo completar test de estrés)"
                
                self.results.append({
                    "Module": "WP-Cron",
                    "Endpoint": url,
                    "Status": r_base.status_code,
                    "Size": len(r_base.content),
                    "Findings": findings
                })
            else:
                status_val = r_base.status_code if r_base else "Inaccesible"
                print(f"    {C_GREEN}[+] wp-cron.php parece estar protegido o bloqueado externamente (Status: {status_val}).{C_RESET}")
        except Exception as e:
            print(f"    {C_RED}[!] Error probando wp-cron: {e}{C_RESET}")

    async def check_route(self, route: str) -> Optional[Dict]:
        url = urljoin(self.base_url, route.lstrip("/"))
        try:
            # Rotar User-Agent dinámicamente por cada ruta evaluada
            headers = self.request_headers()
            r = await self.head_or_get_headers(url, timeout=self.req_timeout, follow_redirects=False, headers=headers)
            
            if not r:
                return None
                
            body_loaded = bool(r.content)
            if r.status_code == 200 and not body_loaded and self.should_fetch_body(url, r.headers):
                body_headers = self.request_headers({"Range": "bytes=0-65535"})
                r_body = await self.safe_request("GET", url, timeout=self.req_timeout, follow_redirects=False, headers=body_headers)
                if r_body:
                    r = r_body
                    body_loaded = True
            title = self.get_title(r.text[:5000]) if body_loaded else ""
            kws = self.analyze_keywords(r.text[:5000]) if body_loaded else ""
            size = self.header_value_int(r.headers, "Content-Length")
            if size is None:
                size = len(r.content) if body_loaded else 0
            
            # Filtrar redirecciones que no aportan (Ruido)
            if r.status_code in [301, 302]:
                location = r.headers.get('Location', '')
                dest_url = urljoin(url, location)
                
                # 1. Ignorar si redirige al Home (típico de 404 manejados por WP)
                if dest_url.rstrip("/") == self.base_url.rstrip("/"):
                    return None
                
                # 2. Ignorar si es un patrón detectado como genérico (Redirect-404) o al login
                dest_pattern = location.split('?')[0] if '?' in location else location
                dest_pattern_no_proto = dest_pattern.replace("https://", "").replace("http://", "")
                
                if dest_pattern in self.generic_redirect_patterns or dest_pattern_no_proto in self.generic_redirect_patterns:
                    self.filtered_redirects += 1
                    return None
                
                # 3. Ignorar si es solo un cambio de www/no-www o http/https a la misma ruta
                parsed_orig = urlparse(url)
                parsed_dest = urlparse(dest_url)
                if parsed_orig.path == parsed_dest.path and (parsed_orig.netloc.replace("www.", "") == parsed_dest.netloc.replace("www.", "")):
                    return None
                
                # 4. Si llega aquí, es una redirección "interesante" (ej: a otro dominio o ruta distinta)
                tqdm.write(f"    {C_YELLOW}[{r.status_code}]{C_RESET} {url} --> {C_YELLOW}{location}{C_RESET}")
                return {
                    "Module": "Scanner",
                    "Endpoint": url,
                    "Status": r.status_code,
                    "Size": size,
                    "Findings": f"Redirección Interesante: {location}"
                }

            # Formateo de salida para 200 OK
            if r.status_code == 200:
                if self.is_archive_like_response(url, r.headers) and "text/html" in r.headers.get("Content-Type", "").lower() and not body_loaded:
                    self.filtered_redirects += 1
                    return None

                if self.is_archive_like_response(url, r.headers) and not self.is_textual_response(r.headers):
                    content_type = r.headers.get("Content-Type", "desconocido")
                    tqdm.write(f"    {C_GREEN}[200]{C_RESET} {url} | Size: {size} | Type: {content_type}")
                    return {
                        "Module": "Scanner",
                        "Endpoint": url,
                        "Status": r.status_code,
                        "Size": size,
                        "Findings": f"Archivo potencialmente expuesto | Type: {content_type}"
                    }

                if not body_loaded:
                    tqdm.write(f"    {C_GREEN}[200]{C_RESET} {url} | Size: {size} | Cuerpo omitido por cabeceras")
                    return {
                        "Module": "Scanner",
                        "Endpoint": url,
                        "Status": r.status_code,
                        "Size": size,
                        "Findings": "Recurso existe; cuerpo omitido por Content-Type/Length"
                    }

                # Filtro de Soft-404 mejorado
                if self.is_soft_404(r.content):
                    self.filtered_redirects += 1 # Contamos soft-404 también como filtrado
                    return None

                tqdm.write(f"    {C_GREEN}[200]{C_RESET} {url} | Size: {size} | Title: '{title[:40]}'")
                if kws:
                    tqdm.write(f"        {C_RED}--> Keywords detectadas: {kws}{C_RESET}")
                
                return {
                    "Module": "Scanner",
                    "Endpoint": url,
                    "Status": r.status_code,
                    "Size": size,
                    "Findings": f"Title: {title} | KWs: {kws}"
                }
            
            return None
        except httpx.RequestError as e:
            tqdm.write(f"{C_RED}[ERR] {url} -> {e}{C_RESET}")
            return None

    async def check_directory_listing(self):
        print(f"\n{C_CYAN}[*] --- Fase 7: Indexación de Directorios (Directory Listing) ---{C_RESET}")
        dirs_to_check = ["wp-content/uploads/", "wp-includes/", "wp-content/plugins/"]
        for directory in dirs_to_check:
            url = urljoin(self.base_url, directory)
            try:
                await self.sleep_with_jitter()
                headers = self.request_headers()
                r = await self.safe_request("GET", url, timeout=self.req_timeout, headers=headers)
                if r and ("Index of" in r.text or "Index of /" in self.get_title(r.text)):
                    print(f"    {C_RED}[!] ¡Vulnerabilidad! Directory Listing habilitado en: {url}{C_RESET}")
                    self.results.append({"Module": "Dir Listing", "Endpoint": url, "Status": r.status_code, "Size": len(r.content), "Findings": "Directory Listing Habilitado"})
                else:
                    print(f"    {C_GREEN}[+] Protegido o sin acceso público: {url}{C_RESET}")
            except Exception as e:
                print(f"    {C_YELLOW}[-] Error al verificar {url}: {e}{C_RESET}")

    async def check_classic_file(self, path: str, sem: asyncio.Semaphore, pbar) -> Optional[Dict]:
        url = urljoin(self.base_url, path)
        res_dict = None
        async with sem:
            try:
                headers = self.request_headers()
                r = await self.safe_request("GET", url, timeout=self.req_timeout, follow_redirects=False, headers=headers)
                if r and r.status_code == 200:
                    is_phpinfo = "phpinfo()" in r.text or "PHP Version" in r.text
                    color = C_RED if is_phpinfo else C_GREEN
                    info = " (PHPINFO DETECTADO)" if is_phpinfo else ""
                    tqdm.write(f"    {color}[+]{C_RESET} Archivo encontrado: {url}{info}")
                    res_dict = {
                        "Module": "Classic Files",
                        "Endpoint": url,
                        "Status": r.status_code,
                        "Size": len(r.content),
                        "Findings": f"Archivo Clásico: {path}{info}"
                    }
            except Exception:
                pass
        pbar.update(1)
        return res_dict

    async def test_classic_files(self):
        print(f"\n{C_CYAN}[*] --- Fase 8: Archivos Clásicos y Sensibles ---{C_RESET}")
        classic_paths = [
            "info.php", "phpinfo.php", "test.php", "i.php", "php.php", 
            "p.php", "status.php", "check.php", "temp.php", "old.php",
            "php.ini", ".user.ini", ".htaccess", "web.config", 
            "error_log", "error.log", "robots.txt", "sitemap.xml",
            "composer.json", "package.json", "wp-config.php.dist"
        ]
        
        found_count = 0
        sem = asyncio.Semaphore(10)
        with tqdm(total=len(classic_paths), desc="Buscando archivos clásicos", unit="file", leave=False) as pbar:
            tasks = [self.check_classic_file(path, sem, pbar) for path in classic_paths]
            results = await asyncio.gather(*tasks)
            for res in results:
                if res:
                    self.results.append(res)
                    found_count += 1
        if found_count == 0:
            print(f"    {C_GREEN}[+] No se detectaron archivos clásicos adicionales en la raíz.{C_RESET}")

    async def check_port(self, host: str, port: int, service: str, sem: asyncio.Semaphore) -> Optional[Tuple[int, str]]:
        async with sem:
            try:
                conn = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(conn, timeout=1.5)
                writer.close()
                await writer.wait_closed()
                return port, service
            except Exception:
                pass
            return None

    async def test_ports(self):
        print(f"\n{C_CYAN}[*] --- Fase 2: Escaneo de Puertos Comunes ---{C_RESET}")
        common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 139: "NetBIOS", 143: "IMAP",
            443: "HTTPS", 445: "SMB", 1433: "MSSQL", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt"
        }
        
        target_host = self.base_url.split("//")[-1].split("/")[0].split(":")[0]
        print(f"    {C_CYAN}[*] Escaneando host: {target_host}{C_RESET}")
        
        found_ports = []
        sem = asyncio.Semaphore(20)
        
        tasks = [self.check_port(target_host, p, s, sem) for p, s in common_ports.items()]
        results = await asyncio.gather(*tasks)
        for res in results:
            if res:
                port, service = res
                print(f"    {C_RED}[!] Puerto Abierto: {port} ({service}){C_RESET}")
                found_ports.append(f"{port}/{service}")

        if not found_ports:
            print(f"    {C_GREEN}[+] No se detectaron otros puertos comunes abiertos.{C_RESET}")
        
        self.results.append({
            "Module": "Port Scan",
            "Endpoint": target_host,
            "Status": "N/A",
            "Size": 0,
            "Findings": f"Puertos Abiertos: {', '.join(found_ports) if found_ports else 'Ninguno detectado'}"
        })

    async def scan_routes(self):
        print(f"\n{C_CYAN}[*] --- Fase 9: Escaneo de Rutas ({len(self.routes)} rutas críticas) ---{C_RESET}")
        sem = asyncio.Semaphore(min(self.threads * 2, 25) if self.threads > 1 else 1)
        
        async def worker(route, pbar):
            async with sem:
                res = await self.check_route(route)
                pbar.update(1)
                return res

        with tqdm(total=len(self.routes), desc="Escaneando rutas", unit="url") as pbar:
            tasks = [worker(route, pbar) for route in self.routes]
            results = await asyncio.gather(*tasks)
            for res in results:
                if res:
                    self.results.append(res)

    async def test_security_headers(self):
        self.log_progress("Iniciando auditoría de Cabeceras de Seguridad HTTP...")
        print(f"\n{C_CYAN}[*] --- Fase: Cabeceras de Seguridad HTTP ---{C_RESET}")
        
        headers_to_check = {
            "Content-Security-Policy": "Protege contra XSS e inyecciones de datos.",
            "X-Frame-Options": "Evita Clickjacking.",
            "X-Content-Type-Options": "Previene sniffing MIME.",
            "Strict-Transport-Security": "Fuerza HTTPS (HSTS).",
            "Referrer-Policy": "Controla información del referer."
        }
        
        try:
            await self.sleep_with_jitter()
            r = await self.safe_request("GET", self.base_url, timeout=self.req_timeout)
            if r:
                missing = []
                for header, desc in headers_to_check.items():
                    if header not in r.headers:
                        missing.append(header)
                        print(f"    {C_YELLOW}[!] Falta cabecera de seguridad: {header} - {desc}{C_RESET}")
                
                if missing:
                    findings = f"Faltan cabeceras de seguridad: {', '.join(missing)}"
                    self.results.append({
                        "Module": "Security Headers",
                        "Endpoint": self.base_url,
                        "Status": r.status_code,
                        "Size": len(r.content),
                        "Findings": findings
                    })
                else:
                    print(f"    {C_GREEN}[+] Cabeceras de seguridad recomendadas presentes.{C_RESET}")
        except Exception as e:
            print(f"    {C_RED}[ERR] Error en cabeceras de seguridad: {e}{C_RESET}")

    async def test_theme_version(self):
        self.log_progress("Iniciando auditoría activa de versión de Temas...")
        print(f"\n{C_CYAN}[*] --- Fase: Extracción Activa de Versión del Tema ---{C_RESET}")
        if not hasattr(self, 'detected_themes') or not self.detected_themes:
            print(f"    {C_GREEN}[+] No se detectaron temas pasivamente para validar versión.{C_RESET}")
            return
            
        for theme in self.detected_themes:
            url = urljoin(self.base_url, f"wp-content/themes/{theme}/style.css")
            try:
                await self.sleep_with_jitter()
                r = await self.safe_request("GET", url, timeout=5)
                if r and r.status_code == 200 and "Theme Name:" in r.text:
                    version_match = re.search(r'Version:\s*([^\r\n]+)', r.text, re.IGNORECASE)
                    version = version_match.group(1).strip() if version_match else "Desconocida"
                    print(f"    {C_GREEN}[+] Tema detectado: {theme} -> Versión extraída: {version}{C_RESET}")
                    
                    findings = f"Tema activo expuesto: {theme} (v{version})"
                    
                    theme_cve = await self.check_cve_nvd(f"WordPress Theme {theme}", version)
                    if theme_cve and "Sin CVEs" not in theme_cve and "Error" not in theme_cve and "omitida" not in theme_cve:
                        findings += f" | Vulnerabilidades: {theme_cve}"
                        for cve_str in theme_cve.replace("CVEs: ", "").split(" | "):
                            if "CVE-" in cve_str:
                                self.results.append({
                                    "Module": "CVE-Scanner",
                                    "Endpoint": f"Theme: {theme}",
                                    "Status": "VULNERABLE",
                                    "Size": 0,
                                    "Findings": cve_str.strip()
                                })
                    
                    self.results.append({
                        "Module": "Theme Version",
                        "Endpoint": url,
                        "Status": r.status_code,
                        "Size": len(r.content),
                        "Findings": findings
                    })
                else:
                    print(f"    {C_YELLOW}[-] No se pudo extraer la versión de style.css del tema {theme}.{C_RESET}")
            except Exception as e:
                print(f"    {C_RED}[ERR] Error analizando versión del tema {theme}: {e}{C_RESET}")

    async def check_upload_leak(self, path: str, sem: asyncio.Semaphore, pbar) -> Optional[Dict]:
        url = urljoin(self.base_url, path)
        res_dict = None
        async with sem:
            try:
                headers = self.request_headers()
                r = await self.head_or_get_headers(url, timeout=self.req_timeout, follow_redirects=False, headers=headers)
                if r and r.status_code == 200:
                    size = self.header_value_int(r.headers, "Content-Length") or len(r.content)
                    content_type = r.headers.get("Content-Type", "").lower()
                    if "text/html" in content_type and self.should_fetch_body(url, r.headers):
                        r_body = await self.safe_request("GET", url, timeout=self.req_timeout, follow_redirects=False, headers=self.request_headers({"Range": "bytes=0-65535"}))
                        if r_body:
                            r = r_body
                            size = self.header_value_int(r.headers, "Content-Length") or len(r.content)
                    if not (r.content and self.is_soft_404(r.content)) and "text/html" not in content_type:
                        tqdm.write(f"    {C_RED}[!] ¡Archivo expuesto detectado! {url}{C_RESET}")
                        res_dict = {
                            "Module": "Uploads Leak",
                            "Endpoint": url,
                            "Status": r.status_code,
                            "Size": size,
                            "Findings": f"Archivo de respaldo expuesto: {path.split('/')[-1]} | Type: {r.headers.get('Content-Type', 'desconocido')}"
                        }
            except Exception:
                pass
        pbar.update(1)
        return res_dict

    async def test_uploads_leak(self):
        self.log_progress("Iniciando verificación de archivos expuestos en subidas (uploads)...")
        print(f"\n{C_CYAN}[*] --- Fase: Archivos Expuestos en Subidas ---{C_RESET}")
        
        leak_paths = [
            "wp-content/uploads/backup.sql",
            "wp-content/uploads/database.sql",
            "wp-content/uploads/db.sql",
            "wp-content/uploads/dump.sql",
            "wp-content/uploads/backup.zip",
            "wp-content/uploads/site.zip",
            "wp-content/uploads/wp-backup.zip",
            "wp-content/uploads/wp.zip",
            "wp-content/backup.sql",
            "wp-content/database.sql",
            "wp-content/db.sql",
            "wp-content/backup.zip"
        ]
        
        found_count = 0
        sem = asyncio.Semaphore(10)
        with tqdm(total=len(leak_paths), desc="Buscando fugas en uploads/wp-content", unit="file", leave=False) as pbar:
            tasks = [self.check_upload_leak(path, sem, pbar) for path in leak_paths]
            results = await asyncio.gather(*tasks)
            for res in results:
                if res:
                    self.results.append(res)
                    found_count += 1
                
        if found_count == 0:
            print(f"    {C_GREEN}[+] No se detectaron archivos de respaldos expuestos.{C_RESET}")

    async def check_config_path(self, path: str, signatures: List[str], sem: asyncio.Semaphore, pbar) -> Optional[Dict]:
        url = urljoin(self.base_url, path)
        res_dict = None
        async with sem:
            try:
                await self.sleep_with_jitter()
                headers = self.request_headers()
                r = await self.safe_request("GET", url, timeout=self.req_timeout, follow_redirects=False, headers=headers)
                if r and r.status_code == 200:
                    body_text = r.text
                    if not self.is_soft_404(r.content):
                        # Validar firmas para evitar falsos positivos
                        matched = any(sig in body_text for sig in signatures)
                        if matched or not signatures:
                            tqdm.write(f"    {C_RED}[!] ¡Alerta! Recurso o configurador expuesto: {url}{C_RESET}")
                            res_dict = {
                                "Module": "Server Config",
                                "Endpoint": url,
                                "Status": r.status_code,
                                "Size": len(r.content),
                                "Findings": f"Recurso crítico expuesto: {path}"
                            }
            except Exception:
                pass
        pbar.update(1)
        return res_dict

    async def test_server_config(self):
        self.log_progress("Iniciando auditoría de configuraciones e instaladores expuestos...")
        print(f"\n{C_CYAN}[*] --- Fase: Configuraciones del Servidor e Instaladores ---{C_RESET}")
        
        config_paths = [
            ("wp-admin/install.php", ["WordPress &rsaquo; Instalación", "install-select.png", "setup-config.php"]),
            ("wp-admin/setup-config.php", ["WordPress &rsaquo; Archivo de configuración", "setup-config"]),
            ("phpmyadmin/", ["phpMyAdmin", "pmahomme"]),
            ("adminer.php", ["Adminer", "Login - Adminer"]),
            (".env", ["DB_HOST", "DB_PASSWORD", "DB_USER", "DB_NAME"]),
            ("wp-config.php.bak", ["DB_PASSWORD", "wp-config"]),
            ("wp-content/debug.log", ["PHP Notice:", "PHP Warning:", "PHP Stack trace"]),
        ]
        
        found_count = 0
        sem = asyncio.Semaphore(5)
        with tqdm(total=len(config_paths), desc="Buscando configuraciones", unit="file", leave=False) as pbar:
            tasks = [self.check_config_path(path, sigs, sem, pbar) for path, sigs in config_paths]
            results = await asyncio.gather(*tasks)
            for res in results:
                if res:
                    self.results.append(res)
                    found_count += 1
                
        if found_count == 0:
            print(f"    {C_GREEN}[+] No se detectaron instaladores ni configuraciones críticas expuestas.{C_RESET}")

    async def test_passive_malware(self):
        self.log_progress("Iniciando análisis pasivo de malware y defacement...")
        print(f"\n{C_CYAN}[*] --- Fase: Análisis Pasivo de Malware y Defacement ---{C_RESET}")
        
        findings = []
        try:
            await self.sleep_with_jitter()
            r = await self.safe_request("GET", self.base_url, timeout=self.req_timeout)
            if r and r.status_code == 200:
                html = r.text
                html_lower = html.lower()
                
                # 1. Scripts JS ofuscados sospechosos
                if "eval(function(p,a,c,k,e,r)" in html or "eval(function(p,a,c,k,e,d)" in html:
                    findings.append("JS Ofuscado detectado (eval packing)")
                    print(f"    {C_RED}[!] ¡Alerta! Se detectó código JavaScript ofuscado (eval/packed) en la página principal.{C_RESET}")
                
                # 2. Iframes ocultos sospechosos
                iframe_matches = re.findall(r'<iframe[^>]*>', html, re.IGNORECASE)
                for iframe in iframe_matches:
                    iframe_lower = iframe.lower()
                    if "width=\"0\"" in iframe_lower or "height=\"0\"" in iframe_lower or "display:none" in iframe_lower or "visibility:hidden" in iframe_lower or "position:absolute" in iframe_lower:
                        findings.append("Iframe oculto sospechoso")
                        print(f"    {C_RED}[!] ¡Alerta! Se detectó un iframe oculto en el HTML (frecuente en inyecciones de malware): {iframe}{C_RESET}")
                        break
                
                # 3. Enlaces sospechosos o inyecciones de Spam SEO comunes
                spam_keywords = ["casino", "viagra", "cialis", "betting", "lottery", "porn", "poker", "vulgar", "dating"]
                spam_found = []
                for kw in spam_keywords:
                    # Contamos ocurrencias para no alertar por palabras comunes de uso legítimo
                    matches = html_lower.count(kw)
                    if matches > 5:
                        spam_found.append(f"{kw} ({matches} veces)")
                        
                if spam_found:
                    findings.append(f"Posible Spam SEO: {', '.join(spam_found)}")
                    print(f"    {C_RED}[!] ¡Alerta! Alta presencia de palabras clave de SPAM detectada en el HTML: {', '.join(spam_found)}{C_RESET}")
            
            if findings:
                self.results.append({
                    "Module": "Passive Malware",
                    "Endpoint": self.base_url,
                    "Status": r.status_code if r else "None",
                    "Size": len(r.content) if r else 0,
                    "Findings": f"Indicadores de compromiso pasivos detectados: {', '.join(findings)}"
                })
            else:
                print(f"    {C_GREEN}[+] No se detectaron indicadores pasivos de malware ni Spam SEO.{C_RESET}")
        except Exception as e:
            print(f"    {C_RED}[ERR] Error en análisis pasivo de malware: {e}{C_RESET}")

    def _sync_test_ssl_tls(self):
        self.log_progress("Iniciando auditoría SSL/TLS y certificados...")
        print(f"\n{C_CYAN}[*] --- Fase: Auditoría SSL/TLS ---{C_RESET}")
        
        if not self.base_url.startswith("https://"):
            print(f"    {C_YELLOW}[i] El objetivo no utiliza HTTPS. Omitiendo auditoría SSL/TLS.{C_RESET}")
            return
            
        parsed_url = urlparse(self.base_url)
        hostname = parsed_url.hostname
        port = parsed_url.port or 443
        
        import ssl
        import datetime
        
        findings = []
        
        # 1. Comprobar validez y expiración del certificado
        try:
            context = ssl.create_default_context()
            context.check_hostname = self.verify_ssl
            if not self.verify_ssl:
                context.verify_mode = ssl.CERT_NONE
                
            with socket.create_connection((hostname, port), timeout=6) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        not_after_str = cert.get("notAfter")
                        if not_after_str:
                            # Parse format: 'May 22 16:17:00 2026 GMT'
                            try:
                                not_after = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                                remaining_days = (not_after - datetime.datetime.utcnow()).days
                                if remaining_days < 0:
                                    findings.append(f"Certificado Expirado (hace {abs(remaining_days)} días)")
                                    print(f"    {C_RED}[!] ¡Alerta! Certificado SSL/TLS expiró hace {abs(remaining_days)} días.{C_RESET}")
                                elif remaining_days < 15:
                                    findings.append(f"Certificado por expirar ({remaining_days} días restantes)")
                                    print(f"    {C_YELLOW}[!] Advertencia: El certificado SSL/TLS expira pronto ({remaining_days} días restantes).{C_RESET}")
                                else:
                                    print(f"    {C_GREEN}[+] Certificado válido por {remaining_days} días más.{C_RESET}")
                            except Exception as parse_e:
                                pass
        except Exception as cert_e:
            findings.append("Fallo al verificar certificado (SSL handshake error)")
            print(f"    {C_YELLOW}[!] No se pudo validar el certificado SSL/TLS (Handshake fallido: {cert_e}).{C_RESET}")
            
        # 2. Comprobar soporte a protocolos obsoletos (TLS v1.0 y TLS v1.1)
        import warnings
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=DeprecationWarning)
            for version, name in [(ssl.TLSVersion.TLSv1, "TLSv1.0"), (ssl.TLSVersion.TLSv1_1, "TLSv1.1")]:
                try:
                    # Algunos entornos de Python o SSL de OS pueden no soportar versiones obsoletas por completo
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    context.minimum_version = version
                    context.maximum_version = version
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    with socket.create_connection((hostname, port), timeout=4) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            findings.append(f"Protocolo inseguro activo: {name}")
                            print(f"    {C_RED}[!] ¡Alerta! El servidor web acepta conexiones usando el protocolo obsoleto {name}.{C_RESET}")
                except Exception:
                    # El Handshake falló o la versión no está soportada, lo cual indica que el servidor la rechaza (¡Correcto!)
                    pass
                
        if findings:
            self.results.append({
                "Module": "SSL-TLS Audit",
                "Endpoint": f"{hostname}:{port}",
                "Status": "N/A",
                "Size": 0,
                "Findings": f"Debilidades SSL/TLS detectadas: {', '.join(findings)}"
            })
        else:
            print(f"    {C_GREEN}[+] Transporte SSL/TLS seguro configurado (sin protocolos obsoletos habilitados).{C_RESET}")

    async def test_ssl_tls(self):
        await asyncio.to_thread(self._sync_test_ssl_tls)

    def export_results(self):
        if not self.output_csv:
            return
        print(f"\n{C_CYAN}[*] Guardando resultados en {self.output_csv}...{C_RESET}")
        try:
            with open(self.output_csv, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["Module", "Endpoint", "Status", "Size", "Findings"])
                writer.writeheader()
                writer.writerows(self.results)
            print(f"{C_GREEN}[+] Exportación completa.{C_RESET}")
        except Exception as e:
            print(f"{C_RED}[!] Error al guardar CSV: {e}{C_RESET}")

    def classify_finding(self, finding: str) -> str:
        """Clasifica un hallazgo por su nivel de riesgo."""
        f = finding.lower()
        if any(x in f for x in ["vulnerable", "confirmado", "activo", "ssrf", "system.multicall", "id_rsa", "phpinfo", "wp-config", "cve-"]):
            return "CRITICAL"
        if any(x in f for x in ["alerta", "posible", "enumeración", "expuesto", "listing", "backup"]):
            return "WARNING"
        return "INFO"

    def generate_vulnerability_report(self):
        """Genera un informe limpio con solo vulnerabilidades explotables o críticas."""
        filename = "vulnerabilidades_detectadas.txt"
        critical_findings = [r for r in self.results if self.classify_finding(r.get("Findings", "")) == "CRITICAL"]
        warning_findings = [r for r in self.results if self.classify_finding(r.get("Findings", "")) == "WARNING"]
        
        if not critical_findings and not warning_findings:
            return

        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write("="*60 + "\n")
                f.write(f"INFORME DE VULNERABILIDADES - {self.base_url}\n")
                f.write("="*60 + "\n\n")
                
                if critical_findings:
                    f.write("[!] HALLAZGOS CRÍTICOS / EXPLOTABLES\n")
                    f.write("-" * 40 + "\n")
                    for r in critical_findings:
                        f.write(f"Endpoint: {r['Endpoint']}\n")
                        f.write(f"Hallazgo: {r['Findings']}\n")
                        f.write("-" * 20 + "\n")
                    f.write("\n")
                
                if warning_findings:
                    f.write("[*] ADVERTENCIAS / EXPOSICIÓN DE INFORMACIÓN\n")
                    f.write("-" * 40 + "\n")
                    for r in warning_findings:
                        f.write(f"Endpoint: {r['Endpoint']}\n")
                        f.write(f"Hallazgo: {r['Findings']}\n")
                        f.write("-" * 20 + "\n")
            
            print(f"\n{C_GREEN}[+] Informe de vulnerabilidades críticas generado: {filename}{C_RESET}")
        except Exception as e:
            print(f"{C_RED}[!] Error al generar informe: {e}{C_RESET}")

    def show_summary(self):
        """Muestra un resumen estadístico de los hallazgos con colores correctos."""
        print(f"\n{C_CYAN}{'='*60}\n[+] RESUMEN DE LA AUDITORÍA\n{'='*60}{C_RESET}")
        
        critical = 0
        warning = 0
        info = 0
        
        for res in self.results:
            severity = self.classify_finding(res.get("Findings", ""))
            if severity == "CRITICAL": critical += 1
            elif severity == "WARNING": warning += 1
            else: info += 1
        
        print(f"    {C_RED}[!!!] CRÍTICOS (Explotables): {critical}{C_RESET}")
        print(f"    {C_YELLOW}[!] ADVERTENCIAS (Riesgo):   {warning}{C_RESET}")
        print(f"    {C_CYAN}[i] INFORMATIVOS:           {info}{C_RESET}")
        if self.filtered_redirects > 0:
            print(f"    {C_BLUE}[-] Falsos positivos filtrados (Redirect/Soft-404): {self.filtered_redirects}{C_RESET}")
        print(f"{C_CYAN}{'='*60}{C_RESET}")
        
        self.generate_vulnerability_report()

    async def run_async(self, skip_phases=None):
        skip_phases = skip_phases or []
        print_rainbow(CONTRALORIA_BANNER)
        print(f"\n{C_CYAN}{'='*60}\n[+] Iniciando Auditoría Segura Avanzada WP en: {self.base_url}\n{'='*60}{C_RESET}")
        
        if not self.client:
            async with httpx.AsyncClient(verify=self.verify_ssl, timeout=self.req_timeout) as client:
                self.client = client
                await self._run_phases(skip_phases)
        else:
            await self._run_phases(skip_phases)
            
        self.export_results()
        self.show_summary()
        print(f"\n{C_GREEN}[*] ¡Auditoría finalizada exitosamente!{'='*20}{C_RESET}")

    async def _run_phases(self, skip_phases):
        if "recon" not in skip_phases: await self.recon()
        if "active_plugins" not in skip_phases: await self.test_active_plugins()
        if "headers" not in skip_phases: await self.test_security_headers()
        if "theme" not in skip_phases: await self.test_theme_version()
        if "ports" not in skip_phases: await self.test_ports()
        if "ssl_tls" not in skip_phases: await self.test_ssl_tls()
        if "xmlrpc" not in skip_phases: await self.test_xmlrpc()
        if "rest" not in skip_phases: await self.test_rest_users()
        if "author" not in skip_phases: await self.test_author_enum()
        if "login" not in skip_phases: await self.test_login_enum()
        if "cron" not in skip_phases: await self.test_wp_cron()
        if "cli" not in skip_phases: await self.test_wp_cli()
        if "dir" not in skip_phases: await self.check_directory_listing()
        if "server_config" not in skip_phases: await self.test_server_config()
        if "uploads" not in skip_phases: await self.test_uploads_leak()
        if "classic" not in skip_phases: await self.test_classic_files()
        if "passive_malware" not in skip_phases: await self.test_passive_malware()
        if "routes" not in skip_phases: await self.scan_routes()

    def run(self, skip_phases=None):
        try:
            asyncio.run(self.run_async(skip_phases))
        except KeyboardInterrupt:
            print(f"\n{C_RED}[!] Proceso cancelado por el usuario.{C_RESET}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Auditoría Básica y Segura de WordPress")
    parser.add_argument("-u", "--url", required=True, help="Dominio objetivo (ej: https://ejemplo.cl)")
    parser.add_argument("-w", "--wordlist", help="Ruta a wordlist personalizada (opcional)")
    parser.add_argument("-o", "--output", help="Ruta para exportar resultados a CSV (opcional, ej: reporte.csv)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Número de hilos concurrentes para el escaneo (por defecto: 5)")
    parser.add_argument("-d", "--delay", type=float, default=0, help="Retraso base en segundos entre peticiones (por defecto: 0)")
    parser.add_argument("-j", "--jitter", type=float, default=0, help="Porcentaje de variación aleatoria del retraso (0-100) para evitar patrones agresivos de tráfico (por defecto: 0)")
    parser.add_argument("--nvd-key", help="Clave API de NVD (NIST) para evitar rate limits")
    parser.add_argument("--verify-ssl", action="store_true", help="Habilitar verificación de certificados SSL (por defecto: False)")
    parser.add_argument("--skip", help="Fases a saltar separadas por coma (ej: ports,routes,cron,headers,theme,uploads)")

    args = parser.parse_args()

    # Disable threading if delay/jitter is explicitly used to maintain realistic flow
    if args.delay > 0 and args.threads > 1:
        print(f"{C_YELLOW}[!] Delay activado: Reduciendo hilos a 1 para evitar patrones agresivos de tráfico.{C_RESET}")
        args.threads = 1

    skip_list = args.skip.split(",") if args.skip else []

    auditor = WPAuditor(
        args.url, 
        args.wordlist, 
        args.output, 
        args.threads, 
        args.delay, 
        args.jitter,
        nvd_key=args.nvd_key,
        verify_ssl=args.verify_ssl
    )
    auditor.run(skip_phases=skip_list)
