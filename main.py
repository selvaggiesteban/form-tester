#!/usr/bin/env python3
"""
Form Tester - Automated Contact Form Testing Tool
Author: Esteban Selvaggi
Website: https://selvaggiesteban.dev
Repository: https://github.com/selvaggiesteban/form-tester.git

A command-line tool that crawls websites, identifies contact forms,
submits test data, and falls back to SMTP email delivery when forms
are unavailable or protected by anti-spam measures.
"""

# =============================================================================
# CONFIGURATION SECTION - Modify these settings as needed
# =============================================================================

# SMTP Configuration
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = ""  # Set via environment variable: FORM_TESTER_SMTP_USER
SMTP_PASSWORD = ""  # Set via environment variable: FORM_TESTER_SMTP_PASSWORD
SMTP_FROM_EMAIL = ""  # Set via environment variable: FORM_TESTER_FROM_EMAIL

# Test Data - Configure with your own information
TEST_DATA = {
    "name": "Test User",
    "email": "test@example.com",
    "subject": "Test Contact Form Submission",
    "message": "This is an automated test message from the form-tester tool.",
    "phone": "+1-555-123-4567",  # Use hyphens, not spaces, for pattern validation
    "company": "Test Company Inc.",
}

# Crawler Settings
MAX_PAGES_PER_DOMAIN = 10
REQUEST_TIMEOUT = 30
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
RATE_LIMIT_DELAY = 1.0  # Seconds between requests to same domain
MAX_RETRIES = 3

# Form Detection
FORM_FIELD_MAPPINGS = {
    "name": [
        "name", "nombre", "fullname", "full_name", "your_name", "contact_name",
        "first_name", "last_name", "firstname", "lastname", "apellido", "nombres",
        "from_name", "user_name", "customer_name", "client_name", "visitor_name",
        "nom", "prenom", "nome", "cognome"
    ],
    "email": [
        "email", "correo", "e-mail", "mail", "email_address", "your_email",
        "from_email", "contact_email", "user_email", "customer_email", "client_email",
        "visitor_email", "reply_to", "replyto", "correo_electronico", "email_destinatario",
        "adresse_email", "courriel", "indirizzo_email"
    ],
    "subject": [
        "subject", "asunto", "topic", "title", "tema", "motivo", "razon",
        "subject_line", "mail_subject", "message_subject", "consulta_subject",
        "about", "regarding", "re", "asunto_del_mensaje", "titulo",
        "sujet", "objet", "oggetto", "assunto"
    ],
    "message": [
        "message", "mensaje", "comments", "comment", "body", "content", "your_message",
        "msg", "text", "description", "details", "consulta", "consultation",
        "query", "inquiry", "question", "note", "notes", "additional_info",
        "more_info", "informacion_adicional", "mensaje_adicional", "comentarios",
        "textarea", "your_message_text", "message_body", "mail_body",
        "votre_message", "votre_commentaire", "il_tuo_messaggio"
    ],
    "phone": [
        "phone", "telefono", "tel", "telephone", "mobile", "cell", "cellphone",
        "phone_number", "telefono_fijo", "celular", "movil", "numero_telefono",
        "contact_number", "phone_no", "tel_no", "mobile_number", "telefono_contacto",
        "telephone_portable", "numero_de_telephone", "telefono_cellulare"
    ],
    "company": [
        "company", "empresa", "organization", "business", "firma", "organizacion",
        "company_name", "business_name", "organization_name", "nombre_empresa",
        "work_place", "workplace", "employer", "entidad", "razon_social",
        "societe", "entreprise", "societa", "azienda", "empresa_nome"
    ],
}

# Output Files
DOMAINS_FILE = "domains.csv"
RESULTS_FILE = "results.csv"
SUPPRESSION_FILE = "suppression_list.csv"
EVIDENCE_DIR = "evidence"

# Reason Codes for logging
REASON_CODES = {
    "FORM_SUBMITTED_SUCCESS": "Formulario enviado exitosamente",
    "HAS_RECAPTCHA": "reCAPTCHA detectado, envío omitido",
    "HAS_HCAPTCHA": "hCAPTCHA detectado, envío omitido",
    "NO_FORM_FOUND": "No se encontró formulario de contacto",
    "EMAIL_SENT": "Email enviado vía SMTP como fallback",
    "HARD_BOUNCE": "Bounce permanente detectado, agregado a suppression list",
    "FORM_FILL_ERROR": "Error al completar campos del formulario",
    "HONEYPOT_DETECTED": "Honeypot detectado, envío omitido",
    "NETWORK_ERROR": "Error de red al acceder al sitio",
    "TIMEOUT_ERROR": "Timeout en la solicitud",
    "SMTP_ERROR": "Error al enviar email vía SMTP",
    "UNKNOWN_ERROR": "Error desconocido",
    "SUPPRESSED": "Email en lista de supresión",
    "FORM_VALIDATION_FAILED": "Validación del formulario fallida",
}

# =============================================================================
# IMPORTS
# =============================================================================

import asyncio
import csv
import json
import os
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import click
import httpx
from dotenv import load_dotenv
from selectolax.lexbor import LexborHTMLParser

# Load environment variables
load_dotenv()

# Override config with environment variables
SMTP_USER = os.getenv("FORM_TESTER_SMTP_USER", SMTP_USER)
SMTP_PASSWORD = os.getenv("FORM_TESTER_SMTP_PASSWORD", SMTP_PASSWORD)
SMTP_FROM_EMAIL = os.getenv("FORM_TESTER_FROM_EMAIL", SMTP_FROM_EMAIL)

# Proxy Configuration (optional)
PROXY_URL = os.getenv("FORM_TESTER_PROXY_URL", "")
HTTP_PROXY = os.getenv("FORM_TESTER_HTTP_PROXY", "")
HTTPS_PROXY = os.getenv("FORM_TESTER_HTTPS_PROXY", "")


# =============================================================================
# DATA CLASSES
# =============================================================================

class DomainTask:
    """Represents a task for processing a domain."""

    def __init__(self, domain: str, target_email: str = ""):
        self.domain = domain
        self.target_email = target_email
        self.visited_urls: Set[str] = set()
        self.forms_found: List[Dict] = []
        self.emails_found: Set[str] = set()
        self.results: List[Dict] = []


class FormData:
    """Represents a detected contact form."""

    def __init__(self, url: str, html: str, fields: Dict, submit_button: Optional[str] = None):
        self.url = url
        self.html = html
        self.fields = fields
        self.submit_button = submit_button
        self.has_captcha = False
        self.has_honeypot = False
        self.captcha_type: Optional[str] = None


# =============================================================================
# CSV HANDLING
# =============================================================================

def load_domains(filename: str = DOMAINS_FILE) -> List[DomainTask]:
    """Load domains from CSV file.

    Expected CSV format: domain,email (optional)
    Example: example.com,contact@example.com
    """
    tasks = []
    path = Path(filename)

    if not path.exists():
        click.echo(f"⚠️  Archivo {filename} no encontrado. Creando archivo de ejemplo...")
        create_sample_domains_file(filename)
        return []

    with open(path, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            domain = row[0].strip()
            email = row[1].strip() if len(row) > 1 else ""
            if domain:
                tasks.append(DomainTask(domain, email))

    return tasks


def create_sample_domains_file(filename: str):
    """Create a sample domains.csv file."""
    with open(filename, "w", encoding="utf-8") as f:
        f.write("# Domains to test - format: domain,email (optional)\n")
        f.write("example.com,contact@example.com\n")
        f.write("testsite.org\n")


def load_suppression_list(filename: str = SUPPRESSION_FILE) -> Set[str]:
    """Load suppressed email addresses from file."""
    suppressed = set()
    path = Path(filename)

    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                if row and not row[0].startswith("#"):
                    suppressed.add(row[0].strip().lower())

    return suppressed


def add_to_suppression_list(email: str, reason: str, filename: str = SUPPRESSION_FILE):
    """Add an email to the suppression list."""
    path = Path(filename)
    file_exists = path.exists()

    with open(path, "a", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["email", "reason", "date_added"])
        writer.writerow([email.lower(), reason, datetime.now().isoformat()])


def log_result(
    domain: str,
    action: str,
    status: str,
    reason_code: str,
    details: str = "",
    evidence_path: str = "",
    filename: str = RESULTS_FILE,
):
    """Log a result to the results CSV file."""
    path = Path(filename)
    file_exists = path.exists()

    with open(path, "a", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow([
                "timestamp",
                "domain",
                "action",
                "status",
                "reason_code",
                "reason_description",
                "details",
                "evidence_path",
            ])
        writer.writerow([
            datetime.now().isoformat(),
            domain,
            action,
            status,
            reason_code,
            REASON_CODES.get(reason_code, reason_code),
            details,
            evidence_path,
        ])


# =============================================================================
# CRAWLER
# =============================================================================

class WebCrawler:
    """Crawls websites to find contact forms and email addresses."""

    def __init__(self, task: DomainTask):
        self.task = task
        self.base_url = self._normalize_url(task.domain)
        self.domain_hosts = {urlparse(self.base_url).netloc}
        self.last_request_time: Dict[str, float] = {}

    def _normalize_url(self, domain: str) -> str:
        """Normalize domain to full URL."""
        if not domain.startswith(("http://", "https://")):
            return f"https://{domain}"
        return domain

    async def _rate_limited_request(self, client: httpx.AsyncClient, url: str) -> Optional[httpx.Response]:
        """Make a rate-limited HTTP request."""
        host = urlparse(url).netloc
        now = time.time()

        # Rate limiting
        if host in self.last_request_time:
            elapsed = now - self.last_request_time[host]
            if elapsed < RATE_LIMIT_DELAY:
                await asyncio.sleep(RATE_LIMIT_DELAY - elapsed)

        for attempt in range(MAX_RETRIES):
            try:
                self.last_request_time[host] = time.time()
                response = await client.get(
                    url,
                    timeout=REQUEST_TIMEOUT,
                    follow_redirects=True,
                )
                return response
            except httpx.TimeoutException:
                if attempt == MAX_RETRIES - 1:
                    return None
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
            except Exception:
                if attempt == MAX_RETRIES - 1:
                    return None
                await asyncio.sleep(2 ** attempt)

        return None

    async def crawl(self) -> Tuple[List[FormData], Set[str]]:
        """Crawl the domain for contact forms and emails."""
        forms_found = []
        emails_found = set()

        # Contador separado para páginas dinámicas descubiertas
        self.dynamic_pages_visited = 0
        max_dynamic_pages = MAX_PAGES_PER_DOMAIN  # 10 páginas

        # IP address to mask real IP (RFC 5737 documentation range)
        FAKE_IP = "203.0.113.1"

        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            # Headers to mask real IP (some servers may respect these)
            "X-Forwarded-For": FAKE_IP,
            "X-Real-IP": FAKE_IP,
            "Forwarded": f"for={FAKE_IP}",
            "CF-Connecting-IP": FAKE_IP,
        }

        # Configure proxy if set
        proxy_config = None
        if PROXY_URL:
            proxy_config = PROXY_URL
        elif HTTP_PROXY or HTTPS_PROXY:
            proxy_config = {
                "http://": HTTP_PROXY or PROXY_URL,
                "https://": HTTPS_PROXY or PROXY_URL,
            }

        async with httpx.AsyncClient(headers=headers, proxy=proxy_config) as client:
            urls_to_visit = [self.base_url]

            # Agregar URLs de contacto comunes al inicio
            contact_urls = [
                "/contacto",
                "/contacto/",
                "/contact",
                "/contact/",
            ]
            base = self.base_url.rstrip('/')
            for contact_path in contact_urls:
                contact_url = f"{base}{contact_path}"
                if contact_url not in urls_to_visit:
                    urls_to_visit.append(contact_url)
                    click.echo(f"  📌 URL de contacto agregada: {contact_url}")

            while urls_to_visit:
                url = urls_to_visit.pop(0)

                if url in self.task.visited_urls:
                    continue

                # Verificar si es una URL predefinida o dinámica
                is_predefined = any(url.endswith(path) or url.rstrip('/').endswith(path.rstrip('/'))
                                    for path in ["/contacto", "/contact"])

                # Si es dinámica y ya alcanzamos el límite, saltar
                if not is_predefined and self.dynamic_pages_visited >= max_dynamic_pages:
                    continue

                self.task.visited_urls.add(url)
                if not is_predefined:
                    self.dynamic_pages_visited += 1

                click.echo(f"  🔍 Crawling: {url}")

                response = await self._rate_limited_request(client, url)
                if not response or response.status_code != 200:
                    continue

                content_type = response.headers.get("content-type", "")
                if "text/html" not in content_type:
                    continue

                # Parse HTML
                html_content = response.text
                parser = LexborHTMLParser(html_content)

                # Look for contact forms
                page_forms = self._extract_forms(parser, url, html_content)
                forms_found.extend(page_forms)

                # Look for emails
                page_emails = self._extract_emails(parser, html_content)
                emails_found.update(page_emails)

                # Find links to follow
                new_urls = self._extract_links(parser, url)
                for new_url in new_urls:
                    if self._is_contact_page(new_url) and new_url not in self.task.visited_urls:
                        urls_to_visit.insert(0, new_url)  # Prioritize contact pages
                    elif new_url not in self.task.visited_urls:
                        urls_to_visit.append(new_url)

        return forms_found, emails_found

    def _extract_forms(self, parser: LexborHTMLParser, url: str, html: str) -> List[FormData]:
        """Extract contact forms from the page."""
        forms = []

        for form_node in parser.css("form"):
            form_html = form_node.html
            fields = {}
            submit_button = None
            all_inputs = []  # Para debugging

            # Extract ALL input fields (incluyendo ocultos para mejor detección)
            for input_node in form_node.css("input, textarea, select"):
                input_type = input_node.attributes.get("type", "text").lower()
                input_name = input_node.attributes.get("name", "")
                input_id = input_node.attributes.get("id", "")
                placeholder = input_node.attributes.get("placeholder", "").lower()

                # Buscar label asociado al campo
                label_text = self._find_field_label(parser, input_id, input_name)

                all_inputs.append({
                    "type": input_type,
                    "name": input_name,
                    "id": input_id,
                    "placeholder": placeholder,
                    "label": label_text,
                })

                # Skip submit/button inputs para el mapeo de campos
                if input_type in ("submit", "button", "image"):
                    if input_type == "submit":
                        submit_button = input_name or input_id
                    continue

                # Map field to known types (incluyendo campos ocultos)
                field_key = self._classify_field(input_name, input_id, placeholder, label_text)
                if field_key:
                    fields[field_key] = {
                        "name": input_name,
                        "id": input_id,
                        "type": input_type,
                        "placeholder": placeholder,
                    }

            # Check if this looks like a contact form
            # Criterio: debe tener campo email + (mensaje O nombre)
            has_email = "email" in fields
            has_message = "message" in fields
            has_name = "name" in fields

            if has_email and (has_message or has_name):
                form_data = FormData(url, form_html, fields, submit_button)

                # Check for CAPTCHA
                if self._has_captcha(html):
                    form_data.has_captcha = True
                    if "recaptcha" in html.lower():
                        form_data.captcha_type = "reCAPTCHA"
                    elif "hcaptcha" in html.lower():
                        form_data.captcha_type = "hCAPTCHA"

                # Check for honeypot
                if self._has_honeypot(form_node):
                    click.echo(f"        ⚠️  Honeypot detectado, pero se procesará de todos modos")
                    form_data.has_honeypot = True

                forms.append(form_data)
            elif has_email:
                # Debug: mostrar por qué no se detectó como formulario de contacto
                click.echo(f"     ℹ️  Formulario con email encontrado pero sin message/name: {url}")
                click.echo(f"        Campos detectados: {list(fields.keys())}")

        return forms

    def _find_field_label(self, parser: LexborHTMLParser, field_id: str, field_name: str) -> str:
        """Find label text associated with a field."""
        label_text = ""

        if field_id:
            # Buscar label con atributo for
            label_node = parser.css_first(f"label[for='{field_id}']")
            if label_node:
                label_text = label_node.text(strip=True).lower()

        if not label_text and field_name:
            # Buscar label con atributo for por name
            label_node = parser.css_first(f"label[for='{field_name}']")
            if label_node:
                label_text = label_node.text(strip=True).lower()

        return label_text

    def _classify_field(self, name: str, field_id: str, placeholder: str, label_text: str = "") -> Optional[str]:
        """Classify a form field based on its attributes and label."""
        search_text = f"{name} {field_id} {placeholder} {label_text}".lower()

        for field_type, keywords in FORM_FIELD_MAPPINGS.items():
            for keyword in keywords:
                if keyword in search_text:
                    return field_type

        # Heurísticas adicionales para campos comunes
        # Si tiene type="email", es probablemente email
        if "email" in search_text or "correo" in search_text or "e-mail" in search_text:
            return "email"

        # Si parece un campo de asunto pero no se detectó antes
        if any(word in search_text for word in ["asunto", "subject", "tema", "motivo"]):
            return "subject"

        # Si parece un campo de teléfono
        if any(word in search_text for word in ["phone", "telefono", "tel", "mobile", "celular"]):
            return "phone"

        return None

    def _has_captcha(self, html: str) -> bool:
        """Check if the page has CAPTCHA protection."""
        captcha_indicators = [
            "recaptcha",
            "g-recaptcha",
            "hcaptcha",
            "h-captcha",
            "data-sitekey",
            "captcha",
        ]
        html_lower = html.lower()
        return any(indicator in html_lower for indicator in captcha_indicators)

    def _has_honeypot(self, form_node) -> bool:
        """Check if the form has a honeypot field.

        Honeypots are fields designed to trick bots. They are typically:
        - Fields hidden from users (display:none, visibility:hidden, off-screen)
        - Fields with names that sound legitimate but are actually traps
        """
        # Contar campos visibles vs ocultos
        visible_fields = 0
        hidden_fields = 0
        honeypot_indicators = 0

        for input_node in form_node.css("input"):
            input_type = input_node.attributes.get("type", "").lower()
            input_name = input_node.attributes.get("name", "").lower()
            style = input_node.attributes.get("style", "").lower()

            # Saltar campos de tipo submit, button, image
            if input_type in ("submit", "button", "image"):
                continue

            # Verificar si es un campo oculto
            is_hidden = input_type == "hidden"
            is_css_hidden = "display:none" in style or "visibility:hidden" in style
            is_off_screen = "left:-" in style or "top:-" in style

            if is_hidden or is_css_hidden or is_off_screen:
                hidden_fields += 1

                # Solo marcar como honeypot si el campo oculto tiene nombre sospechoso
                # y NO hay otros campos legítimos visibles en el formulario
                honeypot_names = ["email", "name", "phone", "url", "website", "company"]
                if any(keyword in input_name for keyword in honeypot_names):
                    # Verificar si tiene prefijos/sufijos típicos de honeypot
                    if any(indicator in input_name for indicator in [
                        "trap", "honeypot", "bot", "spam", "sneaky",
                        "_chk", "check", "verify", "validation"
                    ]):
                        honeypot_indicators += 1
            else:
                visible_fields += 1

        # Es honeypot si hay indicadores fuertes de honeypot
        # O si hay campos ocultos sospechosos sin campos visibles
        if honeypot_indicators > 0:
            return True

        # No es honeypot si hay campos visibles (formulario legítimo)
        if visible_fields > 0:
            return False

        # Solo campos ocultos = probable honeypot
        return hidden_fields > 0 and visible_fields == 0

    def _extract_emails(self, parser: LexborHTMLParser, html: str) -> Set[str]:
        """Extract email addresses from the page."""
        emails = set()

        # Look for mailto: links
        for link in parser.css("a[href^='mailto:']"):
            href = link.attributes.get("href", "")
            if href.startswith("mailto:"):
                email = href[7:].split("?")[0].strip()
                if self._is_valid_email(email):
                    emails.add(email.lower())

        # Look for email patterns in text
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        matches = re.findall(email_pattern, html)
        for email in matches:
            if self._is_valid_email(email):
                emails.add(email.lower())

        return emails

    def _is_valid_email(self, email: str) -> bool:
        """Validate email format."""
        pattern = r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$'
        return bool(re.match(pattern, email))

    def _extract_links(self, parser: LexborHTMLParser, base_url: str) -> List[str]:
        """Extract internal links from the page."""
        links = []

        for link in parser.css("a[href]"):
            href = link.attributes.get("href", "").strip()
            text = link.text(strip=True).lower()

            if not href:
                continue

            # Skip external links (completamente diferentes dominios)
            if href.startswith(("http://", "https://")):
                parsed_href = urlparse(href)
                parsed_base = urlparse(base_url)
                # Solo incluir si es el mismo dominio
                if parsed_href.netloc != parsed_base.netloc:
                    continue
                full_url = href
            elif href.startswith("//"):
                # Protocol-relative URL
                parsed_base = urlparse(base_url)
                full_url = f"{parsed_base.scheme}:{href}"
            elif href.startswith("/"):
                # Absolute path
                full_url = urljoin(base_url, href)
            elif href.startswith(("#", "javascript:", "mailto:", "tel:")):
                # Skip anchors and special links
                continue
            else:
                # Relative path
                full_url = urljoin(base_url, href)

            # Normalizar URL (eliminar fragmentos)
            parsed = urlparse(full_url)
            full_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if parsed.query:
                full_url += f"?{parsed.query}"

            links.append(full_url)

        return links

    def _is_contact_page(self, text: str) -> bool:
        """Check if URL or text looks like a contact page."""
        contact_keywords = [
            "contact", "contacto", "kontakt", "contactenos",
            "reach-us", "get-in-touch", "write-us", "escribenos",
            "help", "support", "ayuda", "soporte",
            "about", "nosotros", "about-us", "acerca"
        ]
        text_lower = text.lower()
        return any(keyword in text_lower for keyword in contact_keywords)


# =============================================================================
# SMTP MODULE
# =============================================================================

class SMTPSender:
    """Sends emails via SMTP with bounce handling."""

    def __init__(self):
        self.host = SMTP_HOST
        self.port = SMTP_PORT
        self.user = SMTP_USER
        self.password = SMTP_PASSWORD
        self.from_email = SMTP_FROM_EMAIL or SMTP_USER

    async def send_email(self, to_email: str, subject: str = "", body: str = "") -> Tuple[bool, str]:
        """Send an email via SMTP."""
        if not all([self.host, self.user, self.password]):
            return False, "SMTP credentials not configured"

        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart

            msg = MIMEMultipart()
            msg["From"] = self.from_email
            msg["To"] = to_email
            msg["Subject"] = subject or TEST_DATA["subject"]

            body_text = body or TEST_DATA["message"]
            msg.attach(MIMEText(body_text, "plain"))

            with smtplib.SMTP(self.host, self.port) as server:
                server.starttls()
                server.login(self.user, self.password)
                server.send_message(msg)

            return True, "Email sent successfully"

        except smtplib.SMTPRecipientsRefused as e:
            return False, f"Hard bounce: {str(e)}"
        except smtplib.SMTPException as e:
            return False, f"SMTP error: {str(e)}"
        except Exception as e:
            return False, f"Unknown error: {str(e)}"


# =============================================================================
# FORM SUBMITTER (Playwright)
# =============================================================================

class FormSubmitter:
    """Submits forms using Playwright for JavaScript support."""

    def __init__(self):
        self.evidence_dir = Path(EVIDENCE_DIR)
        self.evidence_dir.mkdir(exist_ok=True)

    async def submit_form(self, form: FormData) -> Tuple[bool, str, str]:
        """Submit a form using Playwright with proper validation."""
        evidence_path = ""
        unfilled_fields = []

        try:
            from playwright.async_api import async_playwright

            async with async_playwright() as p:
                # Configure proxy for Playwright if set
                proxy_config = None
                if PROXY_URL:
                    proxy_config = {"server": PROXY_URL}
                elif HTTP_PROXY:
                    proxy_config = {"server": HTTP_PROXY}

                browser = await p.chromium.launch(headless=True)

                # IP address to mask real IP
                FAKE_IP = "203.0.113.1"

                context_options = {
                    "user_agent": USER_AGENT,
                    "viewport": {"width": 1280, "height": 720},
                    "extra_http_headers": {
                        "Accept-Language": "en-US,en;q=0.5",
                        "Accept-Encoding": "gzip, deflate, br",
                        "DNT": "1",
                        "Upgrade-Insecure-Requests": "1",
                        "Sec-Fetch-Dest": "document",
                        "Sec-Fetch-Mode": "navigate",
                        "Sec-Fetch-Site": "none",
                        "Sec-Fetch-User": "?1",
                        "X-Forwarded-For": FAKE_IP,
                        "X-Real-IP": FAKE_IP,
                        "Forwarded": f"for={FAKE_IP}",
                        "CF-Connecting-IP": FAKE_IP,
                    },
                }

                if proxy_config:
                    context_options["proxy"] = proxy_config

                context = await browser.new_context(**context_options)
                page = await context.new_page()

                # Navigate to the form page
                response = await page.goto(form.url, wait_until="networkidle", timeout=30000)

                # Check if page loaded successfully
                if response and response.status >= 400:
                    await browser.close()
                    return False, f"HTTP_ERROR: Page returned status {response.status}", ""

                # Fill in form fields
                for field_type, field_info in form.fields.items():
                    value = TEST_DATA.get(field_type, "")
                    if value:
                        # Probar múltiples selectores mejorados
                        selectors = [
                            f"[name='{field_info['name']}']",
                            f"#{field_info['id']}",
                            f"input[name*='{field_info['name']}']",
                            f"textarea[name*='{field_info['name']}']",
                            f"input[placeholder*='{field_info['name']}']",
                            f"textarea[placeholder*='{field_info['name']}']",
                            f"input[type='{field_info['type']}']",
                        ]
                        filled = False
                        for selector in selectors:
                            try:
                                # Check if element exists and is visible
                                element = await page.query_selector(selector)
                                if element:
                                    is_visible = await element.is_visible()
                                    if is_visible:
                                        await page.fill(selector, value)
                                        filled = True
                                        break
                            except:
                                continue
                        if not filled:
                            unfilled_fields.append(field_type)
                            if field_type in ["email", "message"]:
                                click.echo(f"        ⚠️  No se pudo llenar campo CRÍTICO {field_type}")
                            else:
                                click.echo(f"        ℹ️  Campo opcional {field_type} no encontrado, continuando...")

                # Check if critical fields were not filled
                critical_fields = ["email", "message"]
                missing_critical = [f for f in critical_fields if f in form.fields and f in unfilled_fields]
                if missing_critical:
                    await browser.close()
                    return False, f"FORM_FILL_ERROR: Could not fill critical fields: {', '.join(missing_critical)}", ""

                # Log optional fields that were skipped
                optional_unfilled = [f for f in unfilled_fields if f not in critical_fields]
                if optional_unfilled:
                    click.echo(f"        ℹ️  Campos opcionales omitidos: {', '.join(optional_unfilled)}")

                # Take screenshot before submission
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                domain = urlparse(form.url).netloc.replace(".", "_")
                screenshot_path = self.evidence_dir / f"{domain}_{timestamp}_before.png"
                await page.screenshot(path=str(screenshot_path), full_page=True)
                evidence_path = str(screenshot_path)

                # Submit the form
                submit_clicked = False
                if form.submit_button:
                    try:
                        await page.click(f"[name='{form.submit_button}']")
                        submit_clicked = True
                    except:
                        pass
                else:
                    # Try to find submit button
                    submit_selectors = [
                        "button[type='submit']",
                        "input[type='submit']",
                        "button:has-text('Send')",
                        "button:has-text('Submit')",
                        "button:has-text('Enviar')",
                        "button:has-text('Enviar mensaje')",
                        "button:has-text('Contactar')",
                        "button:has-text('Enviar correo')",
                        "input[value*='Enviar']",
                        "input[value*='Send']",
                        "input[value*='Submit']",
                    ]
                    for selector in submit_selectors:
                        try:
                            await page.click(selector, timeout=2000)
                            submit_clicked = True
                            break
                        except:
                            continue

                if not submit_clicked:
                    await browser.close()
                    return False, "FORM_SUBMIT_ERROR: Could not find or click submit button", evidence_path

                # Wait for response with multiple strategies
                # Para WordPress/Contact Form 7, esperar respuesta AJAX
                try:
                    # Intentar detectar respuesta AJAX de Contact Form 7
                    await page.wait_for_selector(".wpcf7-response-output", timeout=10000)
                except:
                    # Si no es CF7, esperar carga normal
                    try:
                        await page.wait_for_load_state("networkidle", timeout=10000)
                    except:
                        # Networkidle might not fire, wait for timeout or domcontentloaded
                        try:
                            await page.wait_for_load_state("domcontentloaded", timeout=5000)
                        except:
                            pass

                # Esperar un poco más para AJAX
                await asyncio.sleep(2)

                # Take screenshot after submission
                screenshot_path_after = self.evidence_dir / f"{domain}_{timestamp}_after.png"
                await page.screenshot(path=str(screenshot_path_after), full_page=True)

                # Wait a bit for any AJAX responses (WordPress/Contact Form 7)
                await asyncio.sleep(2)

                # Validate submission result
                validation_result = await self._validate_submission(page)

                # Siempre guardar HTML para diagnóstico (tanto éxito como fallo)
                html_path = self.evidence_dir / f"{domain}_{timestamp}_debug.html"
                try:
                    html_content = await page.content()
                    with open(html_path, "w", encoding="utf-8") as f:
                        f.write(html_content)
                    if not validation_result["success"]:
                        click.echo(f"        📝 HTML guardado para diagnóstico: {html_path}")
                except Exception as e:
                    click.echo(f"        ⚠️  No se pudo guardar HTML: {e}")

                await browser.close()

                if validation_result["success"]:
                    return True, "FORM_SUBMITTED_SUCCESS", evidence_path
                else:
                    return False, f"FORM_VALIDATION_FAILED: {validation_result['reason']}", evidence_path

        except Exception as e:
            return False, f"UNKNOWN_ERROR: {str(e)}", evidence_path

    async def _validate_submission(self, page) -> dict:
        """Validate if the form submission was successful by checking page content."""
        try:
            # Get page content and URL
            content = await page.content()
            content_lower = content.lower()
            url = page.url

            # Success indicators in multiple languages
            success_indicators = [
                "gracias", "thank you", "thanks", "merci", "grazie",
                "mensaje enviado", "message sent", "sent successfully",
                "enviado correctamente", "sent successfully",
                "mensaje recibido", "message received",
                "contacto recibido", "contact received",
                "success", "éxito", "succès", "successo",
                "confirmación", "confirmation",
                "nos pondremos en contacto", "we will contact you",
                "respuesta enviada", "response submitted",
                # Contact Form 7 específico
                "wpcf7-mail-sent-ok",
                # Elementor específico
                "elementor-message-success",
                "form submitted successfully",
            ]

            # Server/Technical error indicators - específicos para errores reales
            error_indicators = [
                # Errores HTTP explícitos
                "http error", "server error", "internal server error",
                "bad request", "forbidden", "unauthorized",
                # Errores de envío específicos
                "failed to send", "no se pudo enviar", "could not send",
                "message failed", "el mensaje no se pudo enviar",
                "envío fallido", "submission failed",
                # Errores de validación de servidor
                "validation failed", "invalid submission",
                "spam detected", "blocked",
            ]

            # Field validation indicators - estos son solo validaciones, no errores del servidor
            field_validation_indicators = [
                "required", "requerido", "obligatorio", "requis",
                "por favor complete", "please fill",
                "campo vacío", "empty field", "missing", "falta", "manquant",
            ]

            # Check for success indicators
            found_success = any(indicator in content_lower for indicator in success_indicators)

            # Check for server/technical errors (solo errores específicos, no la palabra "error" sola)
            found_error = any(indicator in content_lower for indicator in error_indicators)

            # Check for field validation messages
            found_field_validation = any(indicator in content_lower for indicator in field_validation_indicators)

            # Check for form still present (might indicate submission failed)
            form_still_present = await page.query_selector("form") is not None

            # Analyze result
            if found_error and not found_success:
                return {"success": False, "reason": "Error messages detected on page"}

            # Si hay validación de campo pero no error del servidor, podría ser por campos opcionales faltantes
            # Intentar continuar si no hay error técnico grave
            if found_field_validation and not found_success and not found_error:
                # Si el formulario ya no está presente, probablemente se envió
                if not form_still_present:
                    return {"success": True, "reason": "Form submitted (field validation messages may indicate optional fields)"}

            if found_success:
                return {"success": True, "reason": "Success message detected"}

            # If URL changed (redirected), likely successful
            # but we can't be 100% sure without more context

            # If no clear indicators, be conservative
            if not found_success and not found_error:
                # Check if we're on a thank-you or confirmation page
                if any(word in url.lower() for word in ["thank", "gracias", "confirm", "success"]):
                    return {"success": True, "reason": "Redirected to success/confirmation page"}

                # If form is still there and no success message, likely failed
                if form_still_present:
                    return {"success": False, "reason": "Form still present, no success confirmation detected"}

                # Ambiguous case - form gone but no confirmation
                return {"success": False, "reason": "No success confirmation detected after submission"}

            return {"success": found_success, "reason": "Based on page content analysis"}

        except Exception as e:
            return {"success": False, "reason": f"Validation error: {str(e)}"}


# =============================================================================
# MAIN PROCESSING
# =============================================================================

class FormTester:
    """Main class for processing domains."""

    def __init__(self):
        self.smtp_sender = SMTPSender()
        self.form_submitter = FormSubmitter()
        self.suppression_list = load_suppression_list()

    async def process_domain(self, task: DomainTask) -> List[Dict]:
        """Process a single domain."""
        results = []
        domain = task.domain

        click.echo(f"\n{'='*60}")
        click.echo(f"🌐 Procesando: {domain}")
        click.echo(f"{'='*60}")

        # Crear directorio de evidencias si no existe
        evidence_dir = Path(EVIDENCE_DIR)
        evidence_dir.mkdir(exist_ok=True)
        click.echo(f"  📁 Directorio de evidencias: {evidence_dir.absolute()}")

        # Crawl the domain
        crawler = WebCrawler(task)
        forms, emails = await crawler.crawl()

        click.echo(f"\n  📊 Resultados del crawling:")
        click.echo(f"     - Páginas visitadas: {len(task.visited_urls)}")
        click.echo(f"     - Formularios encontrados: {len(forms)}")
        click.echo(f"     - Emails encontrados: {len(emails)}")

        # Process forms
        if forms:
            for form in forms:
                if form.has_captcha:
                    code = f"HAS_{form.captcha_type.upper().replace(' ', '_')}"
                    log_result(domain, "FORM_SKIP", "SKIPPED", code, f"Form at {form.url}")
                    results.append({"domain": domain, "action": "skip", "reason": code})
                    click.echo(f"  ⚠️  {code} detectado en {form.url}")
                    continue

                if form.has_honeypot:
                    log_result(domain, "FORM_SKIP", "SKIPPED", "HONEYPOT_DETECTED", f"Form at {form.url}")
                    results.append({"domain": domain, "action": "skip", "reason": "HONEYPOT_DETECTED"})
                    click.echo(f"  ⚠️  Honeypot detectado en {form.url}")
                    continue

                # Submit the form
                click.echo(f"  📝 Intentando enviar formulario en {form.url}")
                success, message, evidence = await self.form_submitter.submit_form(form)

                if success:
                    log_result(domain, "FORM_SUBMIT", "SUCCESS", "FORM_SUBMITTED_SUCCESS", f"Form at {form.url}", evidence)
                    results.append({"domain": domain, "action": "form_submit", "status": "success"})
                    click.echo(f"  ✅ Formulario enviado exitosamente")
                else:
                    log_result(domain, "FORM_SUBMIT", "FAILED", message, f"Form at {form.url}")
                    results.append({"domain": domain, "action": "form_submit", "status": "failed", "error": message})
                    click.echo(f"  ❌ Error al enviar formulario: {message}")

        else:
            # No form found - try email fallback
            click.echo(f"  📧 No se encontraron formularios, intentando envío por email...")

            # Get target email
            target_email = task.target_email
            if not target_email and emails:
                target_email = emails.pop()  # Use first found email

            if target_email:
                if target_email.lower() in self.suppression_list:
                    log_result(domain, "EMAIL", "SKIPPED", "SUPPRESSED", f"Email {target_email} in suppression list")
                    results.append({"domain": domain, "action": "email", "status": "suppressed"})
                    click.echo(f"  ⛔ Email {target_email} está en la lista de supresión")
                else:
                    success, message = await self.smtp_sender.send_email(target_email)

                    if success:
                        log_result(domain, "EMAIL", "SUCCESS", "EMAIL_SENT", f"To: {target_email}")
                        results.append({"domain": domain, "action": "email", "status": "success"})
                        click.echo(f"  ✅ Email enviado a {target_email}")
                    else:
                        if "Hard bounce" in message:
                            add_to_suppression_list(target_email, "Hard bounce from SMTP")
                            log_result(domain, "EMAIL", "FAILED", "HARD_BOUNCE", f"To: {target_email}, Error: {message}")
                            results.append({"domain": domain, "action": "email", "status": "hard_bounce"})
                            click.echo(f"  ❌ Hard bounce detectado para {target_email}")
                        else:
                            log_result(domain, "EMAIL", "FAILED", "SMTP_ERROR", f"To: {target_email}, Error: {message}")
                            results.append({"domain": domain, "action": "email", "status": "failed", "error": message})
                            click.echo(f"  ❌ Error SMTP: {message}")
            else:
                log_result(domain, "EMAIL", "FAILED", "NO_FORM_FOUND", "No contact form or email found")
                results.append({"domain": domain, "action": "none", "status": "no_contact_found"})
                click.echo(f"  ❌ No se encontró formulario ni email de contacto")

        return results

    async def process_all(self, tasks: List[DomainTask]) -> List[Dict]:
        """Process all domains."""
        all_results = []

        for task in tasks:
            try:
                results = await self.process_domain(task)
                all_results.extend(results)
            except Exception as e:
                click.echo(f"  💥 Error crítico procesando {task.domain}: {e}")
                log_result(task.domain, "PROCESS", "ERROR", "UNKNOWN_ERROR", str(e))
                all_results.append({"domain": task.domain, "action": "error", "error": str(e)})

        return all_results


# =============================================================================
# CLI
# =============================================================================

@click.group()
def cli():
    """Form Tester - Automated Contact Form Testing Tool."""
    pass


@cli.command()
@click.option("--schedule", "-s", help="Schedule execution for a future time (format: YYYY-MM-DD HH:MM)")
@click.option("--domain", "-d", help="Process a single domain instead of reading from domains.csv")
@click.option("--output", "-o", default=RESULTS_FILE, help="Output CSV file for results")
def process(schedule: Optional[str], domain: Optional[str], output: str):
    """Process all domains in domains.csv."""

    # Handle scheduling
    if schedule:
        scheduled_time = datetime.strptime(schedule, "%Y-%m-%d %H:%M")
        now = datetime.now()

        if scheduled_time > now:
            wait_seconds = (scheduled_time - now).total_seconds()
            click.echo(f"⏰ Ejecución programada para {schedule}")
            click.echo(f"   Esperando {int(wait_seconds)} segundos...")
            time.sleep(wait_seconds)

    # Load domains
    if domain:
        tasks = [DomainTask(domain)]
    else:
        tasks = load_domains()

    if not tasks:
        click.echo("⚠️  No hay dominios para procesar")
        return

    click.echo(f"📋 Procesando {len(tasks)} dominio(s)...")

    # Process domains
    tester = FormTester()
    results = asyncio.run(tester.process_all(tasks))

    # Summary
    click.echo(f"\n{'='*60}")
    click.echo(f"📊 RESUMEN")
    click.echo(f"{'='*60}")
    click.echo(f"   Total procesados: {len(results)}")
    click.echo(f"   Resultados guardados en: {output}")

    # Explicación sobre evidence/
    evidence_dir = Path(EVIDENCE_DIR)
    if evidence_dir.exists():
        evidence_files = list(evidence_dir.glob("*.png"))
        click.echo(f"   Evidencias (screenshots): {len(evidence_files)}")
        if len(evidence_files) == 0:
            click.echo(f"\n   ℹ️  Nota: La carpeta evidence/ está vacía porque:")
            click.echo(f"      - No se encontraron formularios de contacto, O")
            click.echo(f"      - Los formularios encontrados tenían CAPTCHA/honeypot")
            click.echo(f"      - Las evidencias solo se guardan cuando se intenta")
            click.echo(f"        enviar un formulario (no en fallback de email)")
    else:
        click.echo(f"   ⚠️  Directorio de evidencias no existe: {EVIDENCE_DIR}")


@cli.command()
def init():
    """Initialize the project with sample files."""
    create_sample_domains_file(DOMAINS_FILE)
    click.echo(f"✅ Archivo {DOMAINS_FILE} creado")
    click.echo(f"✅ Directorio {EVIDENCE_DIR}/ creado")
    Path(EVIDENCE_DIR).mkdir(exist_ok=True)
    click.echo("\nPróximos pasos:")
    click.echo(f"  1. Edita {DOMAINS_FILE} y agrega los dominios a probar")
    click.echo(f"  2. Configura las variables de entorno SMTP:")
    click.echo(f"     - FORM_TESTER_SMTP_USER")
    click.echo(f"     - FORM_TESTER_SMTP_PASSWORD")
    click.echo(f"     - FORM_TESTER_FROM_EMAIL")
    click.echo(f"  3. Ejecuta: python main.py process")


@cli.command()
@click.argument("email")
def suppress(email: str):
    """Add an email to the suppression list."""
    add_to_suppression_list(email, "Manual addition")
    click.echo(f"✅ Email {email} agregado a la lista de supresión")


if __name__ == "__main__":
    cli()
