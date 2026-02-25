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

# Test Data
TEST_DATA = {
    "name": "Test User",
    "email": "test@example.com",
    "subject": "Test Contact Form Submission",
    "message": "This is an automated test message from the form-tester tool.",
    "phone": "+1-555-123-4567",
    "company": "Test Company Inc.",
}

# Crawler Settings
MAX_PAGES_PER_DOMAIN = 10
REQUEST_TIMEOUT = 30
USER_AGENT = "FormTesterBot/1.0 (Contact Form Testing Tool)"
RATE_LIMIT_DELAY = 1.0  # Seconds between requests to same domain
MAX_RETRIES = 3

# Form Detection
FORM_FIELD_MAPPINGS = {
    "name": ["name", "nombre", "fullname", "full_name", "your_name", "contact_name"],
    "email": ["email", "correo", "e-mail", "mail", "email_address", "your_email"],
    "subject": ["subject", "asunto", "topic", "title"],
    "message": ["message", "mensaje", "comments", "comment", "body", "content", "your_message"],
    "phone": ["phone", "telefono", "tel", "telephone", "mobile", "cell"],
    "company": ["company", "empresa", "organization", "business", "firma"],
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

        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "keep-alive",
        }

        async with httpx.AsyncClient(headers=headers) as client:
            urls_to_visit = [self.base_url]

            while urls_to_visit and len(self.task.visited_urls) < MAX_PAGES_PER_DOMAIN:
                url = urls_to_visit.pop(0)

                if url in self.task.visited_urls:
                    continue

                self.task.visited_urls.add(url)
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

            # Extract input fields
            for input_node in form_node.css("input, textarea, select"):
                input_type = input_node.attributes.get("type", "text")
                input_name = input_node.attributes.get("name", "")
                input_id = input_node.attributes.get("id", "")
                placeholder = input_node.attributes.get("placeholder", "").lower()

                # Skip hidden/submit/button inputs
                if input_type in ("hidden", "submit", "button", "image"):
                    if input_type == "submit":
                        submit_button = input_name or input_id
                    continue

                # Map field to known types
                field_key = self._classify_field(input_name, input_id, placeholder)
                if field_key:
                    fields[field_key] = {
                        "name": input_name,
                        "id": input_id,
                        "type": input_type,
                        "placeholder": placeholder,
                    }

            # Check if this looks like a contact form
            if "email" in fields and ("message" in fields or "name" in fields):
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
                    form_data.has_honeypot = True

                forms.append(form_data)

        return forms

    def _classify_field(self, name: str, field_id: str, placeholder: str) -> Optional[str]:
        """Classify a form field based on its attributes."""
        search_text = f"{name} {field_id} {placeholder}".lower()

        for field_type, keywords in FORM_FIELD_MAPPINGS.items():
            for keyword in keywords:
                if keyword in search_text:
                    return field_type

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
        """Check if the form has a honeypot field."""
        for input_node in form_node.css("input"):
            input_type = input_node.attributes.get("type", "")
            input_name = input_node.attributes.get("name", "")
            style = input_node.attributes.get("style", "")

            # Hidden fields with suspicious names
            if input_type == "hidden":
                if any(keyword in input_name.lower() for keyword in ["email", "name", "phone"]):
                    return True

            # Fields hidden via CSS
            if "display:none" in style or "visibility:hidden" in style:
                return True

            # Fields positioned off-screen
            if "left:-" in style or "top:-" in style:
                return True

        return False

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
            href = link.attributes.get("href", "")
            if href.startswith(("http://", "https://")):
                # External link - skip
                continue
            elif href.startswith("/"):
                # Absolute path
                full_url = urljoin(base_url, href)
                links.append(full_url)
            elif href.startswith(("#", "javascript:", "mailto:", "tel:")):
                # Skip anchors and special links
                continue
            elif href:
                # Relative path
                full_url = urljoin(base_url, href)
                links.append(full_url)

        return links

    def _is_contact_page(self, url: str) -> bool:
        """Check if URL looks like a contact page."""
        contact_keywords = ["contact", "contacto", "kontakt", "reach-us", "get-in-touch"]
        url_lower = url.lower()
        return any(keyword in url_lower for keyword in contact_keywords)


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
        """Submit a form using Playwright."""
        evidence_path = ""

        try:
            from playwright.async_api import async_playwright

            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(
                    user_agent=USER_AGENT,
                    viewport={"width": 1280, "height": 720},
                )
                page = await context.new_page()

                # Navigate to the form page
                await page.goto(form.url, wait_until="networkidle", timeout=30000)

                # Fill in form fields
                for field_type, field_info in form.fields.items():
                    value = TEST_DATA.get(field_type, "")
                    if value:
                        selector = f"[name='{field_info['name']}']"
                        try:
                            await page.fill(selector, value)
                        except Exception as e:
                            await browser.close()
                            return False, f"FORM_FILL_ERROR: Could not fill {field_type}", ""

                # Take screenshot before submission
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                domain = urlparse(form.url).netloc.replace(".", "_")
                screenshot_path = self.evidence_dir / f"{domain}_{timestamp}_before.png"
                await page.screenshot(path=str(screenshot_path), full_page=True)
                evidence_path = str(screenshot_path)

                # Submit the form
                if form.submit_button:
                    await page.click(f"[name='{form.submit_button}']")
                else:
                    # Try to find submit button
                    submit_selectors = [
                        "button[type='submit']",
                        "input[type='submit']",
                        "button:has-text('Send')",
                        "button:has-text('Submit')",
                        "button:has-text('Enviar')",
                    ]
                    for selector in submit_selectors:
                        try:
                            await page.click(selector, timeout=2000)
                            break
                        except:
                            continue

                # Wait for response
                await page.wait_for_load_state("networkidle", timeout=10000)

                # Take screenshot after submission
                screenshot_path_after = self.evidence_dir / f"{domain}_{timestamp}_after.png"
                await page.screenshot(path=str(screenshot_path_after), full_page=True)

                await browser.close()

                return True, "FORM_SUBMITTED_SUCCESS", evidence_path

        except Exception as e:
            return False, f"UNKNOWN_ERROR: {str(e)}", ""


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

        # Crawl the domain
        crawler = WebCrawler(task)
        forms, emails = await crawler.crawl()

        click.echo(f"  📊 Resultados del crawling:")
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
