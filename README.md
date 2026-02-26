<div align="center">

```
    ███████╗ ██████╗ ██████╗ ███╗   ███╗    ████████╗███████╗███████╗████████╗███████╗██████╗
    ██╔════╝██╔═══██╗██╔══██╗████╗ ████║    ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗
    █████╗  ██║   ██║██████╔╝██╔████╔██║       ██║   █████╗  ███████╗   ██║   █████╗  ██████╔╝
    ██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║       ██║   ██╔══╝  ╚════██║   ██║   ██╔══╝  ██╔══██╗
    ██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║       ██║   ███████╗███████║   ██║   ███████╗██║  ██║
    ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝       ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
```

**🤖 Automated Contact Form Testing with Intelligent Fallback**

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Code style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Playwright](https://img.shields.io/badge/Playwright-✓-45ba4b.svg)](https://playwright.dev)
[![Async](https://img.shields.io/badge/Async-✓-ff69b4.svg)](https://docs.python.org/3/library/asyncio.html)

**Crawl → Detect → Submit → Fallback → Report**

[🚀 Quick Start](#quick-start) • [📖 Documentation](#documentation) • [⚙️ Configuration](#configuration) • [🐛 Troubleshooting](#troubleshooting)

</div>

---

## 📋 Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [File Formats](#file-formats)
- [Reason Codes](#reason-codes)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
- [Roadmap](#roadmap)
- [FAQ](#faq)
- [Contributing](#contributing)
- [License](#license)

---

## 🎯 Overview

**Form Tester** is a production-grade CLI tool designed for automated testing of contact forms across multiple websites. It intelligently crawls sites, detects contact forms, fills them with test data, and automatically falls back to SMTP email delivery when forms are protected by CAPTCHA, honeypots, or anti-spam measures.

### Why Form Tester?

| Challenge | Solution |
|-----------|----------|
| 🔍 **Finding contact forms** | Smart crawling with contact page detection |
| 🛡️ **CAPTCHA protection** | Automatic detection with SMTP fallback |
| 📝 **Form diversity** | Intelligent field classification supporting 6+ field types |
| 📊 **Audit trail** | Screenshots + CSV logs with standardized reason codes |
| 🚫 **Bounce handling** | Automatic suppression list management |
| ⏱️ **Performance** | Async HTTP with rate limiting and retry logic |

---

## ✨ Key Features

### 🔎 Discovery & Detection
- **Smart Crawling**: Automatically discovers contact pages with intelligent URL pattern matching
- **Form Detection**: Identifies contact forms using field classification algorithms
- **Multi-language Support**: Recognizes form fields in English, Spanish, and more
- **Email Extraction**: Finds email addresses via `mailto:` links and text patterns

### 🤖 Form Interaction
- **JavaScript Support**: Uses Playwright for JavaScript-heavy forms
- **AJAX Handling**: Waits for AJAX responses (Contact Form 7, Elementor)
- **Intelligent Filling**: Maps test data to form fields automatically
- **Field Classification**: Recognizes name, email, phone, company, subject, message fields
- **Validation Aware**: Respects HTML5 validation patterns (e.g., phone formats)

### 🛡️ Protection Detection
- **CAPTCHA Detection**: Identifies reCAPTCHA, hCAPTCHA, and generic CAPTCHA
- **Honeypot Detection**: Spots hidden fields and CSS-obfuscated spam traps
- **Anti-spam Awareness**: Gracefully handles protected forms via fallback

### 📧 Fallback System
- **SMTP Integration**: Sends emails when forms are unavailable
- **Hard Bounce Tracking**: Automatically maintains suppression lists
- **Retry Logic**: Exponential backoff for temporary failures

### 📊 Evidence & Reporting
- **Screenshots**: Before/after screenshots for every submission
- **HTML Debug**: Page source saved for diagnostic purposes
- **CSV Logging**: Structured logging with standardized reason codes
- **Audit Trail**: Complete evidence package for compliance

### ⚙️ Production Ready
- **Rate Limiting**: Configurable delays to respect target servers
- **Async Processing**: High-performance async HTTP client
- **Scheduled Execution**: Run at specific times
- **Single File**: Entire tool in one maintainable Python file

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Form Tester                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │   domains    │───▶│    Crawler   │───▶│   Parser     │      │
│  │     .csv     │    │   (httpx)    │    │ (selectolax) │      │
│  └──────────────┘    └──────────────┘    └──────────────┘      │
│                              │                                   │
│                              ▼                                   │
│              ┌───────────────────────────────┐                   │
│              │       Form Detection          │                   │
│              │  ┌─────────┐  ┌─────────┐    │                   │
│              │  │ Contact │  │  Email  │    │                   │
│              │  │  Forms  │  │ Extract │    │                   │
│              │  └────┬────┘  └────┬────┘    │                   │
│              └───────┼─────────────┼─────────┘                   │
│                      │             │                              │
│                      ▼             ▼                              │
│           ┌─────────────┐   ┌─────────────┐                      │
│           │   Form      │   │   SMTP      │                      │
│           │ Submitter   │   │  Fallback   │                      │
│           │(Playwright) │   │             │                      │
│           └──────┬──────┘   └──────┬──────┘                      │
│                  │                 │                              │
│                  ▼                 ▼                              │
│        ┌─────────────────────────────────┐                      │
│        │      Evidence Collection        │                      │
│        │  ┌────────┐ ┌────────┐ ┌────┐  │                      │
│        │  │Screens │ │  HTML  │ │Logs│  │                      │
│        │  └────────┘ └────────┘ └────┘  │                      │
│        └─────────────────────────────────┘                      │
│                              │                                   │
│                              ▼                                   │
│                    ┌─────────────────┐                          │
│                    │   results.csv   │                          │
│                    │   (Audit Log)   │                          │
│                    └─────────────────┘                          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Workflow Diagram

```
┌─────────┐     ┌──────────┐     ┌─────────────┐
│  Start  │────▶│  Crawl   │────▶│Find Contact │
└─────────┘     │   Site   │     │   Page?     │
                └──────────┘     └──────┬──────┘
                                         │
                    ┌────────────────────┼────────────────────┐
                    │Yes                 │                    │No
                    ▼                   │                    ▼
           ┌─────────────┐              │           ┌─────────────┐
           │Find Forms?  │              │           │  Extract    │
           └──────┬──────┘              │           │   Emails    │
                  │                     │           └──────┬──────┘
         ┌────────┼────────┐            │                  │
         │Yes     │        │No          │                  ▼
         ▼        │        ▼            │          ┌─────────────┐
┌────────────┐     │ ┌────────────┐       │          │  Send SMTP  │
│Has CAPTCHA?│     │ │   Email    │       │          │   Email     │
└─────┬──────┘     │ │  Fallback  │◀──────┘          └──────┬──────┘
      │            │ └────────────┘                         │
┌─────┼─────┐      │                                        │
│Yes   │    │No    │                                        ▼
▼      │    ▼      │                              ┌─────────────────┐
┌────────┐│┌──────────┐                            │   Log Result   │
│ Skip + │││ Has      │                            │   (results.csv) │
│ Screenshot││Honeypot?│                            └─────────────────┘
└────────┘│└────┬─────┘
          │     │
          │  ┌──┴──┐
          │  │Yes  │No
          │  ▼     ▼
          │┌────────┐┌────────────────┐
          ││ Skip + ││Fill Form Fields│
          ││Screenshot││  (Playwright)  │
          │└────────┘└───────┬────────┘
          │                  │
          │                  ▼
          │         ┌────────────────┐
          │         │ Submit + Wait  │
          │         │   + Screenshot │
          │         └───────┬────────┘
          │                 │
          └─────────────────┴──▶ Log Result
```

---

## 🚀 Quick Start

### 1. Install

```bash
# Clone the repository
git clone https://github.com/selvaggiesteban/form-tester.git
cd form-tester

# Install dependencies
pip install -r requirements.txt

# Install Playwright browser
playwright install chromium
```

### 2. Configure

```bash
# Copy environment template
cp .env.example .env

# Edit with your credentials
nano .env
```

### 3. Run

```bash
# Initialize with sample files
python main.py init

# Edit domains
nano domains.csv

# Process all domains
python main.py process
```

---

## 📦 Installation

### Prerequisites

- **Python 3.8+** - [Download](https://python.org)
- **pip** - Usually included with Python
- **Git** - [Download](https://git-scm.com)

### Step-by-Step

#### Linux/macOS

```bash
# Clone repository
git clone https://github.com/selvaggiesteban/form-tester.git
cd form-tester

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install Playwright browser
playwright install chromium

# Set up environment variables
cp .env.example .env
# Edit .env with your settings
```

#### Windows

```powershell
# Clone repository
git clone https://github.com/selvaggiesteban/form-tester.git
cd form-tester

# Create virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Install Playwright browser
playwright install chromium

# Set up environment variables
Copy-Item .env.example .env
# Edit .env with your settings
```

### Environment Variables

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `FORM_TESTER_SMTP_USER` | Yes* | SMTP username | `user@gmail.com` |
| `FORM_TESTER_SMTP_PASSWORD` | Yes* | SMTP password | `app-specific-password` |
| `FORM_TESTER_FROM_EMAIL` | Optional | From address | `sender@example.com` |
| `FORM_TESTER_PROXY_URL` | Optional | Proxy URL (SOCKS5/HTTP) | `socks5://user:pass@host:port` |
| `FORM_TESTER_HTTP_PROXY` | Optional | HTTP proxy URL | `http://proxy.example.com:8080` |
| `FORM_TESTER_HTTPS_PROXY` | Optional | HTTPS proxy URL | `http://proxy.example.com:8080` |

*Required for SMTP fallback functionality

#### Gmail Setup

1. Enable 2-Factor Authentication
2. Go to [App Passwords](https://myaccount.google.com/apppasswords)
3. Generate app-specific password
4. Use that password (not your regular password)

#### Proxy Configuration (Optional)

To route traffic through a proxy and hide your real IP:

```bash
# SOCKS5 proxy
export FORM_TESTER_PROXY_URL="socks5://user:pass@host:port"

# HTTP/HTTPS proxy
export FORM_TESTER_HTTP_PROXY="http://proxy.example.com:8080"
export FORM_TESTER_HTTPS_PROXY="http://proxy.example.com:8080"
```

**Note:** Proxies hide your real IP from the target server. The tool also sends fake IP headers (`X-Forwarded-For`, etc.) which some servers may respect, but using a proxy is the only reliable method to completely mask your IP.

**VPN Alternative:** If you don't have proxies, run the tool while connected to a VPN. This will route all traffic through the VPN's IP address.

---

## 💻 Usage

### Command Reference

```
Usage: main.py [OPTIONS] COMMAND [ARGS]...

Commands:
  process    Process all domains in domains.csv
  init       Initialize the project with sample files
  suppress   Add an email to the suppression list
```

### Process Command

```bash
# Process all domains from domains.csv
python main.py process

# Process specific domain
python main.py process --domain example.com

# Schedule for future (24-hour format)
python main.py process --schedule "2025-01-15 09:00"

# Custom output file
python main.py process --output custom_results.csv
```

### Init Command

```bash
# Create sample files
python main.py init

# Output:
# ✅ Archivo domains.csv creado
# ✅ Directorio evidence/ creado
#
# Próximos pasos:
#   1. Edita domains.csv y agrega los dominios a probar
#   2. Configura las variables de entorno SMTP
#   3. Ejecuta: python main.py process
```

### Suppress Command

```bash
# Add email to suppression list
python main.py suppress bounced@example.com

# Useful for manually marking emails that hard bounced
```

### Example Session

```bash
$ python main.py process --domain example.com

============================================================
🌐 Procesando: example.com
============================================================
  🔍 Crawling: https://example.com
  🔍 Crawling: https://example.com/contact
  📊 Resultados del crawling:
     - Formularios encontrados: 1
     - Emails encontrados: 1
  📝 Intentando enviar formulario en https://example.com/contact
  ✅ Formulario enviado exitosamente

============================================================
📊 RESUMEN
============================================================
   Total procesados: 1
   Resultados guardados en: results.csv
```

---

## ⚙️ Configuration

### Main Configuration (main.py)

Edit the **CONFIGURATION SECTION** at the top of `main.py`:

```python
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
    "phone": "+1-555-123-4567",  # Use hyphens, not spaces, for pattern validation
    "company": "Test Company Inc.",
}

# Crawler Settings
MAX_PAGES_PER_DOMAIN = 10       # Maximum pages to crawl per domain
REQUEST_TIMEOUT = 30            # HTTP request timeout in seconds
USER_AGENT = "FormTesterBot/1.0 (Contact Form Testing Tool)"
RATE_LIMIT_DELAY = 1.0          # Seconds between requests to same domain
MAX_RETRIES = 3                 # Retry attempts for failed requests

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
```

### Advanced Configuration

#### Custom Field Mappings

Add support for additional languages or custom field names:

```python
FORM_FIELD_MAPPINGS = {
    "name": [
        "name", "nombre", "nom", "nome",
        "fullname", "full_name", "your_name",
        "contact_name", "customer_name"
    ],
    "email": [
        "email", "correo", "e-mail", "mail",
        "correio", "email_address", "your_email",
        "contact_email", "customer_email"
    ],
    # ... add more as needed
}
```

#### Crawler Tuning

```python
# Aggressive crawling (not recommended for production)
MAX_PAGES_PER_DOMAIN = 50
RATE_LIMIT_DELAY = 0.5

# Conservative crawling (respectful)
MAX_PAGES_PER_DOMAIN = 5
RATE_LIMIT_DELAY = 2.0
REQUEST_TIMEOUT = 60
```

---

## 📄 File Formats

### Input: domains.csv

```csv
# Comments start with #
# Format: domain,email (email is optional)

# Domain with known contact email
example.com,contact@example.com

# Domain without email (will be discovered)
testsite.org

# Another example with email
blog.example.com,author@example.com
mycompany.io
```

### Output: results.csv

| Column | Type | Description |
|--------|------|-------------|
| `timestamp` | ISO 8601 | When the action occurred |
| `domain` | string | Domain that was processed |
| `action` | enum | FORM_SUBMIT, EMAIL, FORM_SKIP, etc. |
| `status` | enum | SUCCESS, FAILED, SKIPPED, ERROR |
| `reason_code` | string | Machine-readable reason |
| `reason_description` | string | Human-readable description |
| `details` | string | Additional context |
| `evidence_path` | path | Path to screenshot (if any) |

#### Example Output

```csv
timestamp,domain,action,status,reason_code,reason_description,details,evidence_path
2025-01-15T09:30:45,example.com,FORM_SUBMIT,SUCCESS,FORM_SUBMITTED_SUCCESS,Formulario enviado exitosamente,Form at https://example.com/contact,evidence/example_com_20250115_093045_before.png
2025-01-15T09:31:12,testsite.org,FORM_SKIP,SKIPPED,HAS_RECAPTCHA,reCAPTCHA detectado envío omitido,Form at https://testsite.org/contact,
2025-01-15T09:32:08,broken-site.com,EMAIL,FAILED,HARD_BOUNCE,Bounce permanente detectado,To: contact@broken-site.com Error: 550 5.1.1,
```

### Suppression List: suppression_list.csv

```csv
email,reason,date_added
bounced@example.com,Hard bounce from SMTP,2025-01-15T09:32:08
invalid@domain.com,Manual addition,2025-01-15T10:15:22
```

---

## 🏷️ Reason Codes

| Code | Status | Description |
|------|--------|-------------|
| `FORM_SUBMITTED_SUCCESS` | ✅ SUCCESS | Form successfully submitted |
| `EMAIL_SENT` | ✅ SUCCESS | Fallback email sent via SMTP |
| `HAS_RECAPTCHA` | ⏭️ SKIPPED | reCAPTCHA detected, submission skipped |
| `HAS_HCAPTCHA` | ⏭️ SKIPPED | hCAPTCHA detected, submission skipped |
| `HONEYPOT_DETECTED` | ⏭️ SKIPPED | Honeypot detected, submission skipped |
| `NO_FORM_FOUND` | ❌ FAILED | No contact form found on site |
| `HARD_BOUNCE` | ❌ FAILED | Permanent delivery failure |
| `FORM_FILL_ERROR` | ❌ FAILED | Could not fill form fields |
| `NETWORK_ERROR` | ❌ FAILED | Error accessing the site |
| `TIMEOUT_ERROR` | ❌ FAILED | Request timeout |
| `SMTP_ERROR` | ❌ FAILED | Error sending email via SMTP |
| `UNKNOWN_ERROR` | ❌ FAILED | Unexpected error occurred |
| `SUPPRESSED` | ⏭️ SKIPPED | Email in suppression list |
| `FORM_VALIDATION_FAILED` | ❌ FAILED | Form submission validation failed |

---

## 🐛 Troubleshooting

### Common Issues

#### Playwright Not Found

```bash
# Error: ModuleNotFoundError: No module named 'playwright'

# Solution:
pip install playwright
playwright install chromium

# If still failing:
playwright install-deps chromium
```

#### SMTP Authentication Failed

```bash
# Error: SMTP authentication failed

# Common causes:
# 1. Using regular password instead of app-specific password
# 2. 2FA not enabled on Gmail
# 3. Less secure app access disabled

# Solution for Gmail:
# 1. Enable 2FA: https://myaccount.google.com/security
# 2. Generate app password: https://myaccount.google.com/apppasswords
# 3. Use app password in FORM_TESTER_SMTP_PASSWORD
```

#### No Forms Detected

```bash
# Problem: Site has a form but it's not detected

# Solutions:
# 1. Check if form is loaded via JavaScript (should work with Playwright)
# 2. Increase MAX_PAGES_PER_DOMAIN to crawl more pages
# 3. Check if site blocks automated requests (try increasing RATE_LIMIT_DELAY)
# 4. Form may use non-standard field names - add to FORM_FIELD_MAPPINGS
```

#### Form Validation Failed

```bash
# Problem: FORM_VALIDATION_FAILED error after submission

# Common causes:
# 1. Phone number format doesn't match field pattern
#    - Some forms require: +1-555-123-4567 (hyphens only)
#    - Some forms reject: +1 555 123 4567 (with spaces)
#
# 2. Required fields not filled
#    - Check TEST_DATA has values for all required fields
#
# 3. JavaScript validation failing
#    - Check HTML debug file in evidence/ directory
#    - Look for error messages in the saved HTML

# Solutions:
# 1. Update phone format in TEST_DATA:
TEST_DATA = {
    "phone": "+1-555-123-4567",  # No spaces
}

# 2. Check evidence/*.html files for validation error messages
# 3. Increase wait time for AJAX forms:
#    - Already built-in for Contact Form 7 and Elementor
#    - Edit code to add custom waits for other form types
```

#### Rate Limited / Blocked

```bash
# Error: 429 Too Many Requests

# Solutions:
# 1. Increase RATE_LIMIT_DELAY (default: 1.0 seconds)
RATE_LIMIT_DELAY = 3.0  # Wait 3 seconds between requests

# 2. Reduce MAX_PAGES_PER_DOMAIN
MAX_PAGES_PER_DOMAIN = 5

# 3. Use a different User-Agent
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
```

### Debug Mode

Enable debug logging by setting environment variable:

```bash
export PYTHONUNBUFFERED=1
export LOG_LEVEL=DEBUG
python main.py process --domain example.com
```

---

## 🔧 Development

### Project Structure

```
form-tester/
├── main.py              # Single-file application (31KB)
├── requirements.txt     # Python dependencies
├── domains.csv         # Input file (created by init)
├── results.csv         # Output log (created automatically)
├── suppression_list.csv # Bounce tracking (created automatically)
├── evidence/           # Screenshots (created automatically)
├── .env                # Environment variables (you create)
├── .env.example        # Environment template
├── .gitignore          # Git ignore rules
└── README.md           # This file
```

### Testing

```bash
# Test on a known working form
python main.py process --domain httpbin.org

# Test SMTP (requires valid credentials)
python main.py process --domain example.com

# Dry run - just crawl without submitting
# (Edit main.py to disable submission)
```

### Adding Features

The entire application is in `main.py`. Key sections:

| Section | Line | Purpose |
|---------|------|---------|
| Configuration | 20-80 | All user-configurable settings |
| CSV Handling | 150-250 | File I/O operations |
| Web Crawler | 270-450 | HTTP crawling logic |
| SMTP Module | 470-520 | Email sending |
| Form Submitter | 540-620 | Playwright integration |
| CLI | 680+ | Click commands |

---

## 🗺️ Roadmap

### Phase 1: Core (✅ Complete)
- [x] HTTP crawling with httpx
- [x] HTML parsing with selectolax
- [x] Form detection
- [x] Email extraction

### Phase 2: Actions (✅ Complete)
- [x] Form submission with Playwright
- [x] SMTP fallback
- [x] CAPTCHA detection
- [x] Honeypot detection
- [x] Bounce handling

### Phase 3: Interface (✅ Complete)
- [x] CLI with Click
- [x] CSV I/O
- [x] Scheduled execution
- [x] Suppression list

### Phase 4: Refinement (✅ Complete)
- [x] Screenshots
- [x] Rate limiting
- [x] Error handling
- [x] Documentation

### Future Enhancements

- [ ] Proxy support for rotating IPs
- [ ] Parallel domain processing
- [ ] Web dashboard for results
- [ ] API mode (Flask/FastAPI)
- [ ] Docker containerization
- [ ] Multi-language form support expansion
- [ ] Machine learning for form detection
- [ ] Integration with email verification APIs

---

## ❓ FAQ

### Q: Is this tool legal to use?

**A:** Yes, when used responsibly:
- Only test websites you own or have permission to test
- Respect rate limits (built-in)
- Don't use for spam
- Follow robots.txt guidelines

### Q: Can it bypass CAPTCHA?

**A:** No, and it shouldn't. The tool detects CAPTCHA and gracefully falls back to SMTP. CAPTCHA bypassing would violate terms of service and potentially laws.

### Q: Will this work with any contact form?

**A:** It works with most standard HTML forms. Forms that require:
- Complex JavaScript interactions
- Session-based tokens
- Browser-specific features

...may require customization.

### Q: How do I handle sites that block bots?

**A:** Increase `RATE_LIMIT_DELAY` and use a descriptive `USER_AGENT`. Some sites may still block automated requests - in these cases, use the SMTP fallback.

### Q: Can I use this with a different email provider?

**A:** Yes, just update `SMTP_HOST` and `SMTP_PORT` in the configuration. Works with any SMTP provider (SendGrid, AWS SES, etc.).

### Q: How do I prevent duplicate submissions?

**A:** The tool tracks submissions in `results.csv`. Check this file before re-running, or implement additional deduplication logic.

---

## 🤝 Contributing

Contributions are welcome! Here's how:

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/amazing-feature`
3. **Commit** your changes: `git commit -m 'Add amazing feature'`
4. **Push** to the branch: `git push origin feature/amazing-feature`
5. **Open** a Pull Request

### Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/form-tester.git
cd form-tester

# Install dev dependencies
pip install -r requirements.txt
pip install black flake8 pytest

# Run linter
flake8 main.py

# Format code
black main.py
```

### Reporting Issues

When reporting issues, please include:
- Python version: `python --version`
- Error message (full traceback)
- Domain causing the issue (if public)
- Your configuration (redact sensitive info)

---

## 📜 License

MIT License - see [LICENSE](LICENSE) file for details.

```
Copyright (c) 2025 Esteban Selvaggi

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

---

## 👤 Author

**Esteban Selvaggi**

- Website: https://selvaggiesteban.dev
- GitHub: [@selvaggiesteban](https://github.com/selvaggiesteban)
- Email: Contact via website

---

## 🙏 Acknowledgments

- [Playwright](https://playwright.dev) - Browser automation
- [httpx](https://www.python-httpx.org) - Modern HTTP client
- [selectolax](https://github.com/rushter/selectolax) - Fast HTML parsing
- [Click](https://click.palletsprojects.com) - CLI framework

---

<div align="center">

**⭐ Star this repository if you find it useful!**

[⬆ Back to Top](#form-tester)

</div>
