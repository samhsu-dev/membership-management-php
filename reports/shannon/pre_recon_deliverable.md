# Pre-Recon Code Analysis: PHP Membership Management System

---

# Penetration Test Scope & Boundaries

**Primary Directive:** Analysis is strictly limited to the **network-accessible attack surface** of the application. All subsequent tasks must adhere to this scope.

### In-Scope: Network-Reachable Components
A component is considered **in-scope** if its execution can be initiated, directly or indirectly, by a network request that the deployed application server is capable of receiving. This includes:
- Publicly exposed web pages and API endpoints.
- Endpoints requiring authentication via the application's standard login mechanisms.
- Any developer utility, debug console, or script that has been mistakenly exposed through a route or is otherwise callable from other in-scope, network-reachable code.

### Out-of-Scope: Locally Executable Only
A component is **out-of-scope** if it **cannot** be invoked through the running application's network interface and requires an execution context completely external to the application's request-response cycle. This includes:
- CLI scripts and build tools.
- Database migration scripts (`docker/mysql/init.sql` when used for initial DB seeding only).
- Local development server configuration.

---

## 1. Executive Summary

The target is a single-admin PHP membership management application deployed on Apache with PHP 7.4 (end-of-life since November 2022). The application is a flat-file procedural PHP system with no MVC framework — every PHP file lives directly in the web root with no routing layer, no framework, and no security middleware. The security posture of this application is **critically deficient across every analyzed domain**: authentication, authorization, input validation, data protection, and operational security all exhibit fundamental, pervasive vulnerabilities.

The most critical finding is that **every single database query in the application concatenates raw user input directly into SQL strings** with zero use of prepared statements, parameterized queries, or escaping functions. This results in SQL injection vulnerabilities across all 19 network-accessible entry points. Combined with an MD5 password hashing scheme (trivially reversible with no salting), a complete absence of CSRF tokens, and three unrestricted file upload endpoints that allow `.php` webshells to be deployed to web-executable directories, an unauthenticated attacker can achieve full database compromise and likely Remote Code Execution within minutes.

Two critical entry points — `print_membership_card.php` and `get_membership_amount.php` — are accessible without any authentication whatsoever, providing unauthenticated SQL injection vectors. Additionally, `delete_members.php` lacks a session check, enabling unauthenticated hard-deletion of member records. The application also commits default admin credentials (`admin@mail.com` / `codeastro.com`) in seven plaintext files across the repository, including one in the web-accessible `uploads/` directory, making credential theft trivial for any web visitor. The overall risk profile is consistent with a deliberately insecure training/demonstration application that must not be exposed to a public network.

---

## 2. Architecture & Technology Stack

- **Framework & Language:** PHP 7.4 (EOL November 2022, no security patches available). No framework — purely procedural PHP with no MVC separation, no routing layer, no middleware, and no templating engine. HTML is rendered inline via PHP `echo`/`include` statements. This architecture means there is no central security chokepoint: authentication checks, input handling, and database queries are all duplicated per-file with inconsistent implementation quality.

- **Architectural Pattern:** Flat-file PHP monolith. The entire repository is the web root — `COPY . /var/www/html/` in the Dockerfile copies everything including SQL dumps, credential text files, and development artifacts directly into the Apache document root. There is no `public/` subdirectory separation. The single trust boundary is `isset($_SESSION['user_id'])` checked at the top of most (but not all) files. Business logic, SQL queries, and HTML rendering are co-mingled in every file. There is no service layer, no ORM, no dependency injection, and no autoloader.

- **Database:** MySQL 8.4 (Docker) / 5.6.21 (original). Database charset is `latin1` throughout — this is significant because latin1 (ISO-8859-1) encoding can enable charset-based SQL injection bypasses in some MySQL configurations. Connection via MySQLi procedural/OOP (`new mysqli(...)`). The application connects as the MySQL `root` user (`DB_USER: root` in `docker-compose.yml`) with the password `rootpass` — providing full database privileges including `FILE`, `SUPER`, and DDL operations.

- **Frontend Libraries (Vendored — no package manager):**
  - jQuery **3.4.1** — CVE-2019-11358 (prototype pollution), CVE-2020-11022/11023 (XSS via `html()`)
  - jQuery UI **1.12.1** (2016) — CVE-2021-41182/41183/41184 (XSS in tooltip/datepicker)
  - Bootstrap **4.4.1** — CVE-2024-6485 (XSS)
  - DataTables 1.10.20, AdminLTE 3.0.5 (both outdated)

- **Critical Security Components:**
  - **Authentication:** MD5-based password comparison in `index.php` against the `users` table.
  - **Session:** PHP default file-based sessions started with bare `session_start()` in `includes/config.php`; no cookie flags configured.
  - **Authorization:** Per-page `isset($_SESSION['user_id'])` check with no centralized middleware.
  - **Web Server:** Apache (`php:7.4-apache`). No `.htaccess` files exist anywhere — no directory access restrictions, no PHP execution prevention in `uploads/`.
  - **No CSRF protection, no input sanitization library, no output encoding, no security headers.**

- **External CDN Dependencies (runtime supply-chain risk):**
  - `https://code.ionicframework.com/ionicons/2.0.1/css/ionicons.min.css` — loaded in `includes/header.php` and `index.php`
  - `https://fonts.googleapis.com/css?family=Source+Sans+Pro` — loaded in `includes/header.php` and `index.php`
  - These are loaded client-side on every page, creating supply-chain risk and leaking visitor IPs to third parties.

---

## 3. Authentication & Authorization Deep Dive

### Authentication Mechanisms

The application implements username/password authentication against a single `users` table using **MD5 hashing** — a cryptographically broken algorithm with no salting, no work factor, and trivial rainbow-table reversibility. The login handler is `index.php` (POST to itself). The authentication query at `index.php` line 14 directly concatenates the raw `$_POST['email']` value into SQL:

```php
$hashed_password = md5($password);
$sql = "SELECT * FROM users WHERE email = '$email' AND password = '$hashed_password'";
```

This is an SQL injection authentication bypass: submitting `' OR '1'='1' -- -` as the email field logs in without any valid password. The committed MD5 hash `f2d0ff370380124029c2b807a924156c` (in `DATABASE FILE/membershiphp.sql` line 153 and `docker/mysql/init.sql` line 156) is the MD5 of `codeastro.com` — the default password. The login page presents a non-functional "Remember Me" checkbox (`index.php` lines 86-88) with no `name` attribute — it is never transmitted to the server. No MFA, no OAuth, no password reset mechanism exists.

**Authentication Endpoints:**
- `POST /index.php` — login (parameters: `email`, `password`, `login`)
- `GET /logout.php` — logout (destroys session, no CSRF protection)
- `POST /settings.php` with `changePassword` button — password change for authenticated admin (parameters: `currentPassword`, `newPassword`, `confirmPassword`)

**No password reset flow exists.** There is no forgot-password link, no email sending, no token generation, and no reset endpoint anywhere in the codebase.

### Session Management

Session management is configured entirely via bare `session_start()` at `includes/config.php` line 14. **No `session_set_cookie_params()` call exists anywhere in the codebase.** This means:
- `HttpOnly`: Not explicitly set (relies on PHP's `php.ini` default; typically `1` but not guaranteed across deployments)
- `Secure`: **Not set** — session cookie is transmitted over plain HTTP
- `SameSite`: **Not set** — no CSRF protection at the cookie level

`session_regenerate_id()` is never called after successful login (`index.php` lines 19-23), leaving the application vulnerable to **session fixation attacks**: an attacker who pre-seeds a session ID can hijack the authenticated session after the victim logs in.

Sessions use PHP's default file-based storage (`/tmp`). No session timeout is explicitly configured — sessions expire at PHP's default `session.gc_maxlifetime` (typically 1440 seconds).

### Authorization Model

There is **no RBAC**. The `users` table has no `role` column. A single boolean check — `isset($_SESSION['user_id'])` — is the sole authorization gate for all 15 protected pages. Once authenticated, a user has access to every function including member deletion, settings changes, and file uploads. This check is implemented inconsistently:

- **Missing entirely (critical):**
  - `print_membership_card.php` — exposes full member PII to unauthenticated visitors
  - `delete_members.php` — allows unauthenticated hard-deletion of member records
  - `get_membership_amount.php` — unauthenticated AJAX endpoint with SQL injection

- **Placed after database queries execute (logic flaw):**
  - `manage_members.php` — SELECT runs on line 4-5, auth check on line 8
  - `view_type.php` — SELECT runs on lines 4-5, auth check on line 7
  - `list_renewal.php` — SELECT runs on lines 4-5, auth check on line 7

  Although these redirected unauthenticated requests before HTML is rendered, the DB queries still execute, wasting resources and potentially causing side effects.

### CSRF Protection

**Zero CSRF protection exists anywhere in the application.** No CSRF tokens, no SameSite cookie attributes, and no origin validation. Every state-changing operation — member creation, member editing, member deletion (via GET), password change, settings update, membership type management, renewal processing — is vulnerable to CSRF. Critically, the delete operations (`delete_members.php`, `delete_membership.php`) use HTTP GET for destructive actions, meaning a simple `<img src="...delete_members.php?id=1">` tag on any page the admin visits will silently delete a member record.

---

## 4. Data Security & Storage

### Database Security

The application stores a comprehensive set of PII in the `members` table: fullname, date of birth, gender, contact number, email, street address, country, postcode, occupation, and photo filename. **No PII is encrypted at rest** — all columns are plaintext VARCHAR/DATE fields. The database connects as the MySQL `root` user with full privileges (`includes/config.php` lines 2-7), meaning a successful SQL injection attack provides not only data access but also DDL manipulation, file read/write via `INTO OUTFILE`/`LOAD DATA INFILE`, and potentially OS-level code execution through MySQL's UDF mechanism.

Database error messages are echoed directly to the browser in multiple files. Critically, `view_type.php` line 34 and `manage_members.php` line 24 echo the **full SQL query string** along with the error: `echo "Error: " . $insertQuery . "<br>" . $conn->error;` — this leaks the complete query structure including table names and column names to any visitor who triggers a query error, providing fingerprinting information for SQL injection attacks.

### Data Flow Security

PII flows from user input (`$_POST` in `add_members.php`/`edit_member.php`) directly into the database without sanitization. From the database, PII flows directly into HTML output without `htmlspecialchars()` — creating stored XSS vectors on every page that renders member data. The `totalAmount` field in `renew.php` is calculated client-side in JavaScript (lines 210-217) and submitted as a POST parameter (`$_POST['totalAmount']`), then inserted directly into the `renew` table without server-side validation — enabling **price manipulation** where an attacker (or CSRF'd admin) can record arbitrary renewal amounts.

### Committed Secrets

The following secrets are committed to the git repository and tracked by version control:

| File | Secret |
|---|---|
| `01 LOGIN DETAILS & PROJECT INFO.txt` (7 copies in repo, 1 in `uploads/`) | Admin password: `codeastro.com` (plaintext) |
| `docker-compose.yml` lines 10, 20 | `DB_PASS: rootpass`, `MYSQL_ROOT_PASSWORD: rootpass` |
| `DATABASE FILE/membershiphp.sql` line 153 | MD5 hash `f2d0ff370380124029c2b807a924156c` (admin password) |
| `docker/mysql/init.sql` line 156 | Same MD5 hash |

The credential file in `uploads/01 LOGIN DETAILS & PROJECT INFO.txt` is particularly dangerous: it is web-accessible via `http://host/uploads/01%20LOGIN%20DETAILS%20&%20PROJECT%20INFO.txt` and serves the admin password to any unauthenticated visitor.

### Encryption

MD5 is used for all password operations (`index.php` line 12, `settings.php` lines 58-59). No `password_hash()`, bcrypt, Argon2, or any proper password hashing exists. Membership numbers are generated using `mt_rand()` (`add_members.php` line 34) — not a cryptographically secure random source. No encryption of data at rest or in transit is implemented anywhere.

---

## 5. Attack Surface Analysis

### External Entry Points (In-Scope, Network-Reachable)

All PHP files reside directly in the Apache document root (`/var/www/html/`). There is no routing layer or URL rewriting. Every `.php` file is directly network-accessible by URL. The application is served on port 80 (HTTP only). The following entry points have been confirmed through source code analysis:

**Public (No Authentication Required):**

| Endpoint | File | Method | Parameters | Risk |
|---|---|---|---|---|
| `GET/POST /index.php` | `index.php` | GET+POST | `email`, `password`, `login` | SQLi auth bypass, brute-force |
| `GET /print_membership_card.php` | `print_membership_card.php` | GET | `id` (member ID) | **Unauthenticated** SQLi + PII disclosure |
| `GET /get_membership_amount.php` | `get_membership_amount.php` | GET | `membershipTypeId` | **Unauthenticated** SQLi |
| `GET /delete_members.php` | `delete_members.php` | GET | `id` (member ID) | **Unauthenticated** SQLi + hard delete |
| `GET /logout.php` | `logout.php` | GET | None | CSRF-forced logout |

**Authenticated (Session Required — `isset($_SESSION['user_id'])`):**

| Endpoint | File | Method | Parameters | Risk |
|---|---|---|---|---|
| `GET /dashboard.php` | `dashboard.php` | GET | None | Stored XSS display |
| `GET /add_members.php` | `add_members.php` | GET | None | Form |
| `POST /add_members.php` | `add_members.php` | POST | `fullname`, `dob`, `gender`, `contactNumber`, `email`, `address`, `country`, `postcode`, `occupation`, `membershipType`, `photo` (file) | SQLi (all fields), Stored XSS, RCE via file upload |
| `GET /edit_member.php` | `edit_member.php` | GET | `id` | SQLi via `id` |
| `POST /edit_member.php` | `edit_member.php` | POST+GET | `id` (GET), all member fields (POST), `photo` (file) | SQLi (all fields), RCE via file upload, CSRF |
| `GET /delete_members.php` | `delete_members.php` | GET | `id` | SQLi, CSRF (GET-based delete) |
| `GET /manage_members.php` | `manage_members.php` | GET | None | Stored XSS display |
| `GET /memberProfile.php` | `memberProfile.php` | GET | `id` | SQLi via `id`, Stored XSS |
| `GET /add_type.php` | `add_type.php` | GET | None | Form |
| `POST /add_type.php` | `add_type.php` | POST | `membershipType`, `membershipAmount` | SQLi (both fields), CSRF |
| `GET/POST /view_type.php` | `view_type.php` | GET+POST | `membershipType`, `membershipAmount` (POST) | SQLi, Stored XSS, CSRF |
| `GET /edit_type.php` | `edit_type.php` | GET | `id` | SQLi via `id`, Reflected XSS via `id` |
| `POST /edit_type.php` | `edit_type.php` | POST | `membershipType`, `membershipAmount`, `edit_id` | SQLi (all fields), Stored XSS, CSRF |
| `GET /delete_membership.php` | `delete_membership.php` | GET | `id` | SQLi, CSRF, open redirect via `HTTP_REFERER` |
| `GET /list_renewal.php` | `list_renewal.php` | GET | None | Stored XSS display |
| `GET /renew.php` | `renew.php` | GET | `id` | SQLi via `id` |
| `POST /renew.php` | `renew.php` | POST+GET | `membershipType`, `extend`, `totalAmount` | SQLi, price manipulation (client-controlled amount), CSRF |
| `GET /report.php` | `report.php` | GET | None | Form |
| `POST /report.php` | `report.php` | POST | `fromDate`, `toDate` | SQLi (date range), Stored XSS output, CSRF |
| `GET /revenue_report.php` | `revenue_report.php` | GET | None | Form |
| `POST /revenue_report.php` | `revenue_report.php` | POST | `fromDate`, `toDate` | SQLi (date range), Stored XSS output, CSRF |
| `GET /settings.php` | `settings.php` | GET | None | Form |
| `POST /settings.php` (updateSettings) | `settings.php` | POST | `systemName`, `currency`, `logo` (file) | SQLi (all fields), Stored XSS via system_name/currency, RCE via logo upload |
| `POST /settings.php` (changePassword) | `settings.php` | POST | `currentPassword`, `newPassword`, `confirmPassword` | SQLi via password fields, MD5 hashing |

**Web-Accessible Directories (No Auth, Static File Serving):**

| URL Path | Contents | Risk |
|---|---|---|
| `/uploads/` | System logo, `01 LOGIN DETAILS & PROJECT INFO.txt` | **Admin credentials publicly downloadable** |
| `/uploads/member_photos/` | Member photos, potentially uploaded webshells | **PHP execution if `.php` uploaded** |
| `/DATABASE FILE/membershiphp.sql` | Full database dump with admin password hash | **Downloadable via Apache static file serving** |

**Out-of-Scope Components:**

| Component | Reason for Exclusion |
|---|---|
| `docker/mysql/init.sql` | Database initialization script — executed by Docker at container startup, not via HTTP |
| `docker-compose.yml` | Container orchestration configuration — runtime secrets file, not an HTTP endpoint |

### Internal Service Communication

The only internal service is MySQL. The MySQLi connection (`includes/config.php` line 7) uses plaintext TCP with no SSL options. In the Docker Compose deployment, both containers share the same Docker bridge network with no network segmentation between the app container and the database container.

### Input Validation Patterns

**No input validation exists anywhere in the application.** No calls to `filter_var()`, `preg_match()`, `intval()` for integer coercion, or any whitelist validation. The only "validation" is HTML `required` attributes (client-side only, trivially bypassed). File upload validation is absent — no MIME type checking, no extension whitelist, no content inspection.

### Background Processing

No background job queue, cron jobs, or async processing exists. All processing is synchronous within the HTTP request-response cycle.

---

## 6. Infrastructure & Operational Security

### Secrets Management

The `includes/config.php` configuration uses `getenv()` with insecure hardcoded fallbacks:
```php
$username = getenv('DB_USER') ?: 'root';   // default: root (full privileges)
$password = getenv('DB_PASS') ?: '';        // default: empty password
```
The Docker Compose file (`docker-compose.yml`) commits actual runtime secrets (`rootpass`) in plaintext to version control. No secret rotation mechanism, no vault integration, and no `.env` exclusion pattern are used. The `.gitignore` only excludes `.DS_Store`, `*.swp`, `*.swo` — it provides no protection for any sensitive file.

### Configuration Security

**No security headers are set anywhere in the application or web server configuration.** There are no `.htaccess` files and no explicit Apache VirtualHost configuration in the repository. The following security headers are entirely absent:
- `Strict-Transport-Security (HSTS)` — no HTTPS enforcement
- `Content-Security-Policy` — no XSS mitigation at header level
- `X-Frame-Options` / `frame-ancestors` — vulnerable to clickjacking
- `X-Content-Type-Options: nosniff` — MIME sniffing enabled
- `Referrer-Policy` — referer leakage to third-party CDNs
- `Permissions-Policy` — no browser feature restrictions
- `Cache-Control` — no cache control on sensitive pages

No Nginx configuration. No CDN or WAF configuration. Container exposed on HTTP port 80 only (`EXPOSE 80` in Dockerfile). No TLS termination layer. No `php.ini` or `.user.ini` in the repository — PHP runs on Docker image defaults.

### External Dependencies

All frontend libraries are manually vendored (no `composer.json` or `package.json`). Notable vulnerable versions:
- jQuery 3.4.1 — CVE-2019-11358 (prototype pollution), CVE-2020-11022/11023 (XSS via `html()`)
- jQuery UI 1.12.1 — CVE-2021-41182, CVE-2021-41183, CVE-2021-41184 (XSS in tooltip/datepicker)
- Bootstrap 4.4.1 — CVE-2024-6485 (XSS)
- PHP 7.4 — EOL November 2022, no security patches since
- MySQL 5.6.21 (original development target) — multiple historical CVEs

CDN dependencies load from `ionicframework.com` and `fonts.googleapis.com` at runtime on every page load, creating supply-chain risk and leaking visitor IPs to third-party servers.

### Monitoring & Logging

**No security event logging exists.** Failed login attempts generate only an in-page error message with no log entry. There is no audit log for data changes, no rate limiting, no brute-force protection, no intrusion detection, and no SIEM integration. The only logging present is a development artifact in `get_membership_amount.php` (lines 12, 28) using `error_log()` to log AJAX responses. No PII is intentionally written to logs, but PHP error logs may capture SQL query error messages containing injected payload fragments.

---

## 7. Overall Codebase Indexing

The repository at `/repos/membership-management-php/` is structured as a flat-file PHP application with the entire codebase residing directly in the web root — there is no `public/` or `www/` subdirectory separation. The application comprises 20 PHP files at the root level (each representing a distinct page or functional endpoint), one `includes/` directory containing shared partials (`config.php`, `header.php`, `footer.php`, `nav.php`, `sidebar.php`, `pagetitle.php`), an `uploads/` directory for user-submitted content (member photos and system logo), a `dist/` directory containing AdminLTE CSS/JS assets, a `plugins/` directory with all manually-vendored frontend libraries (jQuery, Bootstrap, DataTables, FontAwesome, etc.), and a `docker/` directory containing MySQL initialization SQL.

There is no build system, no autoloader, no composer dependency management, and no package.json. All security-relevant logic — authentication, authorization, data access, and output rendering — is implemented ad-hoc in each individual PHP file. Code reuse is limited to `include('includes/config.php')` (which establishes the database connection and starts the session) and include calls for HTML partials. This flat architecture means every `.php` file in the web root is an independent entry point, and every database interaction follows the same vulnerable pattern of raw string concatenation with no parameterization.

The repository includes two database dump files (`DATABASE FILE/membershiphp.sql` and `docker/mysql/init.sql`) which are structural duplicates containing the full schema and a seeded admin account. A `Dockerfile` and `docker-compose.yml` define the container deployment. Seven copies of a plaintext `01 LOGIN DETAILS & PROJECT INFO.txt` credential file are distributed throughout the directory tree, including in the web-accessible `uploads/` directory, representing a developer artifact that was incorrectly committed to version control. The `.gitignore` provides no protection for any sensitive file.

---

## 8. Critical File Paths

### Configuration
- `/repos/membership-management-php/includes/config.php`
- `/repos/membership-management-php/docker-compose.yml`
- `/repos/membership-management-php/Dockerfile`
- `/repos/membership-management-php/.gitignore`

### Authentication & Authorization
- `/repos/membership-management-php/index.php`
- `/repos/membership-management-php/logout.php`
- `/repos/membership-management-php/settings.php`
- `/repos/membership-management-php/print_membership_card.php` — **Missing auth check**
- `/repos/membership-management-php/delete_members.php` — **Missing auth check**
- `/repos/membership-management-php/get_membership_amount.php` — **Missing auth check**
- `/repos/membership-management-php/manage_members.php` — Auth check after DB query
- `/repos/membership-management-php/view_type.php` — Auth check after DB query
- `/repos/membership-management-php/list_renewal.php` — Auth check after DB query

### API & Routing
- `/repos/membership-management-php/dashboard.php`
- `/repos/membership-management-php/add_members.php`
- `/repos/membership-management-php/edit_member.php`
- `/repos/membership-management-php/delete_members.php`
- `/repos/membership-management-php/manage_members.php`
- `/repos/membership-management-php/memberProfile.php`
- `/repos/membership-management-php/add_type.php`
- `/repos/membership-management-php/edit_type.php`
- `/repos/membership-management-php/view_type.php`
- `/repos/membership-management-php/delete_membership.php`
- `/repos/membership-management-php/renew.php`
- `/repos/membership-management-php/list_renewal.php`
- `/repos/membership-management-php/report.php`
- `/repos/membership-management-php/revenue_report.php`
- `/repos/membership-management-php/get_membership_amount.php`

### Data Models & DB Interaction
- `/repos/membership-management-php/DATABASE FILE/membershiphp.sql`
- `/repos/membership-management-php/docker/mysql/init.sql`

### Dependency Manifests
- `/repos/membership-management-php/plugins/jquery/jquery.js` — jQuery 3.4.1 (CVE-2019-11358, CVE-2020-11022/11023)
- `/repos/membership-management-php/plugins/jquery-ui/jquery-ui.js` — jQuery UI 1.12.1 (CVE-2021-41182/41183/41184)
- `/repos/membership-management-php/plugins/bootstrap/js/bootstrap.bundle.js` — Bootstrap 4.4.1 (CVE-2024-6485)

### Sensitive Data & Secrets Handling
- `/repos/membership-management-php/01 LOGIN DETAILS & PROJECT INFO.txt` — Plaintext admin credentials
- `/repos/membership-management-php/uploads/01 LOGIN DETAILS & PROJECT INFO.txt` — **Web-accessible plaintext credentials**
- `/repos/membership-management-php/DATABASE FILE/01 LOGIN DETAILS & PROJECT INFO.txt`
- `/repos/membership-management-php/includes/01 LOGIN DETAILS & PROJECT INFO.txt`
- `/repos/membership-management-php/dist/css/01 LOGIN DETAILS & PROJECT INFO.txt`
- `/repos/membership-management-php/dist/img/01 LOGIN DETAILS & PROJECT INFO.txt`
- `/repos/membership-management-php/dist/js/01 LOGIN DETAILS & PROJECT INFO.txt`

### Middleware & Input Validation
- None — no middleware layer or validation library exists

### Logging & Monitoring
- None — no logging framework; only bare `error_log()` in `get_membership_amount.php` lines 12, 28

### Infrastructure & Deployment
- `/repos/membership-management-php/Dockerfile`
- `/repos/membership-management-php/docker-compose.yml`

### Shared HTML Partials (Included on Every Page)
- `/repos/membership-management-php/includes/header.php` — Stored XSS via `$systemName` in `<title>`
- `/repos/membership-management-php/includes/sidebar.php` — Stored XSS via `getSystemName()` and `getLogoUrl()`
- `/repos/membership-management-php/includes/nav.php`
- `/repos/membership-management-php/includes/footer.php`
- `/repos/membership-management-php/includes/pagetitle.php`

---

## 9. XSS Sinks and Render Contexts

**Overview:** The application contains no calls to `htmlspecialchars()`, `htmlentities()`, or `strip_tags()` anywhere in the codebase. Every database column value echoed to HTML is an unescaped Stored XSS sink. Every `$_GET` or `$_POST` value echoed to HTML is a Reflected XSS sink. The attack chain for Stored XSS is: user input → raw SQL INSERT/UPDATE → database → raw `echo` to HTML. The application also uses jQuery 3.4.1 (CVE-2020-11022/11023: XSS via `.html()`) and jQuery UI 1.12.1 (CVE-2021-41182/41183/41184: XSS in tooltip/datepicker).

---

### HTML Body Context — Stored XSS (Database-Sourced)

**1. Member Profile Page — All Member Fields**
- **File:** `memberProfile.php`
- **Lines:** 120–133
- **Sinks:**
  - Line 120: `echo $memberDetails['membership_number'];`
  - Line 121: `echo $memberDetails['fullname'];`
  - Line 122: `echo $memberDetails['dob'];`
  - Line 123: `echo $memberDetails['gender'];`
  - Line 124: `echo $memberDetails['contact_number'];`
  - Line 125: `echo $memberDetails['email'];`
  - Line 128: `echo $memberDetails['address'];`
  - Line 129: `echo $memberDetails['country'];`
  - Line 130: `echo $memberDetails['postcode'];`
  - Line 131: `echo $memberDetails['occupation'];`
  - Line 132: `echo $memberDetails['membership_type_name'];`
- **Data Source:** `members` table (written via `add_members.php` POST, no sanitization)

**2. Manage Members Table**
- **File:** `manage_members.php`
- **Lines:** 89–96
- **Sinks:**
  - Line 89: `echo "<td>{$row['membership_number']}</td>";`
  - Line 90: `echo "<td>{$row['fullname']}</td>";`
  - Line 91: `echo "<td>{$row['contact_number']}</td>";`
  - Line 92: `echo "<td>{$row['email']}</td>";`
  - Line 93: `echo "<td>{$row['address']}</td>";`
  - Line 94: `echo "<td>{$membershipTypeName}</td>";`
- **Data Source:** `members` table

**3. Dashboard — Recent Members List**
- **File:** `dashboard.php`
- **Lines:** 299, 305–308
- **Sinks:**
  - Line 299: `echo '<img src="' . $photoPath . '" ...>';` (also URL context)
  - Line 305: `echo '<a href="javascript:void(0)" ...>' . $row['fullname'] . '</a>';`
  - Line 307: `echo '...' . getMembershipTypeName($row['membership_type']) . '...';`
  - Line 308: `echo 'Membership Number: ' . ($row['membership_number']);`
- **Data Source:** `members` table

**4. Print Membership Card (Unauthenticated Page)**
- **File:** `print_membership_card.php`
- **Lines:** 150, 154–158, 162, 165
- **Sinks:**
  - Line 154: `echo $systemName;`
  - Line 155: `echo $memberDetails['membership_number'];`
  - Line 156: `echo $memberDetails['fullname'];`
  - Line 158: `echo $memberDetails['address']; echo $memberDetails['postcode'];`
  - Line 162: `echo $memberDetails['membership_type_name'];`
- **Data Source:** `members` table + `settings` table
- **Note:** **No authentication check on this page** — exploitable by unauthenticated attackers

**5. Membership Report Output**
- **File:** `report.php`
- **Lines:** 87–91
- **Sinks:**
  - `echo '<td>' . $row['membership_number'] . '</td>';`
  - `echo '<td>' . $row['fullname'] . '</td>';`
  - `echo '<td>' . $row['email'] . '</td>';`
  - `echo '<td>' . $row['membership_type_name'] . '</td>';`
  - `echo '<td>' . $row['expiry_date'] . '</td>';`
- **Data Source:** `members` + `membership_types` tables

**6. Revenue Report Output**
- **File:** `revenue_report.php`
- **Lines:** 87–90
- **Sinks:**
  - `echo '<td>' . $row['fullname'] . '</td>';`
  - `echo '<td>' . $row['membership_number'] . '</td>';`
  - `echo '<td>' . $row['currency'] . $row['total_amount'] . '</td>';`
  - `echo '<td>' . $row['renew_date'] . '</td>';`
- **Data Source:** `members` + `renew` + `settings` tables

**7. Renewal List**
- **File:** `list_renewal.php`
- **Lines:** 83–98
- **Sinks:**
  - `echo "<td>{$row['membership_number']}</td>";`
  - `echo "<td>{$row['fullname']}</td>";`
  - `echo "<td>{$row['contact_number']}</td>";`
  - `echo "<td>{$row['email']}</td>";`
  - `echo "<td>{$membershipTypeName}</td>";`
  - `echo "<td>{$row['expiry_date']}...</td>";`
- **Data Source:** `members` table

**8. Membership Types Table**
- **File:** `view_type.php`
- **Lines:** 85–86
- **Sinks:**
  - `echo "<td>{$row['type']}</td>";`
  - `echo "<td>{$currencySymbol} {$row['amount']}</td>";`
- **Data Source:** `membership_types` + `settings` tables (`$currencySymbol` = `settings.currency`, admin-controlled)

---

### HTML Attribute Context — Stored XSS (Value Attributes)

**9. Edit Member Form — Pre-populated Value Attributes**
- **File:** `edit_member.php`
- **Lines:** 122, 126, 145, 150, 158, 163, 171, 176
- **Sinks (all `value="<?php echo ...?>"` pattern):**
  - Line 122: `value="<?php echo $memberDetails['fullname']; ?>"`
  - Line 126: `value="<?php echo $memberDetails['dob']; ?>"`
  - Line 145: `value="<?php echo $memberDetails['contact_number']; ?>"`
  - Line 150: `value="<?php echo $memberDetails['email']; ?>"`
  - Line 158: `value="<?php echo $memberDetails['address']; ?>"`
  - Line 163: `value="<?php echo $memberDetails['country']; ?>"`
  - Line 171: `value="<?php echo $memberDetails['postcode']; ?>"`
  - Line 176: `value="<?php echo $memberDetails['occupation']; ?>"`
- **Data Source:** `members` table — payload `"><script>alert(1)</script>` in any field breaks attribute context

**10. Edit Membership Type Form — Value Attributes**
- **File:** `edit_type.php`
- **Lines:** 78, 82
- **Sinks:**
  - Line 78: `value="<?php echo $editData['type']; ?>"`
  - Line 82: `value="<?php echo $editData['amount']; ?>"`
- **Data Source:** `membership_types` table

**11. Renew Form — Pre-populated Value Attributes**
- **File:** `renew.php`
- **Lines:** 100, 104
- **Sinks:**
  - `value="<?php echo $memberDetails['fullname']; ?>"`
  - `value="<?php echo $memberDetails['membership_number']; ?>"`
- **Data Source:** `members` table

---

### HTML Attribute Context — Reflected XSS (Direct User Input)

**12. Edit Membership Type — GET `id` Reflected into Hidden Input**
- **File:** `edit_type.php`
- **Line:** 72
- **Sink:** `value="<?php echo $edit_id; ?>"` where `$edit_id = $_GET['id'] ?? null;`
- **Data Source:** `$_GET['id']` — direct user input reflected into HTML attribute without encoding
- **Payload:** `?id="><script>alert(1)</script>` (URL: `/edit_type.php?id="><script>alert(1)</script>`)

---

### HTML Body Context — Stored XSS (Settings — Affects ALL Pages)

**13. Page Title — All Authenticated Pages**
- **File:** `includes/header.php`
- **Line:** 13
- **Sink:** `<title><?php echo $systemName; ?></title>`
- **Data Source:** `settings.system_name` (set via `settings.php` POST — SQLi/XSS writable)
- **Note:** Fires on every page load for authenticated users. Payload in `settings.system_name`: `</title><script>alert(document.cookie)</script>`

**14. Sidebar Brand Text — All Authenticated Pages**
- **File:** `includes/sidebar.php`
- **Line:** 28
- **Sink:** `<span class="brand-text font-weight-light"><?php echo getSystemName(); ?></span>`
- **Data Source:** `settings.system_name`
- **Note:** Same persistence as #13 — fires on every page

---

### URL Context — Stored XSS (img src Attributes)

**15. Member Photo Path in `img src`**
- **Files:** `memberProfile.php` line 139, `print_membership_card.php` line 165, `dashboard.php` line 299
- **Sink Pattern:** `echo '<img src="uploads/member_photos/' . $memberDetails['photo'] . '" ...>';`
- **Data Source:** `members.photo` database column (stored filename from upload)
- **Exploit:** If `photo` column contains `" onerror="alert(1)`, the attribute breaks and executes JavaScript
- **Also:** Uploaded `.php` files' paths would be stored here and served as webshells when directly accessed

**16. Logo URL in `img src`**
- **File:** `print_membership_card.php`
- **Line:** 150
- **Sink:** `echo "<span class='logo'><img src='{$logoUrl}' alt='Logo'></span>";`
- **Data Source:** `settings.logo` database column (set via `settings.php` POST handler)

---

### jQuery XSS Sinks (Inherited CVE Risk)

**17. jQuery 3.4.1 `.html()` Sink**
- **Files:** Multiple pages using DataTables, jQuery UI (`plugins/datatables/*.js`, `plugins/jquery-ui/jquery-ui.js`)
- **CVEs:** CVE-2020-11022, CVE-2020-11023 — `jQuery.html()` with untrusted input executes script elements
- **Context:** DataTables renders member data from server into table rows via jQuery `.html()` calls. If stored XSS payloads contain `<script>` tags (which would be rendered server-side and could also be injected via DataTables client-side rendering), XSS fires.

---

## 10. SSRF Sinks

**Overview:** The application contains **no Server-Side Request Forgery vulnerabilities**. There are no HTTP client libraries, no curl calls, no `file_get_contents()` with URL parameters, no URL-fetching primitives, no XML parsers, no webhook functionality, no import-from-URL features, no SMTP sending, and no socket operations. The application is a self-contained PHP/MySQL system with no outbound network connectivity in its application code.

### HTTP(S) Clients
**None found.** No `curl_init()`, `curl_setopt()`, `curl_exec()`, `file_get_contents()` with HTTP URLs, `fopen()` with HTTP wrappers, or any HTTP client library (Guzzle, etc.) exists in the codebase.

### Raw Sockets & Connect APIs
**None found.** No `fsockopen()`, `stream_socket_client()`, or socket operations exist.

### URL Openers & File Includes
**None found.** All `include()`/`require()` calls use hardcoded local paths. No URL-based includes. No `allow_url_include` references.

### Redirect & "Next URL" Handlers — FINDING

**Open Redirect via `HTTP_REFERER` (Client-side only — not SSRF)**
- **File:** `delete_membership.php`
- **Lines:** 15 and 22
- **Code:**
  ```php
  header("Location: ".$_SERVER['HTTP_REFERER']);
  ```
- **Analysis:** `$_SERVER['HTTP_REFERER']` is entirely attacker-controlled (sent in the `Referer:` HTTP request header). Both success and fallback branches blindly redirect to this value. This enables a client-side **open redirect** — the victim's browser is redirected to an attacker-controlled URL after the delete action. Note: This is a redirect issued to the end user's browser, **not** a server-side outbound connection; it is not SSRF. However, it is exploitable for phishing. The `Referer` header may also contain CRLF sequences enabling **HTTP header injection** in some configurations.
- **Scope:** In-scope — this endpoint is authenticated and network-reachable.
- **All other `header("Location: ...")` calls** in the codebase use hardcoded string literals (e.g., `"Location: manage_members.php"`) and are not user-influenced.

### Headless Browsers & Render Engines
**None found.**

### Media Processors
**None found.** Image uploads use `move_uploaded_file()` with no server-side image processing library.

### Webhook Testers & Callback Verifiers
**None found.**

### SSO/OIDC Discovery & JWKS Fetchers
**None found.** No OAuth, OIDC, or SSO integrations exist.

### Importers & Data Loaders
**None found.** No CSV import, bulk URL-based data load, or "import from URL" functionality.

### XML/HTML Parsers (XXE)
**None found.** No `simplexml_load_string()`, `DOMDocument::loadXML()`, or XML parsing of any kind.

### Cloud Metadata Helpers
**None found.** No AWS/GCP/Azure metadata endpoint calls.

### Email (SMTP Injection)
**None found.** No `mail()` function calls, no PHPMailer, no SMTP configuration anywhere.

### Summary
The only external-request-adjacent finding is the open redirect in `delete_membership.php` lines 15 and 22, which is a client-side redirect to an attacker-controlled `Referer` header value. No SSRF vectors exist in this codebase.

