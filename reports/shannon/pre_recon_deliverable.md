# Penetration Test Scope & Boundaries

**Primary Directive:** This analysis is strictly limited to the **network-accessible attack surface** of the EHTDA Membership Management System. All subsequent tasks must adhere to this scope. Before reporting any finding (e.g., an entry point, a vulnerability sink), it has been verified against the "In-Scope" criteria below.

### In-Scope: Network-Reachable Components
A component is considered **in-scope** if its execution can be initiated, directly or indirectly, by a network request that the deployed application server is capable of receiving. This includes:
- Publicly exposed web pages and API endpoints.
- Endpoints requiring authentication via the application's standard login mechanisms.
- Any developer utility, debug console, or script that has been mistakenly exposed through a route or is otherwise callable from other in-scope, network-reachable code.

### Out-of-Scope: Locally Executable Only
A component is **out-of-scope** if it **cannot** be invoked through the running application's network interface and requires an execution context completely external to the application's request-response cycle. This includes tools that must be run via:
- A command-line interface (e.g., shell scripts, CLI migrations).
- CI/CD pipeline scripts or build tools.
- Database migration scripts (e.g., `init.sql` run at container startup).
- Local development servers, test harnesses, or debugging utilities.

**Out-of-Scope Components Identified:**
- `/repos/MembershipManagementSystemPHP/init.sql` — Database initialization script executed by the MySQL container at startup. Not directly network-accessible; however, it seeds default credentials and schema that are highly relevant to network-reachable endpoints.
- `/repos/MembershipManagementSystemPHP/Dockerfile` and `docker-compose.yml` — Container build/orchestration files. Not network-accessible themselves, but they contain hardcoded credentials that affect the runtime environment.

---

## 1. Executive Summary

The EHTDA Membership Management System is a **raw PHP application with no framework**, deployed via Docker on Apache/PHP 8.1. The security posture of this application is **critically deficient across every major security domain**. There are no prepared statements, no output encoding, no CSRF protection, no secure session configuration, no file upload validation, and the sole authentication mechanism uses MD5 password hashing — a broken algorithm. The combination of these deficiencies means a remote attacker with no prior credentials can achieve **full database compromise, unauthenticated data exfiltration, and likely Remote Code Execution** within minutes of initial access.

The most immediately exploitable attack chains are: (1) unauthenticated SQL injection on `delete_members.php` and `print_membership_card.php`, both of which lack any session guard and accept unsanitized GET parameters directly into DELETE and SELECT queries; (2) unrestricted file upload via `settings.php` which uses the raw client-supplied filename to place arbitrary files (including `.php` webshells) directly in the web-accessible `uploads/` directory; and (3) authentication bypass via SQL injection on the login form at `index.php`. The default seeded admin credentials (`admin@test.com` / `admin123`) further guarantee initial access even without exploiting SQL injection.

The application stores substantial member PII (full names, dates of birth, addresses, license numbers, blood type) in plaintext with no encryption. All 19 PHP files are at the document root with no routing protection, and the `includes/config.php` file containing database credentials is potentially web-accessible. No security headers are set, the session cookie has no `HttpOnly`, `Secure`, or `SameSite` flags, and no CSRF tokens protect any of the 13+ state-changing forms. This application requires complete security remediation before any production deployment.

---

## 2. Architecture & Technology Stack

- **Framework & Language:** Raw PHP 8.1 (no framework — no Laravel, CodeIgniter, Symfony, or any MVC pattern). The application consists of 19 standalone PHP files at the document root, each handling its own routing, database access, business logic, and HTML rendering in a monolithic, procedural style. The UI layer uses the AdminLTE 3 Bootstrap-based admin template with jQuery DataTables for tabular data. No `composer.json` or Composer-managed dependencies exist. Third-party assets (AdminLTE, jQuery, Bootstrap, Font Awesome) are referenced from `dist/` and `plugins/` directories that are absent from the repository and presumably deployed separately.

- **Architectural Pattern:** Direct file access architecture — there is no front controller or URL routing layer. Every `.php` file in the document root is independently reachable by direct HTTP request (e.g., `http://host/delete_members.php?id=1`). Apache's `mod_rewrite` is enabled but no `.htaccess` rewrite rules exist, meaning there is no URL normalization or request filtering layer. The `includes/` subdirectory contains `config.php` which handles the database connection and calls `session_start()`, but this directory has no `deny from all` protection and is potentially web-accessible. The trust boundary between the web tier and the database is weak: the application connects to MySQL as the `root` user with the password `rootpass`, giving full database-level control to any SQL injection.

- **Critical Security Components:** The application uses **no security libraries of any kind**. Password storage uses `md5()` (a 1992-era general-purpose hash, not a password hash). There is no CSRF library, no input validation library, no output encoding, no prepared statement use, and no security headers middleware. The database extension is `mysqli` (procedural style), used exclusively via `$conn->query()` with raw string interpolation. The sole security mechanism is the per-page session guard `if (!isset($_SESSION['user_id'])) { header("Location: index.php"); exit(); }`, which is missing entirely from three files (`delete_members.php`, `print_membership_card.php`, `get_membership_amount.php`).

- **Technology Stack Summary:**

| Component | Technology | Security Implication |
|---|---|---|
| Language | PHP 8.1 | Modern version; attack surface is in application logic, not runtime |
| Web Server | Apache (mod_rewrite enabled) | No `.htaccess`; all directories accessible |
| Database | MySQL 8.0 via mysqli | Root account; no prepared statements |
| Password Hashing | MD5 (unsalted) | Broken; rainbow-table reversible |
| Session Management | PHP native sessions | No secure flags, no regeneration |
| File Upload | `move_uploaded_file()` | No validation; RCE possible |
| Containerization | Docker / docker-compose | Hardcoded credentials in tracked files |
| External CDNs | Ionic Framework, Google Fonts | Minor: loaded over HTTP in some contexts |

---

## 3. Authentication & Authorization Deep Dive

**Authentication Mechanism:**
The login handler at `index.php` (lines 4–30) accepts `$_POST['email']` and `$_POST['password']`, hashes the password with `md5($password)` (line 12), and executes the raw SQL query: `SELECT * FROM users WHERE email = '$email' AND password = '$hashed_password'` (line 14). There is no prepared statement, no rate limiting, no account lockout, and no MFA. The MD5 hash is computed server-side before the SQL injection occurs, which means the `$email` field is the primary injection vector — a payload of `' OR '1'='1' -- ` in the email field bypasses authentication entirely. The `users` table contains only `id`, `email`, and `password` columns; there is no `role`, `is_active`, `login_attempts`, or `locked_until` field. After successful authentication, only `$_SESSION['user_id']` and `$_SESSION['email']` are set (lines 20–21); there is no multi-factor challenge or session integrity check.

**Authentication Endpoints (Exhaustive List):**
- `POST /index.php` — Primary login endpoint. Parameters: `email`, `password`, `login`. No authentication required. **SQL injection on `email` field.**
- `GET /logout.php` — Session destruction. No CSRF token required; any GET request (including from a cross-origin `<img src>` tag) destroys the session.
- `POST /settings.php` (with param `changePassword`) — Password change for authenticated admin. Parameters: `currentPassword`, `newPassword`, `confirmPassword`. Uses `md5()` for both verification and new hash storage (lines 58–59). No re-authentication challenge beyond the current password.

**Session Management:**
`session_start()` is called at `/repos/MembershipManagementSystemPHP/includes/config.php` line 2, included at the top of every page. **Session cookie flags are never configured** — there is no `session_set_cookie_params()` call, no `ini_set('session.cookie_httponly', 1)`, no `ini_set('session.cookie_secure', 1)`, and no `ini_set('session.cookie_samesite', 'Strict')` anywhere in the entire codebase. PHP's default behavior (HttpOnly: off, Secure: off, SameSite: none) applies. The session cookie is transmitted in plaintext over HTTP (no TLS configured), is accessible to JavaScript (no HttpOnly), and is sent cross-origin (no SameSite). `session_regenerate_id()` is **never called** after login, leaving the application vulnerable to session fixation — an attacker who can set a victim's session cookie before login retains control of the session after authentication. `logout.php` clears the session array and calls `session_destroy()` but does not delete the cookie from the client via `setcookie(session_name(), '', time()-3600)`.

**Authorization Model:**
The application implements a flat, single-role authorization model. There is one admin account and no concept of roles, groups, or permissions. The authorization check used on 14 of 19 files is: `if (!isset($_SESSION['user_id'])) { header("Location: index.php"); exit(); }`. Three files have **no authorization check at all**: `delete_members.php` (destructive DELETE operation), `print_membership_card.php` (PII disclosure), and `get_membership_amount.php` (data disclosure). In two files (`manage_members.php` lines 4–11 and `list_renewal.php` lines 4–10), the database query executes *before* the session guard, meaning unauthenticated requests cause unnecessary database load — a minor logic flaw. There are no privilege escalation paths since there is only one account level, but the absence of authorization on delete/read operations is a critical bypass.

**SSO/OAuth/OIDC:** Not present. No external identity provider integration exists.

**Password Reset:** No password reset mechanism exists. There is no "Forgot Password" link, no reset token generation, no email verification, and no related database columns or tables.

---

## 4. Data Security & Storage

**Database Security:**
The application connects to MySQL 8.0 as the `root` user with the hardcoded fallback password `rootpass` (`/repos/MembershipManagementSystemPHP/includes/config.php`, lines 4–8). This connection is made using `new mysqli()` with no SSL options, meaning all queries (including those containing PII) travel unencrypted between the PHP application container and the MySQL container. The `root` account has full privileges over all databases on the server, meaning a successful SQL injection can be escalated beyond the `membership_db` database to any system database. Connection errors are disclosed directly to the browser via `die("Connection failed: " . $conn->connect_error)` (line 12 of `config.php`), potentially leaking database server information. No least-privilege application database account exists; the same root credentials used for application queries are also the MySQL superuser credentials committed to `docker-compose.yml`.

**Data Flow Security:**
All member PII (full name, date of birth, gender, contact number, email, address, country, license number, blood type) is stored in plaintext in the `members` table with no column-level encryption, no data masking, and no field-level access control. The `renew` table stores financial amounts in plaintext. PII flows from `$_POST` fields in `add_members.php` directly into SQL INSERT statements with no sanitization, is stored raw in the database, and is retrieved and echoed back to HTML without `htmlspecialchars()` encoding — creating both SQL injection and stored XSS vectors in the same data flow. Member photos are stored in `uploads/member_photos/` (web-accessible directory) and the filename is stored in `members.photo`. The logo path is stored in `settings.logo`. Both are concatenated into HTML `src` attributes without encoding, and the files themselves are directly web-accessible with no PHP execution prevention in the `uploads/` directory.

**Sensitive Data Exposure:**
- `init.sql` line 50 contains the cleartext admin password `admin123` as a SQL argument to `MD5()`, committed to git history.
- `docker-compose.yml` lines 9–10 and line 21 contain the plaintext database root password `rootpass`, committed to git.
- Database and SQL errors are echoed to the browser in 16 locations throughout the codebase (see complete list under Section 6). Notably, `manage_members.php` line 24 and `view_type.php` line 34 echo the **full SQL query string** including user-supplied data alongside the MySQL error, providing complete schema enumeration to any attacker who triggers an error.

**Multi-tenant Data Isolation:**
The application is **single-tenant** — there are no tenant IDs, no row-level security mechanisms, and no data partitioning. All data is globally accessible to any authenticated session.

---

## 5. Attack Surface Analysis

**External Entry Points (In-Scope, Network-Reachable):**

The application uses a direct-file-access architecture: every `.php` file at the document root is a network-reachable entry point. All files are served from Apache port 80 (mapped to host port 9010 via docker-compose).

**Unauthenticated Entry Points (Highest Priority):**

| Endpoint | Method | Parameters | Critical Risk |
|---|---|---|---|
| `GET /index.php` | GET, POST | `email`, `password`, `login` | SQL injection → auth bypass |
| `GET /delete_members.php` | GET | `id` | **No auth check** — SQL injection → unauthenticated DELETE of any member record |
| `GET /print_membership_card.php` | GET | `id` | **No auth check** — SQL injection → unauthenticated PII disclosure of all member records |
| `GET /get_membership_amount.php` | GET | `membershipTypeId` | No auth check — SQL injection → data disclosure |
| `GET /logout.php` | GET | (none) | No CSRF protection — cross-site session destruction |

**Authenticated Entry Points:**

| Endpoint | Method | Parameters | Critical Risk |
|---|---|---|---|
| `POST /add_members.php` | GET, POST | `fullname`, `dob`, `gender`, `contactNumber`, `email`, `address`, `country`, `postcode`, `occupation`, `membershipType`, `photo` (file) | SQL injection + unrestricted file upload (RCE) |
| `GET,POST /edit_member.php` | GET, POST | `id` (GET), all member fields (POST), `photo` (file) | SQL injection + unrestricted file upload (RCE) |
| `GET /delete_membership.php` | GET | `id` | SQL injection + open redirect via `HTTP_REFERER` |
| `GET,POST /renew.php` | GET, POST | `id` (GET), `membershipType`, `extend`, `totalAmount`, `member_id` (POST) | SQL injection |
| `GET,POST /settings.php` | GET, POST | `systemName`, `currency`, `logo` (file), `updateSettings` / `currentPassword`, `newPassword`, `confirmPassword`, `changePassword` | SQL injection + **most dangerous file upload** (raw filename used, RCE) |
| `GET,POST /report.php` | GET, POST | `fromDate`, `toDate` | SQL injection via date range |
| `GET,POST /revenue_report.php` | GET, POST | `fromDate`, `toDate` | SQL injection via date range |
| `GET,POST /manage_members.php` | GET, POST | `membershipType`, `membershipAmount` | SQL injection + stored XSS |
| `GET,POST /add_type.php` | GET, POST | `membershipType`, `membershipAmount` | SQL injection |
| `GET,POST /edit_type.php` | GET, POST | `id` (GET), `membershipType`, `membershipAmount`, `edit_id` (POST) | SQL injection + reflected XSS on `edit_id` |
| `GET,POST /view_type.php` | GET, POST | `membershipType`, `membershipAmount` | SQL injection + echoes raw SQL query to browser |
| `GET /dashboard.php` | GET | (none) | Stored XSS via member data display |
| `GET /memberProfile.php` | GET | `id` | SQL injection + reflected XSS on `$memberId` in onclick/href |
| `GET /list_renewal.php` | GET | (none) | Stored XSS via member data display |
| `GET /print_membership_card.php` | GET | `id` | (**also unauthenticated** — see above) |

**Sensitive File Potentially Web-Accessible:**
- `GET /includes/config.php` — If PHP processing fails, the source containing DB credentials could be served as plaintext.

**Input Validation Patterns:**
There are **no input validation patterns** in this application. Every `$_GET`, `$_POST`, and `$_FILES` value is used without type casting (except `$memberId` in some files which uses `$_GET['id']` directly without `intval()`), sanitization, or validation. `$_FILES['logo']['name']` in `settings.php` is used as-is for the upload destination filename. Date values in `report.php` and `revenue_report.php` are passed directly from `$_POST` into SQL BETWEEN clauses without format validation.

**Background Processing:**
No cron jobs, queue workers, or background task configurations exist. All processing is synchronous within the HTTP request-response cycle.

**API Schema Files:**
No OpenAPI/Swagger, GraphQL, or other API schema files were found in the repository.

---

## 6. Infrastructure & Operational Security

**Secrets Management:**
This application has no secrets management solution. The database password `rootpass` appears in plaintext in three locations: `docker-compose.yml` (committed to git, line 10 and line 21), `includes/config.php` as a hardcoded fallback (line 6), and implicitly in the environment variable `DB_PASS` injected at runtime. There is no `.gitignore` file, meaning any `.env` file created in the future would be automatically committed. The MySQL root password serves dual purpose — it is both the application's database password and the MySQL superuser password, meaning there is no separation between application-level and administrative-level database access.

**Configuration Security:**
The Docker deployment exposes port 80 (HTTP only) — no TLS is configured anywhere. The `Dockerfile` copies the entire repository into `/var/www/html/`, including `.git/` history and `.shannon/` analysis artifacts. No `EXPOSE 443` or TLS termination exists. Apache runs with `mod_rewrite` enabled but no `.htaccess` file restricts access to sensitive directories (`includes/`, `uploads/`). No environment separation (dev/staging/prod) is configured; the hardcoded defaults in `config.php` suggest the same credentials are used in all environments. No security headers (`X-Frame-Options`, `Content-Security-Policy`, `X-Content-Type-Options`, `Strict-Transport-Security`, `X-XSS-Protection`) are set by Apache configuration, `.htaccess`, or PHP `header()` calls.

**External Dependencies:**
No Composer dependencies exist. The application loads resources from two external CDNs: `https://code.ionicframework.com/ionicons/2.0.1/css/ionicons.min.css` and `https://fonts.googleapis.com/css?family=Source+Sans+Pro`. These are minor supply chain risks but are out of scope for network-level testing. There are no payment gateways, OAuth providers, or external API integrations.

**Monitoring & Logging:**
The application has no structured logging, no security event logging, and no intrusion detection integration. Two `error_log()` calls exist in `get_membership_amount.php` (lines 12 and 28) logging membership type IDs and AJAX responses to the Apache error log. Database errors are disclosed to the browser in 16 locations rather than being logged server-side — this means security-relevant error events (including SQL injection error responses) are visible to attackers but not captured in any server-side log for defensive monitoring. There is no login attempt logging, no failed authentication recording, and no session anomaly detection.

---

## 7. Overall Codebase Indexing

The repository at `/repos/MembershipManagementSystemPHP/` contains **19 PHP application files** all placed flat at the document root, with one subdirectory (`includes/`) containing the shared configuration file. The codebase totals approximately 2,000–2,500 lines of procedural PHP across all files. There is no build system, no test framework, no linter configuration, and no dependency manager. The `Dockerfile` and `docker-compose.yml` define the complete deployment environment (PHP 8.1 / Apache, MySQL 8.0), and `init.sql` provides the database schema and seed data. The `dist/` and `plugins/` directories referenced in HTML templates are absent from the repository and must be supplied separately, likely as a pre-built AdminLTE distribution. The naming convention is functional (e.g., `add_members.php`, `edit_member.php`, `delete_members.php`) with no namespace, class, or modular organization. Security-relevant code is discoverable by reading each `.php` file sequentially; the shared `includes/config.php` is the only centralized component. The lack of a routing layer, framework, or MVC pattern means every `.php` file independently manages authentication guards (with three files failing to do so), database connections (all inherited from `config.php`), and HTML output (all unencoded). This flat structure makes the entire attack surface immediately enumerable by directory listing or source review.

---

## 8. Critical File Paths

### Configuration
- `/repos/MembershipManagementSystemPHP/includes/config.php` — DB credentials, session_start(), connection error disclosure
- `/repos/MembershipManagementSystemPHP/docker-compose.yml` — Hardcoded DB root password (`rootpass`) in git-tracked file
- `/repos/MembershipManagementSystemPHP/Dockerfile` — Container definition; copies entire repo including `.git/` to web root
- `/repos/MembershipManagementSystemPHP/init.sql` — Database schema + seed data including default admin MD5 hash

### Authentication & Authorization
- `/repos/MembershipManagementSystemPHP/index.php` — Login handler: SQL injection on `email` field (line 14), MD5 hashing (line 12)
- `/repos/MembershipManagementSystemPHP/logout.php` — Session destruction; no CSRF protection; does not delete client cookie
- `/repos/MembershipManagementSystemPHP/settings.php` — Password change handler (lines 44–72); also the most dangerous file upload endpoint
- `/repos/MembershipManagementSystemPHP/delete_members.php` — **No session guard** (critical); unauthenticated DELETE; SQL injection (lines 35, 39, 46)
- `/repos/MembershipManagementSystemPHP/print_membership_card.php` — **No session guard** (critical); unauthenticated PII disclosure; SQL injection (line 5–8)
- `/repos/MembershipManagementSystemPHP/get_membership_amount.php` — No session guard; SQL injection (line 14)

### API & Routing
- `/repos/MembershipManagementSystemPHP/index.php` — Login form and POST handler
- `/repos/MembershipManagementSystemPHP/dashboard.php` — Main dashboard; stored XSS in member display (lines 301, 307, 310)
- `/repos/MembershipManagementSystemPHP/manage_members.php` — Member list; echoes raw SQL query on error (line 24); auth-after-query flaw (lines 4–11)
- `/repos/MembershipManagementSystemPHP/list_renewal.php` — Renewal list; auth-after-query flaw (lines 4–10)
- `/repos/MembershipManagementSystemPHP/get_membership_amount.php` — Unauthenticated AJAX/JSON API endpoint

### Data Models & DB Interaction
- `/repos/MembershipManagementSystemPHP/init.sql` — Schema: `users`, `members`, `membership_types`, `renew`, `settings` tables
- `/repos/MembershipManagementSystemPHP/add_members.php` — Member INSERT; all POST fields SQL-injectable (lines 45–48); unrestricted file upload (lines 36–43)
- `/repos/MembershipManagementSystemPHP/edit_member.php` — Member UPDATE; SQL injection on all fields (lines 17, 56–59); unrestricted file upload (lines 50–53)
- `/repos/MembershipManagementSystemPHP/renew.php` — Renewal INSERT/UPDATE; SQL injection including on `totalAmount` (lines 34, 39)
- `/repos/MembershipManagementSystemPHP/report.php` — Date range SQL injection (line 16)
- `/repos/MembershipManagementSystemPHP/revenue_report.php` — Date range SQL injection (line 17)

### Dependency Manifests
- None (no `composer.json`, `package.json`, or `requirements.txt` exist)

### Sensitive Data & Secrets Handling
- `/repos/MembershipManagementSystemPHP/includes/config.php` — DB credentials; hardcoded fallbacks `root`/`rootpass`
- `/repos/MembershipManagementSystemPHP/docker-compose.yml` — Plaintext `MYSQL_ROOT_PASSWORD: rootpass`
- `/repos/MembershipManagementSystemPHP/init.sql` — `MD5('admin123')` seed; admin email `admin@test.com`

### Middleware & Input Validation
- None — no middleware layer, no input validation library, no sanitization functions exist.

### Logging & Monitoring
- `/repos/MembershipManagementSystemPHP/get_membership_amount.php` — Lines 12, 28: only `error_log()` calls in entire codebase
- `/repos/MembershipManagementSystemPHP/manage_members.php` — Line 24: echoes raw SQL query + DB error to browser
- `/repos/MembershipManagementSystemPHP/view_type.php` — Line 34: echoes raw SQL query + DB error to browser

### Infrastructure & Deployment
- `/repos/MembershipManagementSystemPHP/Dockerfile` — PHP 8.1 + Apache; port 80 only; no TLS
- `/repos/MembershipManagementSystemPHP/docker-compose.yml` — Port mapping 9010:80; hardcoded MySQL root password

---

## 9. XSS Sinks and Render Contexts

All XSS sinks below are on network-accessible pages. The application has **zero instances of `htmlspecialchars()`, `htmlentities()`, or any output encoding** — every database-sourced and user-input-sourced variable is echoed raw to HTML. All member data fields constitute stored XSS vectors (data stored via SQL injection-vulnerable INSERTs and echoed without encoding).

### HTML Body Context — Stored XSS (DB Data Echoed Raw)

These sinks render data originally sourced from user-supplied POST fields, stored in the database without sanitization, and echoed back without encoding:

| File | Line(s) | Sink | Data Source |
|---|---|---|---|
| `manage_members.php` | 90–95 | `echo "<td>{$row['fullname']}</td>"` and similar for `contact_number`, `email`, `address`, `membership_type_name` | DB: `members`, `membership_types` tables |
| `manage_members.php` | 24 | `echo "Error: " . $insertQuery . "<br>" . $conn->error` | Reflected: `$_POST['membershipType']` injected into SQL string, echoed |
| `memberProfile.php` | 120–132 | `echo $memberDetails['membership_number']`, `fullname`, `dob`, `gender`, `contact_number`, `email`, `address`, `country`, `postcode`, `occupation`, `membership_type_name` | DB: `members` JOIN `membership_types` |
| `dashboard.php` | 307, 310 | `echo '<a ...>' . $row['fullname'] . '</a>'` and `'Membership Number: ' . $row['membership_number']` | DB: `members` |
| `list_renewal.php` | 83–97 | `echo "<td>{$row['membership_number']}</td>"` and `fullname`, `contact_number`, `email`, `membership_type_name`, `expiry_date`, `$membershipStatus` | DB: `members` JOIN `membership_types` |
| `report.php` | 87–91 | `echo '<td>' . $row['membership_number'] . '</td>'` and `fullname`, `email`, `membership_type_name` | DB: `members` JOIN `membership_types` |
| `revenue_report.php` | 87–90 | `echo '<td>' . $row['fullname'] . '</td>'` and `membership_number`, `currency`, `total_amount`, `renew_date` | DB: `members` JOIN `renew` JOIN `settings` |
| `view_type.php` | 85–86 | `echo "<td>{$row['type']}</td>"` and `$currencySymbol . ' ' . $row['amount']` | DB: `membership_types`, `settings` |
| `view_type.php` | 34 | `echo "Error: " . $insertQuery . "<br>" . $conn->error` | Reflected: `$_POST['membershipType']` in SQL echoed |
| `print_membership_card.php` | 154–164 | `echo $systemName`, `$memberDetails['membership_number']`, `fullname`, `address`, `postcode`, `membership_type_name` | DB: `settings`, `members` — **also unauthenticated page** |

### HTML Attribute Context — Stored XSS

| File | Line | Sink | Data Source |
|---|---|---|---|
| `edit_member.php` | 122 | `value="<?php echo $memberDetails['fullname']; ?>"` | DB: `members.fullname` |
| `edit_member.php` | 126 | `value="<?php echo $memberDetails['dob']; ?>"` | DB |
| `edit_member.php` | 145 | `value="<?php echo $memberDetails['contact_number']; ?>"` | DB |
| `edit_member.php` | 150 | `value="<?php echo $memberDetails['email']; ?>"` | DB |
| `edit_member.php` | 158 | `value="<?php echo $memberDetails['address']; ?>"` | DB |
| `edit_member.php` | 163 | `value="<?php echo $memberDetails['country']; ?>"` | DB |
| `edit_member.php` | 171 | `value="<?php echo $memberDetails['postcode']; ?>"` | DB |
| `renew.php` | 100 | `value="<?php echo $memberDetails['fullname']; ?>" disabled` | DB |
| `renew.php` | 104 | `value="<?php echo $memberDetails['membership_number']; ?>" disabled` | DB |
| `settings.php` | 121 | `value="<?php echo $settings['system_name']; ?>"` | DB: `settings.system_name` (originally `$_POST['systemName']`) |
| `settings.php` | 133 | `value="<?php echo $settings['currency']; ?>"` | DB: `settings.currency` |
| `edit_type.php` | 78 | `value="<?php echo $editData['type']; ?>"` | DB: `membership_types.type` |
| `edit_type.php` | 82 | `value="<?php echo $editData['amount']; ?>"` | DB |

### HTML Attribute Context — Reflected XSS

| File | Line | Sink | Data Source |
|---|---|---|---|
| `edit_type.php` | 72 | `value="<?php echo $edit_id; ?>"` (hidden input) | `$_GET['id']` directly |
| `memberProfile.php` | 108 | `onclick="printMembershipCard('<?php echo $memberId; ?>')"` | `$_GET['id']` directly |
| `memberProfile.php` | 112, 145 | `href="print_membership_card.php?id=<?php echo $memberId; ?>"` | `$_GET['id']` directly |

### HTML `src` Attribute Context — Stored XSS / Content Injection

| File | Line | Sink | Data Source |
|---|---|---|---|
| `memberProfile.php` | 139 | `echo '<img src="' . $photoPath . '"...'` where `$photoPath = 'uploads/member_photos/' . $memberDetails['photo']` | DB: `members.photo` (filename from file upload) |
| `print_membership_card.php` | 150 | `echo "<span class='logo'><img src='{$logoUrl}' alt='Logo'></span>"` where `$logoUrl` from `settings.logo` | DB: `settings.logo` (raw upload filename) |
| `print_membership_card.php` | 167 | `<img src="<?php echo $photoPath; ?>"` | DB: `members.photo` |
| `dashboard.php` | 301 | `echo '<img src="' . $photoPath . '"...'` | DB: `members.photo` |

### JavaScript Context — DOM-Based / Event Handler XSS

| File | Line | Sink | Data Source |
|---|---|---|---|
| `memberProfile.php` | 108 | `onclick="printMembershipCard('<?php echo $memberId; ?>')"` — `$memberId` from `$_GET['id']` injected into a JS function call in an onclick attribute | Reflected: `$_GET['id']` |

### `<option>` Value/Body Context — Stored XSS

| File | Line | Sink | Data Source |
|---|---|---|---|
| `add_members.php` | 192 | `echo "<option value='{$row['id']}'>{$row['type']} - {$currencySymbol}{$row['amount']}</option>"` | DB: `membership_types.type`, `settings.currency` |
| `renew.php` | 117 | `echo "<option value='{$row['id']}'>{$row['type']} - {$row['amount']}</option>"` | DB: `membership_types.type` |

---

## 10. SSRF Sinks

**No SSRF vulnerabilities were identified.** A comprehensive search of the codebase confirmed the following are entirely absent:

- `curl_init()`, `curl_setopt()`, `curl_exec()` — PHP cURL not used
- `file_get_contents()` with HTTP/HTTPS URLs — not present
- `fopen()` with HTTP/HTTPS URLs — not present
- Any HTTP client library (Guzzle, etc.) — no Composer dependencies exist
- `mail()` / SMTP libraries — not present
- Payment gateway integrations (Stripe, PayPal, etc.) — not present
- OAuth flows or external URL redirects from parameters — not present
- Webhook outbound calls — not present
- `copy($url, $dest)` or image functions with remote URLs — not present
- Dynamic `include`/`require` with user-controlled paths — not present (all inclusions use hardcoded `includes/` paths)

**One Open Redirect was identified** (not technically SSRF but a related server-controlled redirect using attacker-supplied input):

**File:** `/repos/MembershipManagementSystemPHP/delete_membership.php`
**Lines:** 15 and 22
**Code:**
```php
header("Location: ".$_SERVER['HTTP_REFERER']);
```
`$_SERVER['HTTP_REFERER']` is an HTTP request header fully controlled by the client. This value is used verbatim as the `Location:` redirect target with no validation, allowlisting, or sanitization. An attacker can forge the `Referer` header to redirect victims to an arbitrary URL (e.g., `https://attacker.com/phishing`) after any membership type deletion action. The second occurrence (line 22) fires even for non-GET requests, making the open redirect reachable without a valid `id` parameter.
