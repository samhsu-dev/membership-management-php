# Authentication Analysis Report

## 1. Executive Summary

- **Analysis Status:** Complete
- **Key Outcome:** Eight distinct authentication and session management vulnerabilities were identified. The application is critically compromised across every authentication domain: it uses a broken password hashing algorithm (MD5, unsalted), has no rate limiting on any authentication endpoint, exposes admin credentials in a publicly-downloadable file, allows SQL injection authentication bypass, is vulnerable to session fixation (session ID never regenerated after login), sets no `HttpOnly`, `Secure`, or `SameSite` flags on the session cookie, and has three endpoints that require no authentication at all. The application is served over plain HTTP with no TLS.
- **Purpose of this Document:** This report provides the strategic context on the application's authentication mechanisms, dominant flaw patterns, and key architectural details necessary to effectively exploit the vulnerabilities listed in the exploitation queue.

---

## 2. Dominant Vulnerability Patterns

### Pattern 1: Complete Absence of Transport Security
- **Description:** The application is served exclusively over HTTP (port 9010) with zero TLS/HTTPS. No `Strict-Transport-Security` header is ever sent. Session cookies and credentials are transmitted in plaintext over the network. Confirmed live: `curl -si http://host.docker.internal:9010/index.php` — no HSTS header, no TLS redirect.
- **Implication:** Any network-adjacent attacker (on the same network segment or an upstream provider) can passively intercept session cookies and credentials in transit, enabling trivial session hijacking and credential theft.
- **Representative Findings:** `AUTH-VULN-01`.

### Pattern 2: Broken Authentication Credentials (MD5 + Default Credentials)
- **Description:** All passwords are stored as bare MD5 hashes (no salt, no work factor). The default admin password (`codeastro.com`) is committed to version control, present in seven copies including one in the web-accessible `uploads/` directory. The MD5 hash (`f2d0ff370380124029c2b807a924156c`) is also present in a publicly downloadable database dump at `/DATABASE FILE/membershiphp.sql`. Both the plaintext credential and the MD5 hash are trivially obtainable by any unauthenticated visitor.
- **Implication:** An attacker can log in immediately without brute force by downloading `uploads/01 LOGIN DETAILS & PROJECT INFO.txt` — no guessing required. Even if credentials were changed, MD5 is reversible with rainbow tables (e.g., crackstation.net).
- **Representative Findings:** `AUTH-VULN-04`, `AUTH-VULN-05`.

### Pattern 3: Session Management Failures
- **Description:** Three independent session management failures compound each other: (a) No session ID rotation after login (`session_regenerate_id()` never called), enabling session fixation — confirmed live; (b) `PHPSESSID` cookie lacks `HttpOnly`, `Secure`, and `SameSite` flags — confirmed live: `Set-Cookie: PHPSESSID=...; path=/` only; (c) No session timeout configured beyond PHP defaults (1440s).
- **Implication:** Attackers can pre-plant a known session ID, wait for the admin to log in, and then use that same ID to access the application. The missing `HttpOnly` flag allows JavaScript to read the session cookie (enabling XSS-to-session-hijack chains). The missing `Secure` flag allows cookie transmission over HTTP.
- **Representative Findings:** `AUTH-VULN-02`, `AUTH-VULN-03`.

### Pattern 4: SQL Injection Authentication Bypass
- **Description:** The login handler at `index.php:14` concatenates raw POST parameters directly into a SQL query: `SELECT * FROM users WHERE email = '$email' AND password = '$hashed_password'`. The `email` field is completely unsanitized. A payload of `' OR '1'='1' -- -` bypasses authentication entirely. Confirmed live: sending this payload returns HTTP 302 redirect to `dashboard.php`.
- **Implication:** An attacker can log in as the admin without knowing any credentials by exploiting the SQL injection.
- **Representative Findings:** `AUTH-VULN-06`.

### Pattern 5: No Rate Limiting on Any Authentication Endpoint
- **Description:** Ten rapid successive failed login attempts to `POST /index.php` all returned HTTP 200 with no lockout, no CAPTCHA, no throttle, no 429 response. Confirmed live. No WAF, no reverse proxy, and no application-level rate limiting exist anywhere.
- **Implication:** Attackers can brute-force passwords or perform credential stuffing at unlimited speed.
- **Representative Findings:** `AUTH-VULN-07`.

### Pattern 6: Missing Authentication on Critical Endpoints
- **Description:** Three endpoints — `print_membership_card.php`, `delete_members.php`, and `get_membership_amount.php` — have no `isset($_SESSION['user_id'])` check whatsoever. All three are accessible by any unauthenticated HTTP request. Confirmed live: `GET /print_membership_card.php?id=1` returns HTTP 200 with full member PII; `GET /delete_members.php?id=X` returns HTTP 302 (executes delete logic) without authentication.
- **Implication:** Any unauthenticated attacker can enumerate and delete all member records, and read all member PII without any credentials.
- **Representative Findings:** `AUTH-VULN-08`.

---

## 3. Strategic Intelligence for Exploitation

- **Authentication Method:** Username/password form POST to `/index.php`. PHP file-based session (`PHPSESSID` cookie). No JWT, no OAuth, no MFA, no password reset flow.
- **Session Token Details:** Session is managed via PHP's default `session_start()`. Cookie: `PHPSESSID=<value>; path=/` — no `HttpOnly`, no `Secure`, no `SameSite`. Sessions stored in `/tmp/sess_*` on the server. Default TTL ~1440 seconds (PHP `session.gc_maxlifetime`). `session_regenerate_id()` is never called — session fixation is exploitable.
- **Password Policy:** No server-side password policy enforced. Passwords hashed with bare `md5()` at `index.php:12`. No minimum length, no complexity requirements, no breach-list check. Change password via `POST /settings.php` with `changePassword` action; `confirmPassword` field is read but never compared to `newPassword` (dead code at `settings.php:48`).
- **Default Credentials:** `admin@mail.com` / `codeastro.com` — publicly available at `http://host.docker.internal:9010/uploads/01%20LOGIN%20DETAILS%20%26%20PROJECT%20INFO.txt`. MD5 hash also in `/DATABASE FILE/membershiphp.sql`.
- **No OAuth/SSO:** No OAuth, OIDC, SAML, or SSO flows exist.
- **No Password Reset:** No forgot-password endpoint, no token generation, no email sending.
- **No Registration:** No public user registration. Accounts require direct DB insertion.
- **Logout:** `GET /logout.php` — properly destroys server-side session (`$_SESSION = array(); session_destroy()`). No CSRF protection on logout (CSRF-forced logout possible, but out of scope for AuthN analysis).
- **Cache-Control:** `Cache-Control: no-store, no-cache, must-revalidate` and `Pragma: no-cache` are present on all pages (PHP default session headers). This is a positive control.

---

## 4. Methodology Checklist: Verdict Summary

| Check | Endpoint/Component | Verdict | Finding ID |
|---|---|---|---|
| Transport/HTTPS enforcement | All endpoints (HTTP only) | **VULNERABLE** | AUTH-VULN-01 |
| HSTS header | All responses | **VULNERABLE** | AUTH-VULN-01 |
| Cache-Control: no-store | All auth responses | **SAFE** | — |
| Rate limiting on login | `POST /index.php` | **VULNERABLE** | AUTH-VULN-07 |
| Rate limiting on password change | `POST /settings.php` (changePassword) | **VULNERABLE** | AUTH-VULN-07 |
| CAPTCHA / lockout | `POST /index.php` | **VULNERABLE** | AUTH-VULN-07 |
| Session cookie HttpOnly | `PHPSESSID` | **VULNERABLE** | AUTH-VULN-02 |
| Session cookie Secure | `PHPSESSID` | **VULNERABLE** | AUTH-VULN-02 |
| Session cookie SameSite | `PHPSESSID` | **VULNERABLE** | AUTH-VULN-02 |
| Session ID rotation after login | `POST /index.php` → session | **VULNERABLE** | AUTH-VULN-03 |
| Logout server-side invalidation | `GET /logout.php` | **SAFE** | — |
| Session IDs in URLs | All endpoints | **SAFE** | — |
| Token/session entropy | `PHPSESSID` (PHP default) | **SAFE** (PHP uses CSPRNG) | — |
| Token expiration | Session TTL | Medium risk (default 1440s only) | — |
| Session fixation | Login flow | **VULNERABLE** | AUTH-VULN-03 |
| Default credentials in code/files | `uploads/` credential file | **VULNERABLE** | AUTH-VULN-04 |
| Password hashing algorithm | `index.php:12`, `settings.php:58` | **VULNERABLE** (MD5) | AUTH-VULN-05 |
| Strong password policy | `POST /settings.php` (changePassword) | **VULNERABLE** (none enforced) | AUTH-VULN-05 |
| Error message enumeration | Login response | **SAFE** (generic "Invalid email or password") | — |
| Auth state in URLs | All redirects | **SAFE** | — |
| Recovery token single-use / TTL | N/A (no password reset flow) | N/A | — |
| Logout cookie clearing | `GET /logout.php` | **SAFE** | — |
| SQL injection auth bypass | `POST /index.php` | **VULNERABLE** | AUTH-VULN-06 |
| OAuth state/nonce | N/A (no OAuth) | N/A | — |
| Missing auth check on endpoints | `print_membership_card.php`, `delete_members.php`, `get_membership_amount.php` | **VULNERABLE** | AUTH-VULN-08 |

---

## 5. Secure by Design: Validated Components

These components were analyzed and found to have adequate defenses. They are low-priority for further testing.

| Component/Flow | Endpoint/File Location | Defense Mechanism Implemented | Verdict |
|---|---|---|---|
| Cache-Control headers | All pages (PHP session defaults) | `Cache-Control: no-store, no-cache, must-revalidate` + `Pragma: no-cache` set automatically by PHP session | SAFE |
| Session entropy | `PHPSESSID` generation | PHP uses `/dev/urandom` (CSPRNG) for session ID generation by default in PHP 7.4 | SAFE |
| Logout server-side invalidation | `logout.php:4-6` | `$_SESSION = array(); session_destroy()` — server-side session data destroyed; old session ID no longer valid | SAFE |
| Error messages (enumeration) | `index.php:26` | Generic error: "Invalid email or password!" — no differentiation between bad username and bad password | SAFE |
| Session IDs not in URLs | All pages | No `session.use_only_cookies = 0` configuration; session IDs are not appended to URLs | SAFE |
| Auth check on protected pages | All 18 protected PHP files | `if (!isset($_SESSION['user_id'])) { header("Location: index.php"); exit(); }` blocks unauthenticated access to the protected set | SAFE (for the protected set only) |
| `confirmPassword` read on change | `settings.php:48` | Read but never compared to `newPassword` — this is a logic bug (non-enforcement) rather than an auth bypass; the password change still requires valid `currentPassword` | LOW RISK |

---

## 6. Exploitation Queue

### AUTH-VULN-01: Transport Exposure — HTTP-only, No HSTS
- **Vulnerability Type:** Transport_Exposure
- **Externally Exploitable:** true
- **Source Endpoint:** ALL endpoints — `GET/POST http://host.docker.internal:9010/*`
- **Vulnerable Code Location:** No TLS configuration exists. `docker-compose.yml` exposes port 9010 as HTTP only. No `.htaccess` HTTPS redirect. No Apache `VirtualHost` with SSL. Confirmed: server responds on HTTP with no TLS.
- **Missing Defense:** No TLS/HTTPS; no `Strict-Transport-Security` header; no HTTPS redirect. All traffic including `PHPSESSID` cookies and credentials transmitted in plaintext.
- **Exploitation Hypothesis:** A network-adjacent attacker performing passive traffic interception (e.g., on the same LAN segment) can capture the admin's `PHPSESSID` session cookie or `email`/`password` credentials in cleartext as they transit the network, then replay the cookie or credentials to gain full admin access.
- **Suggested Exploit Technique:** credential/session theft via passive network interception (MITM, ARP poisoning, or passive sniff on shared network segment).
- **Confidence:** High
- **Notes:** Application is HTTP-only on port 9010. No CDN, no WAF, no TLS termination anywhere. Cookie lacks `Secure` flag, so it is also transmitted over HTTP by browsers without warning.

### AUTH-VULN-02: Session Cookie Misconfiguration — No HttpOnly, Secure, or SameSite
- **Vulnerability Type:** Session_Management_Flaw
- **Externally Exploitable:** true
- **Source Endpoint:** ALL endpoints — session cookie issued on first request to any page
- **Vulnerable Code Location:** `includes/config.php:14` — bare `session_start()` with no `session_set_cookie_params()` call. Confirmed live: `Set-Cookie: PHPSESSID=...; path=/` — no `HttpOnly`, `Secure`, or `SameSite` attributes.
- **Missing Defense:** (a) No `HttpOnly` flag — session cookie is accessible to JavaScript, enabling theft via XSS. (b) No `Secure` flag — cookie transmitted over HTTP. (c) No `SameSite` attribute — cookie sent on cross-site requests (enables CSRF-based session abuse).
- **Exploitation Hypothesis:** An attacker who chains a stored XSS vulnerability (many exist in this app) can steal the admin's `PHPSESSID` cookie value via `document.cookie` and replay it to hijack the admin session, since there is no `HttpOnly` flag preventing JavaScript access.
- **Suggested Exploit Technique:** session_hijacking via XSS-to-cookie-theft, or session theft via network interception.
- **Confidence:** High
- **Notes:** No `HttpOnly` confirmed from live header. `Secure` flag also absent (HTTP-only deployment). Pairs with AUTH-VULN-01 (no TLS) and the stored XSS findings from the recon report.

### AUTH-VULN-03: Session Fixation — No Session ID Rotation After Login
- **Vulnerability Type:** Login_Flow_Logic
- **Externally Exploitable:** true
- **Source Endpoint:** `POST /index.php`
- **Vulnerable Code Location:** `index.php:17-24` — session variables set (`$_SESSION['user_id']`, `$_SESSION['email']`), then redirect to `dashboard.php`. `session_regenerate_id()` is never called anywhere in `index.php` or `includes/config.php`.
- **Missing Defense:** No call to `session_regenerate_id(true)` after successful authentication. The pre-login session ID is directly promoted to an authenticated session.
- **Exploitation Hypothesis:** An attacker can pre-plant a known `PHPSESSID` value (by sending a request to the app and capturing the session ID, then sharing that URL/cookie with a victim), wait for the victim admin to log in using that session, and then use the same known `PHPSESSID` to access the application as the authenticated admin — without ever knowing the admin's password. Confirmed live: a pre-seeded PHPSESSID remained valid after login and provided full dashboard access.
- **Suggested Exploit Technique:** session_fixation
- **Confidence:** High
- **Notes:** Confirmed via live testing: a session ID obtained before login was used to send the login POST request; no new `Set-Cookie` header was issued on the login response; the original session ID subsequently granted full authenticated dashboard access (`HTTP 200`). The cookie also lacks `SameSite`, making it easier to deliver in cross-site scenarios.

### AUTH-VULN-04: Default Credentials Publicly Exposed
- **Vulnerability Type:** Token_Management_Issue
- **Externally Exploitable:** true
- **Source Endpoint:** `GET /uploads/01%20LOGIN%20DETAILS%20%26%20PROJECT%20INFO.txt` (credential file); `GET /DATABASE%20FILE/membershiphp.sql` (DB dump with hash)
- **Vulnerable Code Location:** `uploads/01 LOGIN DETAILS & PROJECT INFO.txt` — web-accessible plaintext file containing admin credentials. `DATABASE FILE/membershiphp.sql:153` — MD5 hash `f2d0ff370380124029c2b807a924156c`. Both files served by Apache as static files with no access restriction.
- **Missing Defense:** No `.htaccess` or Apache configuration to deny access to `uploads/01 LOGIN DETAILS...txt` or the `DATABASE FILE/` directory. Credential files were committed to and deployed in the web root.
- **Exploitation Hypothesis:** Any unauthenticated attacker can download the plaintext credential file at `http://host.docker.internal:9010/uploads/01%20LOGIN%20DETAILS%20%26%20PROJECT%20INFO.txt` to immediately obtain the admin password `codeastro.com`, then use it to authenticate via `POST /index.php` and gain full admin access.
- **Suggested Exploit Technique:** credential_stuffing / direct login with exposed default credentials.
- **Confidence:** High
- **Notes:** Confirmed live: HTTP 200 response with plaintext content including `Email: admin@mail.com` / `Password: codeastro.com`. DB dump also accessible: `GET /DATABASE%20FILE/membershiphp.sql` returns HTTP 200. MD5 hash `f2d0ff370380124029c2b807a924156c` verified to be MD5 of `codeastro.com`.

### AUTH-VULN-05: Weak Password Hashing (MD5, Unsalted)
- **Vulnerability Type:** Login_Flow_Logic
- **Externally Exploitable:** true
- **Source Endpoint:** `POST /index.php` (login), `POST /settings.php` (changePassword)
- **Vulnerable Code Location:** `index.php:12` — `$hashed_password = md5($password);` | `settings.php:58-59` — `if (md5($currentPassword) === $hashedPassword)` and `$hashedNewPassword = md5($newPassword);`
- **Missing Defense:** MD5 is a fast, cryptographically broken hash algorithm with no salting and no work factor. Any MD5 hash can be instantly reversed via rainbow tables or GPU-accelerated cracking. No `password_hash()` (bcrypt/Argon2) is used anywhere.
- **Exploitation Hypothesis:** An attacker who obtains the MD5 password hash from the publicly accessible database dump (`/DATABASE FILE/membershiphp.sql`) can immediately reverse it using online rainbow table lookup (e.g., crackstation.net) to recover the plaintext admin password, then log in via the normal login form.
- **Suggested Exploit_Technique:** offline_hash_cracking (rainbow table lookup against MD5 hash obtained from the public DB dump).
- **Confidence:** High
- **Notes:** Hash `f2d0ff370380124029c2b807a924156c` = MD5 of `codeastro.com` (verified). This is a trivially reversible hash. Even if the admin changes the password to a strong one, any new MD5 hash is still vulnerable to offline cracking. No password complexity policy enforced server-side.

### AUTH-VULN-06: SQL Injection Authentication Bypass
- **Vulnerability Type:** Authentication_Bypass
- **Externally Exploitable:** true
- **Source Endpoint:** `POST /index.php`
- **Vulnerable Code Location:** `index.php:6,14` — `$email = $_POST['email']` directly concatenated into `$sql = "SELECT * FROM users WHERE email = '$email' AND password = '$hashed_password'"` with no escaping, parameterization, or prepared statements.
- **Missing Defense:** No prepared statements, no `mysqli_real_escape_string()`, no input validation. Raw user input is concatenated directly into SQL.
- **Exploitation Hypothesis:** An attacker can log in as the admin without any valid credentials by submitting the SQL injection payload `' OR '1'='1' -- -` as the email value (with any password), causing the query to return all rows and bypass the credential check. Confirmed live: sending this payload results in HTTP 302 redirect to `dashboard.php` (successful login).
- **Suggested Exploit Technique:** SQL injection authentication bypass (`' OR '1'='1' -- -` as email field).
- **Confidence:** High
- **Notes:** Confirmed live. The injected condition `OR '1'='1'` causes `num_rows == 1` check to pass (first row returned). `$_SESSION['user_id']` and `$_SESSION['email']` are populated from the first user row. No prepared statements anywhere in the codebase.

### AUTH-VULN-07: No Rate Limiting on Authentication Endpoints
- **Vulnerability Type:** Abuse_Defenses_Missing
- **Externally Exploitable:** true
- **Source Endpoint:** `POST /index.php`, `POST /settings.php` (changePassword)
- **Vulnerable Code Location:** `index.php:4-29` (login handler) — no rate limiting, no lockout, no CAPTCHA. `settings.php:44-71` (changePassword handler) — same. `includes/config.php` — no session-based attempt counter. No WAF, no reverse proxy, no Apache mod_evasive.
- **Missing Defense:** No per-IP or per-account rate limiting, no exponential backoff, no account lockout, no CAPTCHA, no attempt counter, no monitoring/alerting for failed login spikes.
- **Exploitation Hypothesis:** An attacker can submit thousands of login requests per second to `POST /index.php` with different password values (or use credential stuffing with a leaked credential list) without being throttled, locked out, or challenged, enabling them to brute-force the admin password at full network speed. Confirmed live: 10 rapid failed attempts all returned HTTP 200 with no lockout or throttle.
- **Suggested Exploit Technique:** brute_force_login / credential_stuffing.
- **Confidence:** High
- **Notes:** No WAF, no reverse proxy, no application-level rate limiting anywhere. With MD5 hashing on server side and no salt, even online brute force against the login form is fast. Pairs with AUTH-VULN-05 (MD5 hashes are fast to compute).

### AUTH-VULN-08: Missing Authentication on Sensitive Endpoints
- **Vulnerability Type:** Authentication_Bypass
- **Externally Exploitable:** true
- **Source Endpoint:** `GET /print_membership_card.php`, `GET /delete_members.php`, `GET /get_membership_amount.php`
- **Vulnerable Code Location:** `print_membership_card.php` — no `isset($_SESSION['user_id'])` check anywhere in the file. `delete_members.php` — no auth check; DELETE SQL executes without authentication. `get_membership_amount.php` — no auth check.
- **Missing Defense:** The `isset($_SESSION['user_id'])` guard that protects all other endpoints is completely absent from these three files.
- **Exploitation Hypothesis:** An unauthenticated attacker can (a) enumerate all member PII by requesting `GET /print_membership_card.php?id=1`, `?id=2`, etc. without any session cookie, and (b) permanently delete any member record by requesting `GET /delete_members.php?id=1` without any authentication. Confirmed live: both endpoints returned HTTP 200/302 respectively with no session cookie.
- **Suggested Exploit_Technique:** Direct unauthenticated access to sensitive endpoints (authentication bypass by omission).
- **Confidence:** High
- **Notes:** Three distinct endpoints confirmed live. `print_membership_card.php` exposes full member PII (name, address, membership number, photo). `delete_members.php` executes cascading DELETEs against `renew` and `members` tables. `get_membership_amount.php` is lower sensitivity but also has SQLi. All confirmed accessible without `PHPSESSID` cookie.

