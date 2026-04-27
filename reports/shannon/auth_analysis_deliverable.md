# Authentication Analysis Report

## 1. Executive Summary

- **Analysis Status:** Complete
- **Key Outcome:** Seven critical-to-high authentication vulnerabilities were identified spanning every major authentication domain: SQL injection login bypass, session fixation, missing cookie security flags, transport exposure (HTTP only), no rate limiting, broken password storage (MD5, unsalted), hardcoded default credentials, and three endpoints fully unauthenticated. The application has zero effective authentication defense in depth.
- **Purpose of this Document:** This report provides the strategic context on the application's authentication mechanisms, dominant flaw patterns, and key architectural details necessary to effectively exploit the vulnerabilities listed in the exploitation queue.

---

## 2. Dominant Vulnerability Patterns

### Pattern 1: Complete Absence of Authentication Controls on Critical Endpoints

- **Description:** Three PHP files (`delete_members.php`, `print_membership_card.php`, `get_membership_amount.php`) have no session guard whatsoever. The authentication check pattern `if (!isset($_SESSION['user_id'])) { header("Location: index.php"); exit(); }` is simply absent. Any unauthenticated HTTP request is fully processed, including SQL execution and data return.
- **Implication:** Any internet-facing attacker can delete member records, access full PII membership cards, and query pricing data without any credential. The `delete_members.php` absence is particularly egregious — it was commented out in a prior version of the code (lines 1–26 are commented-out logic) and the replacement implementation at lines 30–59 omits the session guard entirely.
- **Representative Findings:** `AUTH-VULN-06`, `AUTH-VULN-07`.

### Pattern 2: SQL Injection Enabling Full Authentication Bypass

- **Description:** The login handler at `index.php` line 14 constructs a raw SQL query by directly interpolating `$_POST['email']` without sanitization, prepared statements, or parameterization. The `password` field is MD5-hashed before use, making it injection-resistant; however, the `email` field provides a complete bypass vector. Live testing confirmed that `' OR '1'='1' -- -` in the email field returns HTTP 302 redirect to dashboard, confirming full bypass.
- **Implication:** An attacker with no credentials can achieve full administrative access to the application via a single HTTP request. No account exists to target — the injection bypasses the WHERE clause entirely.
- **Representative Finding:** `AUTH-VULN-01`.

### Pattern 3: Broken Session Management

- **Description:** Three compounding session management failures exist simultaneously: (1) `session_regenerate_id()` is never called after successful login, enabling session fixation; (2) `PHPSESSID` cookie is set with no `HttpOnly`, `Secure`, or `SameSite` flags; (3) `logout.php` destroys the server-side session but never issues `setcookie(session_name(), '', time()-3600)` to clear the client-side cookie. Live testing confirmed session fixation: pre-login session ID `e6f021b2c4aae04641e5a380fc709540` remained valid post-login (no `Set-Cookie` header on the 302 response), and the same ID accessed `dashboard.php` successfully.
- **Implication:** An attacker who pre-sets a victim's PHPSESSID (via network injection on HTTP, XSS, or other means) gains persistent authenticated access that survives the victim's login. Additionally, the cookie is sniffable on the wire (HTTP-only, no Secure flag) and accessible to JavaScript (no HttpOnly flag).
- **Representative Findings:** `AUTH-VULN-03`, `AUTH-VULN-04`, `AUTH-VULN-05`.

### Pattern 4: Broken Credential Storage and Policy

- **Description:** Passwords are hashed using `md5($password)` with no salt (`index.php` line 12, `settings.php` line 59). MD5 is a general-purpose hash function, not a password hash, and is reversible via rainbow tables. The database is seeded with the default credential `admin@test.com` / `admin123` (confirmed in `init.sql` line 50). No server-side password policy exists — any length password, including single characters, is accepted. Live confirmation: `admin123` successfully authenticates.
- **Implication:** Any attacker who extracts the `users` table (via SQL injection) can immediately reverse all password hashes. The known default credential eliminates the need for cracking entirely.
- **Representative Findings:** `AUTH-VULN-02`, `AUTH-VULN-08`.

---

## 3. Strategic Intelligence for Exploitation

- **Authentication Method:** Single PHP native session cookie (`PHPSESSID`). No JWT, no token-based auth, no MFA. One user account exists in the `users` table (no registration capability).
- **Session Token Details:** `PHPSESSID` cookie, PHP default session (no configured lifetime). Observed format: 32-character hex string (PHP's default `session.hash_function` = SHA-1 or MD5 of random bytes, 128 bits effective entropy — token entropy itself is not a weakness, but the lack of flags and rotation is catastrophic).
- **Transport:** HTTP only (port 9010/80). No TLS, no HSTS. All credentials and session tokens travel in plaintext.
- **Password Storage:** MD5 (unsalted). MD5 hash of `admin123` = `0192023a7bbd73250516f069df18b500`. Fully reversible with any rainbow table or online cracker.
- **Default Credentials:** `admin@test.com` / `admin123` — seeded in `init.sql` line 50, committed to version control. Live confirmed: HTTP 302 to dashboard on POST.
- **Unauthenticated Endpoints:** `GET /delete_members.php?id=N`, `GET /print_membership_card.php?id=N`, `GET /get_membership_amount.php?membershipTypeId=N` — no session check in source code.
- **Login Bypass SQLi:** `POST /index.php` with `email=' OR '1'='1' -- -&password=anything&login=1` → HTTP 302 to dashboard. Live confirmed.
- **Session Fixation:** Pre-login session ID is reused post-login. No `session_regenerate_id()` call anywhere. Live confirmed.
- **Password Reset:** Does not exist. No forgot-password, no reset token, no email flow.
- **SSO/OAuth:** Does not exist. No external identity provider.
- **Rate Limiting:** Absent. 10 sequential failed login attempts all returned HTTP 200. No lockout, no CAPTCHA, no backoff.
- **Error Messages:** Generic — both valid and invalid email return "Invalid email or password!" (no user enumeration via error message).
- **Password Change Flaw:** `settings.php` lines 44–72 — `$confirmPassword` is read (line 48) but never compared against `$newPassword`. The new password is set to `md5($newPassword)` regardless of whether confirmation matches. This is a logic flaw but requires authenticated access to exploit.
- **Cookie Flags Observed:** `Set-Cookie: PHPSESSID=...; path=/` — no `HttpOnly`, no `Secure`, no `SameSite`.
- **Cache Headers on Auth Responses:** `Cache-Control: no-store, no-cache, must-revalidate; Pragma: no-cache` — SAFE. Auth responses are not cached.

---

## 4. Endpoint-by-Endpoint Authentication Verdict

| Endpoint | Auth Guard | Finding |
|---|---|---|
| `POST /index.php` | None (public) | SQLi login bypass; no rate limit; MD5 weak hashing |
| `GET /logout.php` | None (public) | Server-side session destroyed but client cookie NOT cleared; no CSRF protection on logout |
| `GET /dashboard.php` | `isset($_SESSION['user_id'])` | Guard correct; no issues beyond session quality |
| `GET /manage_members.php` | Guard AFTER DB query (line 8 vs line 4) | Auth-after-query: DB executes before guard; minor |
| `GET /delete_members.php` | **NO GUARD** | Unauthenticated destructive DELETE |
| `GET /print_membership_card.php` | **NO GUARD** | Unauthenticated PII disclosure |
| `GET /get_membership_amount.php` | **NO GUARD** | Unauthenticated data access |
| `GET /list_renewal.php` | Guard AFTER DB query (line 7 vs line 4) | Auth-after-query: minor |
| `GET /view_type.php` | Guard AFTER DB query (line 7 vs line 4) | Auth-after-query: minor |
| `POST /settings.php (changePassword)` | `isset($_SESSION['user_id'])` | `confirmPassword` never compared to `newPassword`; MD5 for new hash |
| All other authenticated endpoints | `isset($_SESSION['user_id'])` | Guard present and correct; no bypass |

---

## 5. Secure by Design: Validated Components

These components were analyzed and found to have defenses or characteristics that do not constitute authentication vulnerabilities.

| Component/Flow | Endpoint/File Location | Defense Mechanism Implemented | Verdict |
|---|---|---|---|
| Login error messages | `index.php` line 26 | Generic "Invalid email or password!" returned for both valid-email/wrong-password AND invalid-email cases | SAFE (no enumeration) |
| Auth response caching | All endpoints via Apache | `Cache-Control: no-store, no-cache, must-revalidate` + `Pragma: no-cache` present on all responses | SAFE |
| Server-side session destruction on logout | `logout.php` lines 4–6 | `$_SESSION = array()` then `session_destroy()` — server-side session data is cleared | SAFE (server side only; client cookie not cleared is noted separately) |
| Session token entropy | `includes/config.php` line 2 | PHP default `session_start()` generates cryptographically random 128-bit session IDs | SAFE |
| SSO / OAuth | N/A | No OAuth, OIDC, or SSO integration exists | N/A |
| Password reset tokens | N/A | No password reset feature exists | N/A |

---

## 6. Detailed Vulnerability Findings

### AUTH-VULN-01: SQL Injection Login Bypass (Authentication_Bypass)

- **Vulnerability Type:** Authentication_Bypass
- **Source Endpoint:** `POST /index.php`
- **Vulnerable Code Location:** `index.php:6,14` — `$email = $_POST['email']` flows directly into `"SELECT * FROM users WHERE email = '$email' AND password = '$hashed_password'"` with no sanitization or prepared statement.
- **Missing Defense:** No parameterized query / prepared statement. No input sanitization. Raw string interpolation of user-supplied `email` field into SQL.
- **Exploitation Hypothesis:** An attacker submitting `' OR '1'='1' -- -` as the email (any password) will cause the WHERE clause to evaluate true for all rows, returning the first user record and establishing an authenticated session without valid credentials.
- **Suggested Exploit Technique:** `sql_injection_auth_bypass`
- **Confidence:** High — Live confirmed. HTTP 302 to `dashboard.php` received with payload `email=admin%40test.com'+OR+'1'%3D'1'+--+-&password=anything`.

---

### AUTH-VULN-02: Default Hardcoded Credentials (Weak_Credentials)

- **Vulnerability Type:** Weak_Credentials
- **Source Endpoint:** `POST /index.php`
- **Vulnerable Code Location:** `init.sql:50` — `INSERT INTO users (email, password) VALUES ('admin@test.com', MD5('admin123'))` seeds the only user account with a trivially guessable password. `index.php:12` uses `md5($password)` to verify.
- **Missing Defense:** No credential rotation requirement post-deployment. No environment-specific credential generation. Default credentials committed to version control and seeded directly into production database.
- **Exploitation Hypothesis:** An attacker using `admin@test.com` / `admin123` will authenticate successfully and receive full administrative session access on first attempt.
- **Suggested Exploit Technique:** `default_credential_login`
- **Confidence:** High — Live confirmed. HTTP 302 to dashboard received with these exact credentials.

---

### AUTH-VULN-03: Session Fixation (Login_Flow_Logic)

- **Vulnerability Type:** Login_Flow_Logic
- **Source Endpoint:** `POST /index.php`
- **Vulnerable Code Location:** `index.php:17-24` — After `$result->num_rows == 1`, the code sets `$_SESSION['user_id']` and redirects. `session_regenerate_id()` is never called anywhere in the codebase (confirmed by full grep of all PHP files).
- **Missing Defense:** `session_regenerate_id(true)` is absent from the login success path. The pre-login session ID is silently promoted to authenticated status without issuance of a new ID.
- **Exploitation Hypothesis:** An attacker who can set a victim's `PHPSESSID` cookie to a known value (via network interception on HTTP, XSS, subdomain cookie injection, or social engineering) before the victim logs in will gain authenticated session access using that known ID after the victim authenticates.
- **Suggested Exploit Technique:** `session_fixation`
- **Confidence:** High — Live confirmed. Session ID `e6f021b2c4aae04641e5a380fc709540` set pre-login; no `Set-Cookie` header on login 302 response; same ID accessed `dashboard.php` returning HTTP 200.

---

### AUTH-VULN-04: Session Cookie Missing Security Flags (Session_Management_Flaw)

- **Vulnerability Type:** Session_Management_Flaw
- **Source Endpoint:** All endpoints (session-wide issue)
- **Vulnerable Code Location:** `includes/config.php:2` — `session_start()` with no `session_set_cookie_params()` configuration. No `ini_set('session.cookie_httponly', 1)`, no `ini_set('session.cookie_secure', 1)`, no `ini_set('session.cookie_samesite', 'Strict')` anywhere in codebase.
- **Missing Defense:** `HttpOnly` flag (prevents JavaScript access), `Secure` flag (prevents transmission over HTTP), `SameSite=Strict` or `Lax` (prevents cross-site request inclusion of cookie).
- **Exploitation Hypothesis:** An attacker on the same network (or exploiting any stored/reflected XSS) can steal the `PHPSESSID` cookie value via JavaScript (`document.cookie`) or network sniffing and replay it to hijack the administrative session.
- **Suggested Exploit Technique:** `session_hijacking`
- **Confidence:** High — Live observed: `Set-Cookie: PHPSESSID=...; path=/` with no additional flags. HTTP-only transport confirmed.

---

### AUTH-VULN-05: Transport Exposure — HTTP Only, No TLS/HSTS (Transport_Exposure)

- **Vulnerability Type:** Transport_Exposure
- **Source Endpoint:** All endpoints — `http://host.docker.internal:9010/`
- **Vulnerable Code Location:** `docker-compose.yml:6` — `ports: "9010:80"` with no 443 mapping; `Dockerfile` — no SSL module or certificate configuration.
- **Missing Defense:** No TLS termination. No HSTS header (`Strict-Transport-Security` absent from all responses). All credentials, session tokens, and PII travel in cleartext over HTTP.
- **Exploitation Hypothesis:** An attacker with network access between the client and server (e.g., same LAN, rogue access point, or ISP-level interception) can capture cleartext `PHPSESSID` cookie values and POST credentials from the login form, enabling full session hijacking and credential theft without any cryptographic barrier.
- **Suggested Exploit Technique:** `credential_interception` / `session_hijacking`
- **Confidence:** High — Live confirmed: no `Strict-Transport-Security` header in any response; application served exclusively on HTTP port 9010.

---

### AUTH-VULN-06: Unauthenticated Access to Destructive Endpoint (Authentication_Bypass)

- **Vulnerability Type:** Authentication_Bypass
- **Source Endpoint:** `GET /delete_members.php`
- **Vulnerable Code Location:** `delete_members.php:30-59` — `include('includes/config.php')` starts session but no `isset($_SESSION['user_id'])` check exists. The original authenticated version was commented out (lines 1–26) and the replacement lacks the guard entirely.
- **Missing Defense:** Session guard `if (!isset($_SESSION['user_id'])) { header("Location: index.php"); exit(); }` is completely absent.
- **Exploitation Hypothesis:** An unauthenticated attacker can delete any member record and all associated renewal records by sending `GET /delete_members.php?id=N` with no session cookie. Combined with SQL injection on the `id` parameter, a UNION/stacked injection could enumerate and delete all members.
- **Suggested Exploit Technique:** `unauthenticated_destructive_access`
- **Confidence:** High — Source code confirms no session guard. Live probe confirms no redirect to login (HTTP 302 to `manage_members.php` on missing `id` param, not to `index.php`).

---

### AUTH-VULN-07: Unauthenticated PII Disclosure (Authentication_Bypass)

- **Vulnerability Type:** Authentication_Bypass
- **Source Endpoint:** `GET /print_membership_card.php`
- **Vulnerable Code Location:** `print_membership_card.php:2-9` — `include('includes/config.php')` then immediately `$memberId = $_GET['id']` and SQL SELECT with JOIN, with zero session check before data access.
- **Missing Defense:** Session guard completely absent. No `isset($_SESSION['user_id'])` check.
- **Exploitation Hypothesis:** An unauthenticated attacker who requests `GET /print_membership_card.php?id=N` for any valid member ID will receive the full membership card HTML page rendering: full name, address, postcode/license number, membership type, photo, and expiry date — all without authentication.
- **Suggested Exploit Technique:** `unauthenticated_data_access`
- **Confidence:** High — Source code confirms no session guard at lines 1-9. When members exist in the database, the page renders PII without authentication.

---

### AUTH-VULN-08: Broken Password Hashing (MD5, Unsalted) (Token_Management_Issue)

- **Vulnerability Type:** Token_Management_Issue
- **Source Endpoint:** `POST /index.php` (authentication), `POST /settings.php` (password change)
- **Vulnerable Code Location:** `index.php:12` — `$hashed_password = md5($password)`; `settings.php:58-59` — `md5($currentPassword)` for verification, `md5($newPassword)` for storage. `init.sql:50` — `MD5('admin123')` for seed data.
- **Missing Defense:** Modern password hashing algorithm (bcrypt, Argon2id, or PBKDF2) with per-user salt. MD5 is a general-purpose hash function with no computational cost, fully reversible via rainbow tables.
- **Exploitation Hypothesis:** An attacker who extracts the `users.password` column via SQL injection will immediately reverse all password hashes to plaintext using freely available rainbow tables or tools like hashcat/john without any computational barrier.
- **Suggested Exploit Technique:** `offline_hash_cracking` / `rainbow_table_lookup`
- **Confidence:** High — Code directly confirms MD5 usage at `index.php:12`. MD5 hash of `admin123` = `0192023a7bbd73250516f069df18b500`.

---

### AUTH-VULN-09: No Rate Limiting on Authentication Endpoints (Abuse_Defenses_Missing)

- **Vulnerability Type:** Abuse_Defenses_Missing
- **Source Endpoint:** `POST /index.php`
- **Vulnerable Code Location:** `index.php:4-30` — Login handler executes immediately on each POST with no rate limit counter, no lockout logic, no CAPTCHA trigger, no account lockout field in `users` table schema (`init.sql:4-8`).
- **Missing Defense:** Per-IP and/or per-account rate limiting, account lockout after N failed attempts, CAPTCHA, progressive backoff. No `login_attempts`, `locked_until`, or `last_attempt` columns exist in the `users` table.
- **Exploitation Hypothesis:** An attacker can submit thousands of login attempts per minute against `POST /index.php` with different password values (brute force) or known credential lists (credential stuffing) without any throttling, lockout, or detection. The MD5 hashing (fast, cheap) means even brute-forcing directly against the login form is viable.
- **Suggested Exploit Technique:** `brute_force_login` / `credential_stuffing`
- **Confidence:** High — Live confirmed: 10 sequential failed login requests all returned HTTP 200 with no rate-limit response, no lockout indication, and no CAPTCHA.

---

### AUTH-VULN-10: Logout Does Not Clear Client-Side Cookie (Session_Management_Flaw)

- **Vulnerability Type:** Session_Management_Flaw
- **Source Endpoint:** `GET /logout.php`
- **Vulnerable Code Location:** `logout.php:4-6` — `$_SESSION = array(); session_destroy();` — server-side session is destroyed but `setcookie(session_name(), '', time()-3600)` is never called. No `Set-Cookie` header with empty/expired PHPSESSID is returned in the logout response.
- **Missing Defense:** `setcookie(session_name(), '', time()-3600, '/', '', false, true)` to expire the client-side PHPSESSID cookie on logout.
- **Exploitation Hypothesis:** After a user logs out, their browser retains the `PHPSESSID` cookie with the old value. If an attacker captures this cookie value before logout (via XSS, network sniff, or shoulder-surfing), they may attempt replay; however, since the server-side session is destroyed on logout, replayed cookies are rejected. The primary risk is in shared-computer scenarios where a subsequent user's browser may attempt to use the leftover cookie before the PHP GC collects the (already destroyed) session file — in practice, session_destroy() makes the session invalid server-side, so this is lower severity. However, the client-side cookie persisting is non-compliant with best practice.
- **Suggested Exploit Technique:** `session_replay_post_logout`
- **Confidence:** Medium — Code confirmed (no setcookie call in logout.php). Live confirmed (no Set-Cookie in logout response). Server-side destruction limits practical exploitability to edge cases.

---
