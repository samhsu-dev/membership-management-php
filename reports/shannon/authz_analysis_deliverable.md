# Authorization Analysis Report

## 1. Executive Summary

- **Analysis Status:** Complete
- **Key Outcome:** Eleven (11) high-confidence authorization vulnerabilities were identified spanning horizontal access control bypass, vertical authentication bypass, and context/workflow authorization flaws. Every endpoint identified in the recon deliverable Section 8 has been systematically analyzed and adjudicated. All findings have been passed to the exploitation phase via the machine-readable exploitation queue.
- **Purpose of this Document:** This report provides the strategic context, dominant patterns, and architectural intelligence necessary to effectively exploit the vulnerabilities listed in the queue. It is intended to be read alongside the JSON deliverable.

---

## 2. Dominant Vulnerability Patterns

### Pattern 1: Complete Absence of Authentication Guard (Vertical Bypass)
- **Description:** Three endpoints (`delete_members.php`, `print_membership_card.php`, `get_membership_amount.php`) include `includes/config.php` (which calls `session_start()`) but have **no** `if (!isset($_SESSION['user_id']))` guard whatsoever. Any HTTP request from the internet — no credentials required — directly triggers database queries and side effects.
- **Implication:** An unauthenticated attacker can delete any member record, read full member PII (name, address, license number, photo), and query pricing data without any credential.
- **Representative:** AUTHZ-VULN-01, AUTHZ-VULN-02, AUTHZ-VULN-03

### Pattern 2: Missing Ownership / Object-Level Authorization (Horizontal IDOR)
- **Description:** Every endpoint that accepts an object identifier (`id`, `membershipTypeId`, `edit_id`) fetches or mutates the object using that identifier alone, with zero validation that the requesting authenticated session is authorized to access that specific object. The application has a flat single-role model — once authenticated, a user can touch any object in the database.
- **Implication:** Any authenticated user can read, edit, delete, or renew any member record, and edit/delete any membership type, by simply varying the numeric ID parameter.
- **Representative:** AUTHZ-VULN-04, AUTHZ-VULN-05, AUTHZ-VULN-06, AUTHZ-VULN-07, AUTHZ-VULN-08

### Pattern 3: Guard Placed After Database Side Effect (Auth-After-Query)
- **Description:** Three files (`manage_members.php`, `list_renewal.php`, `view_type.php`) execute a `SELECT` query against the database at lines 4–5, and only then check the session guard at lines 7–10. An unauthenticated request causes a full database read before the `header("Location: index.php"); exit()` fires.
- **Implication:** Unauthenticated requests trigger unnecessary database queries. While the HTML output is not returned (redirect fires before rendering), this is a logic flaw and an information leakage risk under error conditions.
- **Representative:** AUTHZ-VULN-09

### Pattern 4: Missing Workflow State Validation (Context/Workflow Bypass)
- **Description:** Multi-step workflows do not validate that preceding steps were completed. `renew.php` accepts a POST with client-supplied `totalAmount` without verifying it against the server-side membership type price. `settings.php`'s password change flow reads `confirmPassword` from POST but never compares it to `newPassword` before updating the password hash.
- **Implication:** Attackers can submit renewals with arbitrary (zero or negative) payment amounts, and can change a password to a value that doesn't match the confirmation field — both bypassing intended business logic controls.
- **Representative:** AUTHZ-VULN-10, AUTHZ-VULN-11

### Pattern 5: SQL Injection Enabling Authentication Bypass (Vertical Escalation via SQLi)
- **Description:** The login handler at `index.php` interpolates `$_POST['email']` directly into a SQL query. A payload of `' OR '1'='1'-- -` in the email field bypasses the password check entirely, granting authenticated session to any attacker.
- **Implication:** An external unauthenticated attacker can obtain a fully authenticated session without any valid credentials.
- **Representative:** AUTHZ-VULN-12

---

## 3. Strategic Intelligence for Exploitation

### Session Management Architecture
- PHP native sessions stored server-side; session ID transmitted in `PHPSESSID` cookie with **no HttpOnly, no Secure, no SameSite flags**.
- The sole authorization indicator is `$_SESSION['user_id']` — its presence grants full access to all protected functions.
- **Critical Finding:** No role, permission, or ownership information is stored in the session. The session check is purely binary: present = full admin equivalent; absent = redirect to login (except for 3 unguarded endpoints).
- No `session_regenerate_id()` call after login → session fixation risk.
- `logout.php` destroys the server-side session but does NOT delete the client-side `PHPSESSID` cookie.

### Role/Permission Model
- **Only two states exist:** `anon` (no `$_SESSION['user_id']`) and `auth` (any value in `$_SESSION['user_id']`).
- The `users` table has no role column — schema: `id`, `email`, `password` only.
- **Critical Finding:** There is no RBAC, no sub-roles, no permission table. Every authenticated user is an implicit full administrator. All admin operations (member CRUD, membership type CRUD, settings, password change) are accessible to any account in the `users` table.
- Default credential seeded in `init.sql` line 50: `admin@test.com` / `admin123` (MD5: `0192023a7bbd73250516f069df18b500`).

### Resource Access Patterns
- Every resource endpoint uses numeric GET parameter `id` (or `membershipTypeId`, `edit_id`) passed directly into SQL queries.
- **Critical Finding:** No endpoint validates that the requested object belongs to or is accessible by the requesting session. There are no WHERE clauses filtering by `user_id` or any ownership column. Object IDs are sequential integers (auto-increment), trivially enumerable.
- The `members` table contains: `fullname`, `dob`, `gender`, `contact_number`, `email`, `address`, `country`, `postcode`, `occupation`, `membership_type`, `membership_number`, `expiry_date`, `photo`, `created_at`.

### Workflow Implementation
- Multi-step processes use simple GET → POST patterns. No CSRF tokens, no nonces, no state tokens.
- `renew.php`: The GET phase loads member data; the POST phase executes UPDATE+INSERT. The `totalAmount` field in POST is taken directly from the client (`$_POST['totalAmount']`) and inserted into the `renew` table — the server never validates it against the membership type's stored price.
- `settings.php` password change: `confirmPassword` is read (line 48) but the code path goes directly to `md5($currentPassword) === $hashedPassword` check and then `md5($newPassword)` update (lines 58–60) — `$confirmPassword` is never referenced in any conditional logic.
- **Critical Finding:** Both workflow guards rely entirely on client-supplied values without server-side re-validation.

### File Upload Architecture
- `settings.php` uses `$_FILES['logo']['name']` verbatim as the upload destination: `$targetPath = 'uploads/' . $logoName` (line 19). No extension check, no MIME validation, no filename sanitization.
- `uploads/` directory is web-accessible with no `.htaccess` restriction; PHP files placed there are executable by Apache.
- **Critical Finding:** Uploading a file named `shell.php` places an executable PHP webshell at `http://host.docker.internal:9010/uploads/shell.php`.

### Unauthenticated Endpoint Details
- `delete_members.php` line 30: `include('includes/config.php')` — then immediately processes `$_GET['id']` into DELETE queries with zero session check. The commented-out code block at lines 1–28 shows a prior version existed but the guard was never re-added to the live code.
- `print_membership_card.php` line 4: `$memberId = $_GET['id']` — no `isset()` check, no session check; directly interpolated into SELECT JOIN query at line 5.
- `get_membership_amount.php` line 9: `if (isset($_GET['membershipTypeId']))` — the only condition; no session guard anywhere in the file.

---

## 4. Detailed Findings: Exploitation Queue

### AUTHZ-VULN-01: Unauthenticated Member Deletion (Vertical Bypass)
**Verdict: VULNERABLE**

- **File:** `delete_members.php` lines 30–59
- **Analysis:** `include('includes/config.php')` at line 30 starts the session but no `isset($_SESSION['user_id'])` guard follows. Lines 32–57 directly process `$_GET['id']` into DELETE queries against `renew` and `members` tables. Any unauthenticated HTTP GET request to `/delete_members.php?id=N` triggers full deletion of the member record and all associated renewal records.
- **Side Effect:** Permanent deletion of any member record and associated renewals from the database.
- **Confidence:** High — guard is completely absent, side effect is unconditional.

### AUTHZ-VULN-02: Unauthenticated Member PII Disclosure (Vertical Bypass)
**Verdict: VULNERABLE**

- **File:** `print_membership_card.php` lines 1–30
- **Analysis:** No session guard exists anywhere in the file. Line 4 reads `$_GET['id']` without even an `isset()` check. Lines 5–8 execute a SELECT JOIN query returning full member PII (name, address, license number, membership type, photo). The rendered HTML page displays all this data in a printable membership card format.
- **Side Effect:** Full member PII disclosure (name, DOB, address, license number, membership number, photo, membership status) to any unauthenticated internet attacker.
- **Confidence:** High — guard is completely absent, output is unambiguous PII.

### AUTHZ-VULN-03: Unauthenticated Membership Pricing Data Access (Vertical Bypass)
**Verdict: VULNERABLE**

- **File:** `get_membership_amount.php` lines 1–31
- **Analysis:** No session guard anywhere in the file. Line 9 checks only for the presence of `$_GET['membershipTypeId']`; if present, the value is interpolated into a SELECT query at line 14 and the `amount` field is returned as JSON. No authentication required.
- **Side Effect:** Read access to membership pricing data by unauthenticated callers; also provides an unauthenticated SQL injection entry point (the `membershipTypeId` parameter is directly interpolated with no sanitization).
- **Confidence:** High — guard absent, SQL injection also present on this unauthenticated endpoint.

### AUTHZ-VULN-04: Unauthenticated Member PII Read via memberProfile (Horizontal — clarified: Vertical context, any member accessible)
**Verdict: VULNERABLE**

- **File:** `memberProfile.php` lines 4–16
- **Analysis:** Session guard is correctly placed at lines 4–7 (`if (!isset($_SESSION['user_id']))`), so authentication IS required. However, there is no ownership check. Any authenticated user can supply any member `id` in the GET parameter and retrieve full profile data for that member. Since the `members` table stores data for all members, and there is no `user_id` linkage between `users` and `members`, ANY member ID is accessible to any authenticated session.
- **Side Effect:** Read of any member's full PII by any authenticated session — name, DOB, gender, contact, email, address, country, postcode, occupation, membership type, license number, photo.
- **Confidence:** High — no ownership check, authentication is the only barrier.

### AUTHZ-VULN-05: Any Member Edit Without Ownership Check (Horizontal IDOR)
**Verdict: VULNERABLE**

- **File:** `edit_member.php` lines 4–70
- **Analysis:** Session guard at lines 4–7 is correct. Line 15 reads `$memberId = $_GET['id']` and uses it in a SELECT at line 17. Line 59 uses `$memberId` in an UPDATE query with all POST-supplied fields. No ownership check exists between the session user and the target member. An authenticated user can supply any member's `id` in the GET parameter and overwrite that member's entire record (name, DOB, gender, contact, email, address, country, postcode, occupation) and upload a photo.
- **Side Effect:** Overwrite (mutate) any member's PII; also enables file upload for any member record (photo field), which can be used to place PHP files given the unrestricted upload mechanism.
- **Confidence:** High — no ownership check, `$memberId` flows directly from `$_GET['id']` to UPDATE WHERE clause.

### AUTHZ-VULN-06: Any Member Renewal With Tampered Amount (Horizontal IDOR + Context)
**Verdict: VULNERABLE**

- **File:** `renew.php` lines 4–48
- **Analysis:** Session guard at lines 4–7 is correct. Line 15 reads `$memberId = $_GET['id']` and uses it in a SELECT at line 17 (GET phase). In the POST phase (line 28), `$memberId` is used in UPDATE (line 34) and INSERT (line 39) queries. There is no check that the authenticated user is authorized to renew THIS specific member. Additionally, line 37 reads `$totalAmount = $_POST['totalAmount']` and inserts it directly into the `renew` table — the server never validates this amount against the membership type's stored price in the database.
- **Side Effect:** (1) Renew any member's membership without authorization; (2) Insert any arbitrary `total_amount` value (including 0, negative, or inflated) into the `renew` financial table, corrupting the revenue audit trail.
- **Confidence:** High — no ownership check AND no server-side price validation.

### AUTHZ-VULN-07: Any Membership Type Edit Without Authorization (Horizontal IDOR)
**Verdict: VULNERABLE**

- **File:** `edit_type.php` lines 4–31
- **Analysis:** Session guard at lines 4–7 is correct. Line 15 reads `$id = $_POST['edit_id']` (POST phase) and uses it directly in an UPDATE query at line 17: `UPDATE membership_types SET type = '$membershipType', amount = $membershipAmount WHERE id = $id`. No ownership check exists. Any authenticated user can modify any membership type's name and price.
- **Side Effect:** Modify any membership type's name and price, affecting all members enrolled in that type and all future renewals.
- **Confidence:** High — no ownership check, direct UPDATE on attacker-supplied ID.

### AUTHZ-VULN-08: Any Membership Type Deletion Without Authorization (Horizontal IDOR)
**Verdict: VULNERABLE**

- **File:** `delete_membership.php` lines 4–25
- **Analysis:** Session guard at lines 4–7 is correct. Line 10 reads `$delete_id = $_GET['id'] ?? null` and line 12 executes `DELETE FROM membership_types WHERE id = $delete_id`. No ownership check exists. Any authenticated user can delete any membership type by supplying its ID.
- **Side Effect:** Delete any membership type, potentially causing foreign key violations or data corruption for members enrolled in that type.
- **Confidence:** High — no ownership check, direct DELETE on attacker-supplied ID.

### AUTHZ-VULN-09: Database Query Executes Before Session Guard (Guard-After-Query Flaw)
**Verdict: VULNERABLE**

- **Files:**
  - `manage_members.php` — query at line 4, guard at lines 8–11
  - `list_renewal.php` — query at line 4, guard at lines 7–10
  - `view_type.php` — query at line 4, guard at lines 7–10
- **Analysis:** In all three files, `include('includes/config.php')` is at line 2, then a `SELECT *` query executes at line 4, fetching all rows from `members`, `members`, and `membership_types` respectively. Only after the query completes does the session guard check fire. While the HTML output is blocked (redirect fires before rendering), the database read side effect (query execution, potential error output) occurs before authentication is verified.
- **Side Effect:** Unauthenticated requests cause full table scans on `members` and `membership_types` tables. Under error conditions (`$conn->error`), error messages may be returned to unauthenticated callers.
- **Confidence:** High — code order is unambiguous; query precedes guard on every code path.

### AUTHZ-VULN-10: Client-Controlled Renewal Amount Bypasses Price Validation (Context/Workflow)
**Verdict: VULNERABLE**

- **File:** `renew.php` lines 37–40
- **Analysis:** The renewal workflow is designed so the client loads the membership type price via `get_membership_amount.php` (AJAX) and populates the `totalAmount` field in the form. When the POST is submitted, line 37 reads `$totalAmount = $_POST['totalAmount']` and line 39 inserts it verbatim into the `renew` table: `INSERT INTO renew (member_id, total_amount, renew_date) VALUES ($memberId, $totalAmount, '$renewDate')`. The server performs no lookup of the membership type's price from the database to validate that `totalAmount` matches the expected value.
- **Side Effect:** Insert any arbitrary financial amount (e.g., 0, 1, negative) into the `renew` table, allowing membership renewal at zero or reduced cost, and corrupting all revenue reports generated from this table.
- **Confidence:** High — `$_POST['totalAmount']` flows directly to INSERT with zero server-side validation.

### AUTHZ-VULN-11: Password Confirmation Field Never Validated (Context/Workflow)
**Verdict: VULNERABLE**

- **File:** `settings.php` lines 44–72
- **Analysis:** The password change handler reads `$currentPassword`, `$newPassword`, and `$confirmPassword` from POST (lines 46–48). The code then validates `$currentPassword` against the stored hash (line 58). If it matches, it immediately hashes `$newPassword` and updates the `users` table (lines 59–60). **`$confirmPassword` is read but never compared to `$newPassword` in any conditional statement.** The password is changed to whatever value is in `$newPassword` regardless of whether `$confirmPassword` matches, defeating the confirmation requirement entirely.
- **Side Effect:** Change the admin password to a value that differs from the confirmation field — a minor business logic bypass. More critically, this could be exploited as part of an account takeover workflow where a typo in the new password is silently accepted.
- **Confidence:** High — `$confirmPassword` variable is set but never referenced in the conditional logic; code path to UPDATE is clear.

### AUTHZ-VULN-12: SQL Injection Authentication Bypass on Login (Vertical Escalation)
**Verdict: VULNERABLE**

- **File:** `index.php` lines 6, 12, 14–17
- **Analysis:** Line 6 reads `$email = $_POST['email']`. Line 12 hashes the password with MD5. Line 14 executes: `SELECT * FROM users WHERE email = '$email' AND password = '$hashed_password'`. The `$email` field is interpolated directly with no sanitization. A payload of `' OR '1'='1'-- -` in the email field causes the query to become `SELECT * FROM users WHERE email = '' OR '1'='1'-- - AND password = '...'`, which returns all rows. Since `$result->num_rows == 1` is checked (not `> 0`), the payload must return exactly one row — but with only one user in the `users` table, this evaluates to true and grants a session.
- **Side Effect:** Obtain a fully authenticated session without valid credentials, gaining complete access to all 16 protected application endpoints.
- **Confidence:** High — SQL injection in login form is a textbook vulnerability; single-user database makes `num_rows == 1` trivially satisfiable.

---

## 5. Vectors Analyzed and Confirmed Secure

| **Endpoint** | **Guard Location** | **Defense Mechanism** | **Verdict** |
|---|---|---|---|
| `POST /index.php` (session check for already-logged-in) | `index.php` lines 4–30 | No redirect-if-logged-in but this is the login page itself — acceptable | SAFE (login page, auth bypass covered separately as AUTHZ-VULN-12) |
| `GET /logout.php` | `logout.php` lines 1–10 | No auth required; session destruction is intentionally public | SAFE by design |
| `GET /dashboard.php` | `dashboard.php` lines 4–7 | `if (!isset($_SESSION['user_id']))` guard precedes all DB queries | SAFE (auth guard correct; no object IDs) |
| `GET /add_members.php` | `add_members.php` lines 4–7 | `if (!isset($_SESSION['user_id']))` guard precedes all side effects | SAFE (auth guard correct; no ID parameter — creates new record) |
| `GET,POST /add_type.php` | `add_type.php` lines 4–7 | `if (!isset($_SESSION['user_id']))` guard precedes all side effects | SAFE (auth guard correct; no ID parameter) |
| `POST /report.php` | `report.php` lines 4–7 | `if (!isset($_SESSION['user_id']))` guard precedes all side effects | SAFE (auth guard correct; no object IDs — date range query only) |
| `POST /revenue_report.php` | `revenue_report.php` lines 4–7 | `if (!isset($_SESSION['user_id']))` guard precedes all side effects | SAFE (auth guard correct; no object IDs — date range query only) |
| `GET /includes/config.php` | N/A | PHP executes silently, returns no output; credentials not disclosed via HTTP | SAFE (PHP execution hides source; no output) |

**Note on ownership checks:** Since this application has only one authenticated user account and no multi-tenant separation, "ownership" in the traditional sense does not apply to authenticated operations (all members are "owned" by the single admin). The IDOR findings above are still valid because they demonstrate that the authorization model has zero object-level access control — relevant if additional user accounts are added or if the single-user constraint is not maintained.

---

## 6. Analysis Constraints and Blind Spots

- **Single-User Application:** The application has only one user account (`admin@test.com`). There is no multi-user scenario to test for horizontal privilege escalation between different user accounts. All "horizontal" findings are against the member data objects (PII), not between competing user accounts.
- **No RBAC to Analyze:** With no roles in the `users` table, there is no vertical escalation path between different privilege levels within the authenticated domain. The vertical boundary is entirely between `anon` and `auth`.
- **Static Analysis Only:** This analysis is based on source code review only. Runtime behavior (e.g., PHP error suppression settings, actual Apache configuration) was not verified against the live instance. The findings are based on what the code as written will execute.
- **SQL Injection as Authorization Bypass:** Several SQL injection vectors can also serve as authorization bypass mechanisms (e.g., using SQLi to access or delete data beyond what the URL `id` parameter would normally reach). These are documented here as authorization findings where the SQLi enables bypass; the full SQLi exploitation depth is a separate concern.
- **File Upload RCE as Post-Auth Escalation:** The unrestricted file upload in `settings.php` and `add_members.php`/`edit_member.php` can lead to Remote Code Execution. These are included as context/workflow findings where the authorization model fails to restrict what an authenticated user can do (no file type restriction is an authorization-adjacent control failure).



