# Authorization Analysis Report

## 1. Executive Summary

- **Analysis Status:** Complete
- **Key Outcome:** Twelve authorization vulnerabilities were identified and documented across horizontal, vertical (N/A — single-tier), and context/workflow categories. The application's authorization model is critically deficient: three endpoints require zero authentication, and all remaining authenticated endpoints perform no ownership validation whatsoever. Every resource ID parameter is directly exploitable for IDOR. Client-controlled pricing in the renewal workflow enables financial manipulation. An open redirect via `HTTP_REFERER` facilitates post-action phishing. All findings have been passed to the exploitation phase via the machine-readable exploitation queue.
- **Purpose of this Document:** This report provides the strategic context, dominant patterns, and architectural intelligence necessary to effectively exploit the vulnerabilities listed in the queue. It is intended to be read alongside the JSON deliverable.

---

## 2. Dominant Vulnerability Patterns

### Pattern 1: Complete Absence of Authentication Guard (Horizontal — Unauthenticated)
- **Description:** Three endpoints expose sensitive operations to any unauthenticated internet visitor. No session check, no token, no IP restriction exists. The `include('includes/config.php')` only calls `session_start()` and establishes the DB connection — it performs no authorization check.
- **Implication:** Any unauthenticated internet user can read full member PII, permanently delete any member record with all associated renewal data, and query membership pricing.
- **Representative:** AUTHZ-VULN-01 (`print_membership_card.php`), AUTHZ-VULN-02 (`delete_members.php`), AUTHZ-VULN-08 (`get_membership_amount.php`)

### Pattern 2: Universal IDOR — No Ownership Binding on Any Authenticated Endpoint
- **Description:** Every authenticated endpoint that accepts an object ID parameter (`id`, `edit_id`, `membershipTypeId`) passes that ID directly to a database query with zero ownership check. The session contains only `user_id` and `email` — these are never used to filter or validate resource ownership. There is no `WHERE user_id = $_SESSION['user_id']` guard anywhere in the codebase.
- **Implication:** Any authenticated session can access, modify, or delete any member record, any membership type, and any renewal record simply by enumerating integer IDs.
- **Representative:** AUTHZ-VULN-03, AUTHZ-VULN-04, AUTHZ-VULN-05, AUTHZ-VULN-06, AUTHZ-VULN-07

### Pattern 3: Client-Controlled Business Logic Values
- **Description:** Financial amounts and state-sensitive data are calculated client-side (JavaScript) and submitted as regular POST parameters without server-side validation or recalculation. The server blindly trusts attacker-controlled values.
- **Implication:** Attacker can record arbitrary (e.g., $0.01) renewal amounts in the `renew` table, corrupting financial records.
- **Representative:** AUTHZ-VULN-05 (`renew.php` POST — `totalAmount`)

### Pattern 4: Missing Prior-State Validation in Workflows
- **Description:** Multi-step workflows do not validate that prior steps were completed correctly. The password change workflow reads `confirmPassword` but never compares it to `newPassword`. The renewal and edit workflows lack CSRF tokens and prior-state nonces, allowing any of these state-changing operations to be triggered cross-site.
- **Implication:** Password can be changed to any value without knowing the confirm string. Renewal and member edits can be CSRF-forced on an authenticated admin.
- **Representative:** AUTHZ-VULN-10, AUTHZ-VULN-11

### Pattern 5: Unvalidated Redirect Destination
- **Description:** `delete_membership.php` uses `$_SERVER['HTTP_REFERER']` as the `Location:` redirect target without any validation or allowlist check. The `Referer` header is entirely attacker-controlled.
- **Implication:** After a successful delete operation, an admin's browser can be silently redirected to an attacker-controlled domain for phishing or credential harvesting.
- **Representative:** AUTHZ-VULN-07, AUTHZ-VULN-12

---

## 3. Strategic Intelligence for Exploitation

### Session Management Architecture
- Sessions use PHP's default file-based sessions (`/tmp/sess_*`) started by bare `session_start()` in `includes/config.php:14`
- Session stores only `$_SESSION['user_id']` (integer) and `$_SESSION['email']` (string) — no role, no privilege level
- `session_regenerate_id()` is never called after login → session fixation vulnerability
- Session cookie: `PHPSESSID=...; path=/` — no `HttpOnly`, `Secure`, or `SameSite` flags enforced in code
- **Critical Finding:** The session user_id is stored but never used for ownership validation on any endpoint

### Role/Permission Model
- **No role system exists.** The `users` table schema: `id`, `email`, `password`, `registration_date`, `updated_date` — zero role column
- Single tier: unauthenticated (anon) vs. authenticated (user)
- The only guard: `if (!isset($_SESSION['user_id'])) { header("Location: index.php"); exit(); }`
- **Critical Finding:** Authentication is binary. No RBAC, no capability checks, no ownership model. Three endpoints bypass even this minimal gate.

### Resource Access Patterns
- All member resources use integer ID path parameters: `/endpoint.php?id=X`
- IDs are sequential autoincrement integers (MySQL primary keys) — trivially enumerable
- `edit_type.php` uses `edit_id` in POST body (hidden form field) — also fully attacker-controlled
- `renew.php` uses `$_GET['id']` for member selection AND `$_POST['totalAmount']` for price
- **Critical Finding:** No resource ID is ever bound to the requesting session. No `WHERE user_id = session_user` filter on any query.

### Workflow Implementation
- Multi-step workflows: GET to load form → POST to submit changes
- `renew.php`: GET loads member, POST processes renewal — `$memberId` from `$_GET['id']` is reused in POST handler (line 34, 39) without re-validation
- `edit_member.php`: POST handler uses `$memberId` from `$_GET['id']` (line 15 set in GET block, used in POST block at line 59) — the hidden `member_id` field in the form (line 116) is never read
- `settings.php` changePassword: reads `$confirmPassword` (line 48) but never compares it to `$newPassword` — only `$currentPassword` is validated
- **Critical Finding:** No CSRF tokens, no session-bound nonces, no prior-state enforcement on any workflow step.

### Credential Exposure
- Admin credentials publicly available at `GET /uploads/01%20LOGIN%20DETAILS%20%26%20PROJECT%20INFO.txt` (no auth required): `admin@mail.com` / `codeastro.com`
- Full DB dump with MD5 password hash at `GET /DATABASE%20FILE/membershiphp.sql`
- **Critical Finding:** An attacker can obtain valid credentials without any exploitation — direct credential theft from publicly accessible files.

---

## 4. Vectors Analyzed and Confirmed Secure

These authorization checks were traced and confirmed to have properly-placed guards. They are **low-priority** for further testing.

| **Endpoint** | **Guard Location** | **Defense Mechanism** | **Verdict** |
|---|---|---|---|
| `GET /logout.php` | logout.php:4-8 | Destroys session (no sensitive operation, appropriate for logout) | SAFE |
| `GET /dashboard.php` | dashboard.php:4 | `isset($_SESSION['user_id'])` before any DB query or HTML render | SAFE |
| `GET /add_members.php` | add_members.php:4 | `isset($_SESSION['user_id'])` before any processing | SAFE |
| `POST /add_members.php` | add_members.php:4 | `isset($_SESSION['user_id'])` before INSERT | SAFE (auth present; no IDOR since no existing resource) |
| `GET /view_type.php` | view_type.php:7 | Auth check present; DB query runs before check (lines 4-5) but only reads, no sensitive side effect for auth bypass | SAFE (minor: DB query before auth check wastes resources but doesn't expose data — redirect terminates before HTML render) |
| `GET /add_type.php` | add_type.php:4 | `isset($_SESSION['user_id'])` before form render | SAFE |
| `POST /add_type.php` | add_type.php:4 | `isset($_SESSION['user_id'])` before INSERT | SAFE (auth present; no IDOR) |
| `GET /list_renewal.php` | list_renewal.php:7 | Auth check present (DB query before check is resource waste only) | SAFE |
| `GET /report.php` | report.php:4 | `isset($_SESSION['user_id'])` before any processing | SAFE |
| `POST /report.php` | report.php:4 | `isset($_SESSION['user_id'])` before DB query | SAFE (auth present; reports all members — no per-member ownership check needed for this report function in a single-admin context) |
| `GET /revenue_report.php` | revenue_report.php:4 | `isset($_SESSION['user_id'])` before processing | SAFE |
| `POST /revenue_report.php` | revenue_report.php:4 | `isset($_SESSION['user_id'])` before DB query | SAFE |
| `POST /settings.php (updateSettings)` | settings.php:4 | `isset($_SESSION['user_id'])` — only authenticated users can reach; no role above "authenticated" exists | SAFE from vertical escalation (single-tier model) |
| `GET /manage_members.php` | manage_members.php:8 | Auth check present (DB query before check is resource waste only — no data returned to unauthenticated user due to redirect) | SAFE |

**Note on Vertical Analysis:** The application has a single privilege tier. There is no admin role to escalate to. All "admin" functions (settings, reports) are accessible to any authenticated session by design. Vertical privilege escalation is therefore not applicable in the traditional sense — the only vertical threat is unauthenticated → authenticated, which is covered by the unauthenticated endpoint vulnerabilities (AUTHZ-VULN-01, -02, -08).

---

## 5. Analysis Constraints and Blind Spots

- **Single-Admin Application Context:** The `users` table contains only one row by default. The IDOR vulnerabilities on authenticated endpoints (AUTHZ-VULN-03 through AUTHZ-VULN-07) are most impactful when multiple user accounts exist. However, given the SQL injection authentication bypass on `index.php`, an attacker can create or access accounts regardless.
- **No Multi-Tenant Isolation:** This application is explicitly single-organization. There is no tenant concept, so cross-tenant data leakage is not applicable.
- **CSRF Co-Factor:** All identified context vulnerabilities are amplified by the complete absence of CSRF tokens. The exploitation agent should consider CSRF as a force multiplier for AUTHZ-VULN-10 and AUTHZ-VULN-11.
- **SQL Injection Interaction:** Several IDOR vulnerabilities also contain SQL injection (the same `id` parameter). The exploitation agent may use SQLi as an alternative or amplified attack path, but the authorization flaw (missing ownership check) is the primary concern documented here.
