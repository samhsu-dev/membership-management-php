# Reconnaissance Deliverable: EHTDA Membership Management System

## 0) HOW TO READ THIS
This reconnaissance report provides a comprehensive map of the application's attack surface, with special emphasis on authorization and privilege escalation opportunities for the Authorization Analysis Specialist.

**Key Sections for Authorization Analysis:**
- **Section 4 (API Endpoint Inventory):** Contains authorization details for each endpoint — focus on "Required Role" and "Object ID Parameters" columns to identify IDOR candidates.
- **Section 6.4 (Guards Directory):** Catalog of authorization controls — understand what each guard means before analyzing vulnerabilities.
- **Section 7 (Role & Privilege Architecture):** Complete role hierarchy and privilege mapping — use this to understand the privilege lattice and identify escalation targets.
- **Section 8 (Authorization Vulnerability Candidates):** Pre-prioritized lists of endpoints for horizontal, vertical, and context-based authorization testing.

**How to Use the Network Mapping (Section 6):** The entity/flow mapping shows system boundaries and data sensitivity levels. Pay special attention to flows marked with authorization guards and entities handling PII/sensitive data.

**Priority Order for Testing:** Start with Section 8's High-priority unauthenticated access candidates, then horizontal IDOR-style candidates, then vertical escalation (all authenticated users share a single flat role — there is no vertical escalation by role, but unauthenticated-vs-authenticated is the primary boundary), then context-based workflow bypasses.

---

## 1. Executive Summary

The EHTDA Membership Management System is a membership administration portal built for the Ethiopian Heavy Truck Drivers Association (EHTDA). Its core purpose is tracking member records, membership types, renewal histories, and generating financial and membership reports.

**Technology Stack:** Raw PHP 8.1 with no framework, Apache web server, MySQL 8.0 database, AdminLTE 3 Bootstrap UI template with jQuery DataTables. No Composer dependencies. No framework routing layer.

**Architecture:** 19 standalone PHP files directly accessible at the document root. No front controller. Every `.php` file is independently reachable by direct HTTP request. One `includes/` subdirectory contains a shared `config.php` that initializes the MySQL connection and starts the PHP session.

**Primary Attack Surface Components:**
- Login page (`index.php`) — single authentication entry point
- Member management CRUD (`add_members.php`, `edit_member.php`, `delete_members.php`, `manage_members.php`, `memberProfile.php`)
- Membership card printing (`print_membership_card.php`) — **unauthenticated**
- Membership type management (`add_type.php`, `edit_type.php`, `delete_membership.php`, `view_type.php`)
- Renewal management (`renew.php`, `list_renewal.php`, `get_membership_amount.php`) — the last is **unauthenticated**
- Reporting (`report.php`, `revenue_report.php`)
- Settings/file upload (`settings.php`)

**Critical Security Posture:** The application is critically deficient in every security domain. There are no prepared statements, no output encoding, no CSRF tokens, no file upload validation, MD5 password hashing, three endpoints with no authentication guard, and a flat single-role authorization model with no RBAC.

---

## 2. Technology & Service Map

- **Frontend:** Inline PHP/HTML template rendering; AdminLTE 3 (Bootstrap 4-based admin template); jQuery; DataTables plugin; Ionic Framework icons (CDN); Google Fonts (CDN). No JavaScript framework. No build system.
- **Backend:** PHP 8.1, procedural style, `mysqli` extension exclusively (no PDO, no ORM). Raw string-interpolated SQL queries throughout. No third-party PHP libraries (no Composer).
- **Infrastructure:** Apache httpd (mod_rewrite enabled), Docker container, MySQL 8.0. Application connects to MySQL as `root` with password `rootpass`. HTTP only (port 80); no TLS.
- **Identified Subdomains:** None. Application runs on a single host (`host.docker.internal`) with no subdomains identified.
- **Open Ports & Services:**
  - `TCP 9010` — Apache/PHP 8.1 (the primary application, mapped from container port 80)
  - `TCP 3306` — MySQL 8.0 (internal to Docker network, not externally exposed per docker-compose.yml; app connects as `root`/`rootpass`)

---

## 3. Authentication & Session Management Flow

- **Entry Points:**
  - `POST /index.php` — sole login form; no registration, no SSO, no password reset, no OAuth
  - `GET /logout.php` — session destruction

- **Mechanism (Step-by-Step):**
  1. User submits `email` and `password` fields via POST to `index.php`
  2. Server computes `md5($password)` (line 12 of `index.php`) — no salt, broken algorithm
  3. Server executes: `SELECT * FROM users WHERE email = '$email' AND password = '$hashed_password'` (line 14) — both fields raw-interpolated (SQL injection vector)
  4. If `num_rows == 1`, server sets `$_SESSION['user_id'] = $row['id']` and `$_SESSION['email'] = $row['email']` (lines 20–21)
  5. Server redirects to `dashboard.php` via `header("Location: dashboard.php")` (line 23)
  6. PHP native sessions via `PHPSESSID` cookie. Cookie flags: **no HttpOnly**, **no Secure**, **no SameSite**. No `session_regenerate_id()` call after login (session fixation risk).
  7. `logout.php` calls `session_destroy()` and `$_SESSION = array()` but does NOT delete the client-side `PHPSESSID` cookie.

- **Session Cookie Observed (Live):** `PHPSESSID=<hex>` (domain: host.docker.internal, path: /, no security flags)

- **Code Pointers:**
  - Login handler: `/repos/MembershipManagementSystemPHP/index.php` lines 4–30
  - Logout handler: `/repos/MembershipManagementSystemPHP/logout.php` lines 1–10
  - Session start: `/repos/MembershipManagementSystemPHP/includes/config.php` line 2 (`session_start()`)

- **Default Credentials (from `init.sql` line 50):** `admin@test.com` / `admin123`

### 3.1 Role Assignment Process

- **Role Determination:** No roles exist. After login, only `$_SESSION['user_id']` and `$_SESSION['email']` are set. There is no role column in the `users` table and no role stored in the session.
- **Default Role:** The `users` table schema (from `init.sql` lines 4–8) contains only `id`, `email`, `password`. All authenticated users are implicitly system administrators with full access to all functions.
- **Role Upgrade Path:** Not applicable — no role hierarchy exists.
- **Code Implementation:** `/repos/MembershipManagementSystemPHP/index.php` lines 20–21; `/repos/MembershipManagementSystemPHP/init.sql` lines 4–8 (table definition)

### 3.2 Privilege Storage & Validation

- **Storage Location:** PHP native server-side session. `$_SESSION['user_id']` is the only privilege indicator — its mere presence grants full application access.
- **Validation Points:** Guard is `if (!isset($_SESSION['user_id'])) { header("Location: index.php"); exit(); }`. Present in 16 of 19 files. **Absent in `delete_members.php`, `print_membership_card.php`, and `get_membership_amount.php`.**
- **Cache/Session Persistence:** PHP default session lifetime (until browser close or server-side expiry). No explicit `session.gc_maxlifetime` override observed.
- **Code Pointers:** Guard pattern at lines 4–7 of most protected files; `/repos/MembershipManagementSystemPHP/includes/config.php` line 2

### 3.3 Role Switching & Impersonation

- **Impersonation Features:** None.
- **Role Switching:** None. No sudo mode, no temporary elevation.
- **Audit Trail:** No security event logging anywhere in the application. No login attempt logging. DB errors echoed to browser rather than logged server-side.
- **Code Implementation:** Not applicable.

---

## 4. API Endpoint Inventory

**Network Surface Focus:** Only network-accessible endpoints served by the Apache/PHP application on port 9010. All 19 PHP files are directly reachable at the document root.

| Method | Endpoint Path | Required Role | Object ID Parameters | Authorization Mechanism | Description & Code Pointer |
|---|---|---|---|---|---|
| GET, POST | `/index.php` | anon | None | None | Login form. SQL injection on `email`. See `index.php` lines 4–30. |
| GET | `/logout.php` | anon | None | None | Session destruction. No CSRF protection. See `logout.php`. |
| GET | `/dashboard.php` | auth | None | `isset($_SESSION['user_id'])` at lines 4–7 | Dashboard with statistics. See `dashboard.php`. |
| GET | `/manage_members.php` | auth | None | `isset($_SESSION['user_id'])` at lines 8–11 (after DB query at line 4) | Member list table. Stored XSS output. See `manage_members.php`. |
| GET, POST | `/add_members.php` | auth | None | `isset($_SESSION['user_id'])` at lines 4–7 | Add member form. SQL injection on all POST fields + file upload RCE. See `add_members.php` lines 23–50. |
| GET, POST | `/edit_member.php` | auth | `id` (GET) | `isset($_SESSION['user_id'])` at lines 4–7 | Edit member by ID. SQL injection on `$_GET['id']` + all POST fields. No ownership check. See `edit_member.php` lines 14–61. |
| GET | `/delete_members.php` | **NONE** | `id` (GET) | **NO SESSION GUARD** | Deletes member and renewals. Unauthenticated DELETE. SQL injection on `$_GET['id']`. See `delete_members.php` lines 33–48. |
| GET | `/memberProfile.php` | auth | `id` (GET) | `isset($_SESSION['user_id'])` at lines 4–7 | View member profile. SQL injection on `$_GET['id']`. No ownership check. See `memberProfile.php` lines 10–16. |
| GET | `/print_membership_card.php` | **NONE** | `id` (GET) | **NO SESSION GUARD** | Renders full membership card with PII. Unauthenticated. SQL injection on `$_GET['id']` (no isset check). See `print_membership_card.php` lines 4–9. |
| GET, POST | `/renew.php` | auth | `id` (GET) | `isset($_SESSION['user_id'])` at lines 4–7 | Renew membership. SQL injection on `$_GET['id']`, `$_POST['membershipType']`, `$_POST['totalAmount']`. Amount tampered client-side. See `renew.php` lines 15–40. |
| GET | `/list_renewal.php` | auth | None | `isset($_SESSION['user_id'])` at lines 7–10 (after DB query at line 4) | Renewal list. Stored XSS. See `list_renewal.php`. |
| GET | `/get_membership_amount.php` | **NONE** | `membershipTypeId` (GET) | **NO SESSION GUARD** | JSON AJAX endpoint. Returns membership amount. SQL injection on `$_GET['membershipTypeId']`. See `get_membership_amount.php` lines 10–15. |
| GET | `/view_type.php` | auth | None | `isset($_SESSION['user_id'])` at lines 7–10 (after DB query at line 4) | Membership types list. Stored XSS. See `view_type.php`. |
| GET, POST | `/add_type.php` | auth | None | `isset($_SESSION['user_id'])` at lines 4–7 | Add membership type. SQL injection on `$_POST['membershipType']`, `$_POST['membershipAmount']`. See `add_type.php` lines 12–15. |
| GET, POST | `/edit_type.php` | auth | `id` (GET), `edit_id` (POST) | `isset($_SESSION['user_id'])` at lines 4–7 | Edit membership type. SQL injection on GET `id` and all POST fields. No ownership check. See `edit_type.php` lines 12–29. |
| GET | `/delete_membership.php` | auth | `id` (GET) | `isset($_SESSION['user_id'])` at lines 4–7 | Delete membership type. SQL injection on `$_GET['id']`. Open redirect via `HTTP_REFERER`. See `delete_membership.php` lines 10–22. |
| POST | `/report.php` | auth | None | `isset($_SESSION['user_id'])` at lines 4–7 | Date-range member report. SQL injection on `$_POST['fromDate']`, `$_POST['toDate']`. See `report.php` lines 10–17. |
| POST | `/revenue_report.php` | auth | None | `isset($_SESSION['user_id'])` at lines 4–7 | Date-range revenue report. SQL injection on `$_POST['fromDate']`, `$_POST['toDate']`. See `revenue_report.php` lines 10–18. |
| GET, POST | `/settings.php` | auth | None | `isset($_SESSION['user_id'])` at lines 4–7 | System settings + password change. SQL injection on `$_POST['systemName']`, `$_POST['currency']`. Unrestricted file upload (verbatim filename) to `uploads/`. See `settings.php` lines 10–35. |
| GET | `/includes/config.php` | anon | None | None | Shared DB init file. Web-accessible but PHP executes silently (outputs nothing). Contains DB credentials. See `includes/config.php`. |

---

## 5. Potential Input Vectors for Vulnerability Analysis

**Network Surface Focus:** All vectors below are reachable via HTTP to `http://host.docker.internal:9010/`.

### URL Parameters (GET)
- `index.php` — No GET parameters
- `edit_member.php?id=` — Member record identifier (integer). File: `edit_member.php` line 15. Flows into SELECT and UPDATE queries.
- `delete_members.php?id=` — Member ID to delete (no auth). File: `delete_members.php` line 33. Flows into DELETE query.
- `memberProfile.php?id=` — Member profile ID. File: `memberProfile.php` line 10. Flows into SELECT query.
- `print_membership_card.php?id=` — Member card ID (no auth, no isset check). File: `print_membership_card.php` line 4. Flows into SELECT query.
- `renew.php?id=` — Member ID for renewal. File: `renew.php` line 15. Flows into SELECT and DML queries.
- `get_membership_amount.php?membershipTypeId=` — Membership type ID (no auth). File: `get_membership_amount.php` line 10. Flows into SELECT query.
- `edit_type.php?id=` — Membership type ID. File: `edit_type.php` line 27. Flows into SELECT query.
- `delete_membership.php?id=` — Membership type ID to delete. File: `delete_membership.php` line 10. Flows into DELETE query.

### POST Body Fields
- `index.php` — `email` (line 6, flows into SQL query, primary SQLi vector), `password` (line 7, MD5-hashed before query)
- `add_members.php` — `fullname` (line 23), `dob` (line 24), `gender` (line 25), `contactNumber` (line 26), `email` (line 27), `address` (line 28), `country` (line 29), `postcode` (line 30), `occupation` (line 31), `membershipType` (line 32) — all flow raw into INSERT query at lines 45–48
- `edit_member.php` — `fullname` (line 37), `dob` (line 38), `gender` (line 39), `contactNumber` (line 40), `email` (line 41), `address` (line 42), `country` (line 43), `postcode` (line 44), `occupation` (line 45) — all flow raw into UPDATE query at lines 56–59
- `renew.php` — `membershipType` (line 29), `extend` (line 30), `totalAmount` (line 37) — `totalAmount` is client-controlled amount in INSERT; `membershipType` unquoted in UPDATE
- `add_type.php` — `membershipType` (line 12), `membershipAmount` (line 13) — both flow into INSERT at line 15
- `edit_type.php` — `membershipType` (line 12), `membershipAmount` (line 13), `edit_id` (line 15) — all flow raw into UPDATE at line 17
- `report.php` — `fromDate` (line 10), `toDate` (line 11) — both interpolated into BETWEEN clause at line 16
- `revenue_report.php` — `fromDate` (line 10), `toDate` (line 11) — both interpolated into BETWEEN clause at line 17
- `settings.php` — `systemName` (line 10), `currency` (line 11) — raw in UPDATE at lines 21/33; `currentPassword` (line 46), `newPassword` (line 47), `confirmPassword` (line 48) — password change (confirmPassword never validated against newPassword)

### File Upload Inputs
- `add_members.php` — `$_FILES['photo']` (line 37): extension extracted from `$_FILES['photo']['name']` via `pathinfo()` and preserved in destination filename. Upload path: `uploads/member_photos/`. File: `add_members.php` lines 36–40.
- `edit_member.php` — `$_FILES['photo']` (line 48): original basename + extension preserved in destination filename. Upload path: `uploads/member_photos/`. File: `edit_member.php` lines 48–52.
- `settings.php` — `$_FILES['logo']` (line 13): **entire raw filename used verbatim** as destination (`uploads/<filename>`). No sanitization whatsoever. File: `settings.php` lines 14, 19–20. **Highest severity upload vector.**

### HTTP Headers
- `$_SERVER['HTTP_REFERER']` — Used as redirect target in `delete_membership.php` lines 15 and 22. Fully attacker-controlled. Open redirect vector. Potentially usable for SSRF if any internal redirect validation were added.

### Cookie Values
- `PHPSESSID` — PHP session identifier. No `HttpOnly`, `Secure`, or `SameSite` flags. Susceptible to XSS-based theft and network sniffing. No session fixation protection.

---

## 6. Network & Interaction Map

### 6.1 Entities

| Title | Type | Zone | Tech | Data | Notes |
|---|---|---|---|---|---|
| UserBrowser | Identity | Internet | Any browser | Public | External user/attacker interacting with the application |
| EHTDA-WebApp | Service | App | Apache/PHP 8.1 | PII, Tokens, Secrets | Main application backend; all 19 PHP files; runs on port 9010 |
| MySQL-DB | DataStore | Data | MySQL 8.0 | PII, Tokens, Secrets | Stores members, users, renewals, settings; app connects as root/rootpass |
| uploads-dir | ExternAsset | App | Filesystem/Apache | PII | Web-accessible directory for uploaded files (photos, logos); path traversal risk |
| includes-dir | ExternAsset | App | Filesystem/Apache | Secrets | Contains config.php with DB credentials; web-accessible but PHP execution hides plaintext |
| Ionic-CDN | ThirdParty | ThirdParty | CDN | Public | Ionic framework icons loaded from external CDN |
| GoogleFonts-CDN | ThirdParty | ThirdParty | CDN | Public | Google Fonts loaded from external CDN |

### 6.2 Entity Metadata

| Title | Metadata Key: Value |
|---|---|
| EHTDA-WebApp | Host: `http://host.docker.internal:9010`; Files: 19 PHP files at docroot; Auth: PHP Session (PHPSESSID); DB: MySQL via mysqli as root; Session: `session_start()` in `includes/config.php` line 2; TLS: None (HTTP only) |
| MySQL-DB | Engine: `MySQL 8.0`; Exposure: Internal Docker network only; Credentials: `root`/`rootpass` (hardcoded in docker-compose.yml and includes/config.php fallback); Tables: `users`, `members`, `membership_types`, `renew`, `settings`; Port: 3306 |
| uploads-dir | Path: `uploads/` (relative to docroot); Subdirs: `member_photos/`; Served by Apache; No `.htaccess` restriction; PHP files uploaded here are executable |
| includes-dir | Path: `includes/` (relative to docroot); Files: `config.php` (+ missing partial templates); No `deny from all`; config.php web-accessible (PHP executes, outputs nothing but errors if DB fails) |

### 6.3 Flows

| FROM → TO | Channel | Path/Port | Guards | Touches |
|---|---|---|---|---|
| UserBrowser → EHTDA-WebApp | HTTP | `:9010 /index.php` | None | Public (email, password) |
| UserBrowser → EHTDA-WebApp | HTTP | `:9010 /logout.php` | None | Tokens (session destruction) |
| UserBrowser → EHTDA-WebApp | HTTP | `:9010 /dashboard.php` | auth:user | PII (member counts, names) |
| UserBrowser → EHTDA-WebApp | HTTP | `:9010 /manage_members.php` | auth:user | PII (member list) |
| UserBrowser → EHTDA-WebApp | HTTP | `:9010 /add_members.php` | auth:user | PII (new member data), file upload |
| UserBrowser → EHTDA-WebApp | HTTP | `:9010 /edit_member.php?id=N` | auth:user | PII (member data), file upload |
| UserBrowser → EHTDA-WebApp | HTTP | `:9010 /delete_members.php?id=N` | **None** | PII (deletion of member record) |
| UserBrowser → EHTDA-WebApp | HTTP | `:9010 /memberProfile.php?id=N` | auth:user | PII (full member profile) |
| UserBrowser → EHTDA-WebApp | HTTP | `:9010 /print_membership_card.php?id=N` | **None** | PII (full card: name, address, license, photo) |
| UserBrowser → EHTDA-WebApp | HTTP | `:9010 /renew.php?id=N` | auth:user | PII, Payments (renewal amount) |
| UserBrowser → EHTDA-WebApp | HTTP | `:9010 /list_renewal.php` | auth:user | PII (renewal list) |
| UserBrowser → EHTDA-WebApp | HTTP | `:9010 /get_membership_amount.php?membershipTypeId=N` | **None** | Public (pricing data) |
| UserBrowser → EHTDA-WebApp | HTTP | `:9010 /view_type.php` | auth:user | Public (membership types) |
| UserBrowser → EHTDA-WebApp | HTTP | `:9010 /add_type.php` | auth:user | Public (membership type creation) |
| UserBrowser → EHTDA-WebApp | HTTP | `:9010 /edit_type.php?id=N` | auth:user | Public (membership type edit) |
| UserBrowser → EHTDA-WebApp | HTTP | `:9010 /delete_membership.php?id=N` | auth:user | Public (membership type deletion) |
| UserBrowser → EHTDA-WebApp | HTTP | `:9010 /report.php` | auth:user | PII (member report) |
| UserBrowser → EHTDA-WebApp | HTTP | `:9010 /revenue_report.php` | auth:user | Payments, PII (revenue report) |
| UserBrowser → EHTDA-WebApp | HTTP | `:9010 /settings.php` | auth:user | Secrets (system name, currency, logo upload) |
| UserBrowser → EHTDA-WebApp | HTTP | `:9010 /includes/config.php` | None | Secrets (web-accessible; PHP hides source) |
| EHTDA-WebApp → MySQL-DB | TCP | `:3306` | app-internal | PII, Tokens, Secrets |
| EHTDA-WebApp → uploads-dir | File | local filesystem | None | PII (photos), potential Secrets (uploaded PHP shells) |

### 6.4 Guards Directory

| Guard Name | Category | Statement |
|---|---|---|
| auth:user | Auth | Requires `$_SESSION['user_id']` to be set. Implemented as `if (!isset($_SESSION['user_id'])) { header("Location: index.php"); exit(); }` at lines 4–7 in most protected files. |
| no-guard | Auth | No session check. Present on `delete_members.php`, `print_membership_card.php`, `get_membership_amount.php`. Any HTTP request (authenticated or not) is processed. |
| guard-after-query | Auth | Session guard is present but placed AFTER an initial database query executes. Present in `manage_members.php` (guard at line 8, query at line 4), `list_renewal.php` (guard at line 7, query at line 4), `view_type.php` (guard at line 7, query at line 4). Data is fetched before authentication is verified. |
| no-ownership-check | Authorization | No object ownership verification. For endpoints accepting object IDs (`edit_member.php?id=`, `memberProfile.php?id=`, `renew.php?id=`, `edit_type.php?id=`, `delete_membership.php?id=`), any authenticated user can access/modify any object without verifying they own or are authorized to act on it. |
| no-csrf | Protocol | No CSRF tokens on any form or state-changing endpoint. All 13+ forms and all GET-based delete operations lack CSRF protection. |
| no-rbac | Authorization | No role-based access control exists. All authenticated users share identical privileges. There is no admin-only section. |

---

## 7. Role & Privilege Architecture

### 7.1 Discovered Roles

| Role Name | Privilege Level | Scope/Domain | Code Implementation |
|---|---|---|---|
| anon | 0 | Global | No `$_SESSION['user_id']`. Access to: `index.php`, `logout.php`, `delete_members.php` (no guard!), `print_membership_card.php` (no guard!), `get_membership_amount.php` (no guard!), `includes/config.php` |
| auth | 1 | Global | `$_SESSION['user_id']` is set after successful login. Grants access to ALL 16 remaining files. No sub-roles exist. Effectively a superuser. |

**Note:** There is **no admin role, no manager role, no hierarchical RBAC**. The `users` table has no role column. Any user in the `users` table has identical, unrestricted access to the entire application.

### 7.2 Privilege Lattice

```
Privilege Ordering (→ means "can access resources of"):
anon → auth (all resources)

Parallel Isolation:
None. Single flat privilege level for all authenticated users.

Unauthenticated access to protected resources (implementation bug, not design):
anon → delete_members.php (intended: auth, guard missing)
anon → print_membership_card.php (intended: auth, guard missing)
anon → get_membership_amount.php (possibly intentional AJAX endpoint)
```

**Note:** No role switching, no impersonation, no sudo mode exists.

### 7.3 Role Entry Points

| Role | Default Landing Page | Accessible Route Patterns | Authentication Method |
|---|---|---|---|
| anon | `/index.php` (login) | `/index.php`, `/logout.php`, `/delete_members.php` (bug), `/print_membership_card.php` (bug), `/get_membership_amount.php`, `/includes/config.php` | None |
| auth | `/dashboard.php` | All 19 PHP files | `PHPSESSID` session cookie containing `$_SESSION['user_id']` |

### 7.4 Role-to-Code Mapping

| Role | Middleware/Guards | Permission Checks | Storage Location |
|---|---|---|---|
| anon | None | None | No session data required |
| auth | `if (!isset($_SESSION['user_id'])) { header("Location: index.php"); exit(); }` at lines 4–7 of 16 files | Presence of `$_SESSION['user_id']` only — no further checks | PHP server-side session; session ID in `PHPSESSID` cookie (no security flags) |

---

## 8. Authorization Vulnerability Candidates

### 8.1 Horizontal Privilege Escalation Candidates

The application has a single flat role, so there is no traditional horizontal escalation between user accounts (there is only one administrator account in the `users` table). However, the **member data** (PII) is the sensitive resource. Any authenticated user can access any member record without ownership validation. The three unauthenticated endpoints allow even unauthenticated access.

| Priority | Endpoint Pattern | Object ID Parameter | Data Type | Sensitivity |
|---|---|---|---|---|
| High | `/print_membership_card.php?id=N` | id (GET) | member PII | Full name, address, license number, photo, membership type — unauthenticated access |
| High | `/delete_members.php?id=N` | id (GET) | member record | Unauthenticated deletion of any member and their renewal history |
| High | `/memberProfile.php?id=N` | id (GET) | member PII | Full member profile; no ownership check; authenticated but any auth user accesses any member |
| High | `/edit_member.php?id=N` | id (GET) + POST | member PII | Edit any member's personal data; no ownership check |
| Medium | `/renew.php?id=N` | id (GET) | member renewal + financial | Renew membership for any member; `totalAmount` is client-controlled POST field |
| Medium | `/get_membership_amount.php?membershipTypeId=N` | membershipTypeId (GET) | pricing data | Unauthenticated; SQL injection on ID parameter |
| Medium | `/edit_type.php?id=N` | id (GET), edit_id (POST) | membership type config | Edit any membership type; no ownership check |
| Low | `/delete_membership.php?id=N` | id (GET) | membership type | Delete any membership type; no ownership check |

### 8.2 Vertical Privilege Escalation Candidates

**No vertical escalation by role exists** — there is only one authenticated role. The primary vertical boundary is **unauthenticated → authenticated**. The following endpoints bypass this boundary entirely:

| Target Level | Endpoint Pattern | Functionality | Risk Level |
|---|---|---|---|
| auth (bypassed) | `/delete_members.php?id=N` | Unauthenticated member deletion | Critical |
| auth (bypassed) | `/print_membership_card.php?id=N` | Unauthenticated PII disclosure | High |
| auth (bypassed) | `/get_membership_amount.php?membershipTypeId=N` | Unauthenticated pricing data + SQL injection | Medium |
| auth (login bypass) | `/index.php` POST | SQL injection allows bypassing password check entirely: `email=' OR '1'='1'-- -` | Critical |

**Note:** All authenticated endpoints are effectively admin-equivalent. There is no lower-privilege user role to test for unauthorized admin access.

### 8.3 Context-Based Authorization Candidates

| Workflow | Endpoint | Expected Prior State | Bypass Potential |
|---|---|---|---|
| Member Renewal | `POST /renew.php` | Member loaded via `GET /renew.php?id=N` first | POST without GET id leaves `$memberId` undefined; direct POST with crafted `membershipType` and `totalAmount` bypasses normal renewal flow |
| Member Edit | `POST /edit_member.php` | Member loaded via `GET /edit_member.php?id=N` | POST without GET id — `$memberId` undefined, UPDATE WHERE clause malformed |
| Password Change | `POST /settings.php` (changePassword) | currentPassword must match stored hash | `confirmPassword` is read but **never compared against `newPassword`** — password can be changed to a value that doesn't match the confirmation field |
| File Upload | `POST /settings.php` (updateSettings) | Authenticated user | No MIME/extension validation; raw filename as destination path; path traversal via `../` in filename |

---

## 9. Injection Sources

### SQL Injection Sources (All network-accessible, no prepared statements anywhere)

**SQLi-01 — Login bypass (CRITICAL, unauthenticated)**
- File: `/repos/MembershipManagementSystemPHP/index.php`, lines 6, 14–15
- Source: `$_POST['email']` → `$email` → `"SELECT * FROM users WHERE email = '$email' AND password = '$hashed_password'"` → `$conn->query($sql)`
- Table: `users`

**SQLi-02 — Edit member GET id + POST fields (CRITICAL)**
- File: `/repos/MembershipManagementSystemPHP/edit_member.php`, lines 15, 17, 37–45, 56–61
- Sources: `$_GET['id']` → SELECT and UPDATE WHERE clause; `$_POST['fullname']`, `$_POST['dob']`, `$_POST['gender']`, `$_POST['contactNumber']`, `$_POST['email']`, `$_POST['address']`, `$_POST['country']`, `$_POST['postcode']`, `$_POST['occupation']` → UPDATE SET clause
- Table: `members`

**SQLi-03 — Add member INSERT (CRITICAL)**
- File: `/repos/MembershipManagementSystemPHP/add_members.php`, lines 23–32, 45–50
- Sources: `$_POST['fullname']`, `$_POST['dob']`, `$_POST['gender']`, `$_POST['contactNumber']`, `$_POST['email']`, `$_POST['address']`, `$_POST['country']`, `$_POST['postcode']`, `$_POST['occupation']`, `$_POST['membershipType']` → INSERT VALUES
- Table: `members`

**SQLi-04 — Delete member by GET id (CRITICAL, unauthenticated)**
- File: `/repos/MembershipManagementSystemPHP/delete_members.php`, lines 33–48
- Source: `$_GET['id']` → `$memberId` → three queries (SELECT, DELETE renew, DELETE member)
- Tables: `renew`, `members`

**SQLi-05 — Delete membership type GET id (HIGH)**
- File: `/repos/MembershipManagementSystemPHP/delete_membership.php`, lines 10, 12, 14
- Source: `$_GET['id']` → `$delete_id` → `DELETE FROM membership_types WHERE id = $delete_id`
- Table: `membership_types`

**SQLi-06 — Edit type GET id + POST fields (HIGH)**
- File: `/repos/MembershipManagementSystemPHP/edit_type.php`, lines 12–17, 27–29
- Sources: `$_GET['id']` → SELECT; `$_POST['membershipType']`, `$_POST['membershipAmount']`, `$_POST['edit_id']` → UPDATE
- Table: `membership_types`

**SQLi-07 — Add membership type POST fields (HIGH, three files)**
- Files: `/repos/MembershipManagementSystemPHP/add_type.php` line 15; `/repos/MembershipManagementSystemPHP/manage_members.php` line 17; `/repos/MembershipManagementSystemPHP/view_type.php` line 27
- Sources: `$_POST['membershipType']`, `$_POST['membershipAmount']` → INSERT VALUES
- Table: `membership_types`

**SQLi-08 — Renew member GET id + POST fields (HIGH)**
- File: `/repos/MembershipManagementSystemPHP/renew.php`, lines 15, 17, 29, 34, 37, 39
- Sources: `$_GET['id']` → SELECT, UPDATE WHERE, INSERT; `$_POST['membershipType']` → UPDATE SET; `$_POST['totalAmount']` → INSERT VALUES (amount manipulation)
- Tables: `members`, `renew`

**SQLi-09 — Get membership amount GET id (HIGH, unauthenticated)**
- File: `/repos/MembershipManagementSystemPHP/get_membership_amount.php`, lines 10, 14–15
- Source: `$_GET['membershipTypeId']` → `$membershipTypeId` → `SELECT amount FROM membership_types WHERE id = $membershipTypeId`
- Table: `membership_types`

**SQLi-10 — Member profile GET id (HIGH)**
- File: `/repos/MembershipManagementSystemPHP/memberProfile.php`, lines 10, 12–16
- Source: `$_GET['id']` → `$memberId` → JOIN SELECT on `members` and `membership_types`
- Tables: `members`, `membership_types`

**SQLi-11 — Print membership card GET id (CRITICAL, unauthenticated, no isset check)**
- File: `/repos/MembershipManagementSystemPHP/print_membership_card.php`, lines 4, 5–9
- Source: `$_GET['id']` → `$memberId` (no `isset()` check; undefined triggers PHP notice) → JOIN SELECT
- Tables: `members`, `membership_types`

**SQLi-12 — Date-range member report POST (HIGH)**
- File: `/repos/MembershipManagementSystemPHP/report.php`, lines 10–11, 13–17
- Sources: `$_POST['fromDate']`, `$_POST['toDate']` → `BETWEEN '$fromDate' AND '$toDate'` in WHERE clause
- Tables: `members`, `membership_types`

**SQLi-13 — Date-range revenue report POST (HIGH)**
- File: `/repos/MembershipManagementSystemPHP/revenue_report.php`, lines 10–11, 13–18
- Sources: `$_POST['fromDate']`, `$_POST['toDate']` → `BETWEEN '$fromDate' AND '$toDate'` in WHERE clause
- Tables: `renew`, `members`, `settings`

**SQLi-14 — Settings UPDATE POST (HIGH)**
- File: `/repos/MembershipManagementSystemPHP/settings.php`, lines 10–11, 14, 19–23, 33–35
- Sources: `$_POST['systemName']` → `system_name = '$systemName'`; `$_POST['currency']` → `currency = '$currency'`; `$_FILES['logo']['name']` → `logo = '$targetPath'`
- Table: `settings`

### File Upload / Path Traversal Sources

**FI-01 — Member photo upload, extension preserved (HIGH)**
- File: `/repos/MembershipManagementSystemPHP/add_members.php`, lines 37–40
- Source: `$_FILES['photo']['name']` → `pathinfo($name, PATHINFO_EXTENSION)` preserves extension → `move_uploaded_file($tmp, 'uploads/member_photos/<timestamp>_<uniqid>.<user_ext>')`
- Risk: Uploading `evil.php` results in an executable PHP file at `uploads/member_photos/<timestamp>_<id>.php`

**FI-02 — Member photo upload in edit, full basename preserved (HIGH)**
- File: `/repos/MembershipManagementSystemPHP/edit_member.php`, lines 48–52
- Source: `$_FILES['photo']['name']` → `generateUniqueFileName()` preserves original basename + extension → `move_uploaded_file($tmp, 'uploads/member_photos/<original_basename>_<time>.<ext>')`
- Risk: Attacker controls both the filename and extension; PHP files placed in `uploads/member_photos/` are executable

**FI-03 — Logo upload, fully verbatim filename (CRITICAL)**
- File: `/repos/MembershipManagementSystemPHP/settings.php`, lines 14, 19–20
- Source: `$_FILES['logo']['name']` → `$logoName` → `$targetPath = 'uploads/' . $logoName` → `move_uploaded_file($logoTmpName, $targetPath)`
- Risk: Attacker uploads `shell.php` → stored at `uploads/shell.php` with complete filename control. No randomization, no extension check, path traversal possible with `../shell.php` to escape `uploads/`.

### Open Redirect Sources

**OR-01 — HTTP_REFERER open redirect (LOW)**
- File: `/repos/MembershipManagementSystemPHP/delete_membership.php`, lines 15 and 22
- Source: `$_SERVER['HTTP_REFERER']` (fully attacker-controlled request header) → `header("Location: " . $_SERVER['HTTP_REFERER'])` with no validation
- Risk: Redirect to arbitrary external URL; useful in phishing chains

### Command Injection
- **None found.** No `exec()`, `system()`, `shell_exec()`, `passthru()`, `popen()`, `proc_open()`, or backtick operators exist in any PHP file.

### SSTI / Template Injection
- **None found.** No templating engine or `eval()` of user content.

### Deserialization
- **None found.** No `unserialize()` calls. `json_encode()` is used only for output (not deserialization of user input).

### XSS Sinks (Stored, from DB; no htmlspecialchars() anywhere in codebase)

All member fields (`fullname`, `dob`, `gender`, `contact_number`, `email`, `address`, `country`, `postcode`, `occupation`, `membership_number`, `membership_type`) and settings fields (`system_name`, `currency`, `logo`) are stored without sanitization and reflected without encoding.

Key output files and lines:
- `manage_members.php` lines 90–94 — table body echo
- `memberProfile.php` lines 120–132 — profile field echo
- `print_membership_card.php` lines 154–167 — card echo (unauthenticated)
- `report.php` lines 87–91 — report table echo
- `revenue_report.php` lines 87–90 — revenue table echo
- `dashboard.php` lines 307, 310 — recent members list echo
- `list_renewal.php` lines 83–88 — renewal table echo
- `edit_member.php` lines 122, 126, 145, 150, 158, 163, 171 — value="" attribute echo (stored XSS breaking HTML context)
- `edit_type.php` lines 78, 82 — value="" attribute echo
- `view_type.php` lines 85–86 — table row echo
- Reflected XSS: `memberProfile.php` lines 108, 112, 145 — `$_GET['id']` echoed into onclick attributes and href values without encoding
- Reflected XSS: `edit_type.php` line 72 — `$_GET['id']` echoed into hidden input value attribute
