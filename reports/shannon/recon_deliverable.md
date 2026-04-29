# Reconnaissance Deliverable: PHP Membership Management System

## 0) HOW TO READ THIS

This reconnaissance report provides a comprehensive map of the application's attack surface, with special emphasis on authorization and privilege escalation opportunities for the Authorization Analysis Specialist.

**Key Sections for Authorization Analysis:**
- **Section 4 (API Endpoint Inventory):** Contains authorization details for each endpoint — focus on "Required Role" and "Object ID Parameters" columns to identify IDOR candidates. Three endpoints have NO authentication at all.
- **Section 6.4 (Guards Directory):** Catalog of authorization controls — the only guard that exists is a single `isset($_SESSION['user_id'])` check; there are NO role guards.
- **Section 7 (Role & Privilege Architecture):** This application has NO role system — a single flat user tier exists. The entire authorization model is binary: authenticated vs unauthenticated.
- **Section 8 (Authorization Vulnerability Candidates):** Every authenticated endpoint is an IDOR candidate since there are no object-ownership checks. Three unauthenticated endpoints allow direct data access and destruction.

**How to Use the Network Mapping (Section 6):** The application is a PHP flat-file monolith with no framework, no routing layer, and no middleware. Every `.php` file in the web root IS an endpoint. The only security boundary is a per-file `isset($_SESSION['user_id'])` check — and this is absent from three critical endpoints.

**Priority Order for Testing:** Start with the three unauthenticated endpoints (`print_membership_card.php`, `delete_members.php`, `get_membership_amount.php`) for immediate exploitation. Then test all authenticated endpoints for IDOR since no ownership checks exist anywhere.

---

## 1. Executive Summary

The target is a **PHP 7.4 membership management application** — a flat-file procedural PHP monolith deployed on Apache 2.4.54 (Debian) accessible at `http://host.docker.internal:9010`. The application manages member records (name, address, PII, membership type, renewal history) for a single administrative user.

**Core Technology Stack:** PHP 7.4.33 (EOL), Apache 2.4.54, MySQL 8.4, no framework, no routing layer, no MVC separation. HTML is rendered inline via PHP `echo`/`include`.

**Primary User-Facing Components:**
- Login/Logout (single admin account)
- Member management (add, edit, delete, view, print membership card)
- Membership type management (add, edit, delete)
- Renewal tracking (renew member, list renewals)
- Reporting (membership report, revenue report)
- Settings (system name, currency, logo, password change)
- Three unauthenticated public endpoints

**Critical Security Profile:** The application is critically deficient across every security domain. Every SQL query uses raw string concatenation (universal SQL injection). Three endpoints have no authentication whatsoever. No CSRF protection, no input validation, no output encoding, no security headers, and file uploads accept PHP webshells without restriction. The MySQL connection runs as root.

---

## 2. Technology & Service Map

- **Frontend:** Plain HTML rendered inline via PHP `echo`. Vendored libraries: jQuery 3.4.1 (CVE-2019-11358, CVE-2020-11022/11023), jQuery UI 1.12.1 (CVE-2021-41182/41183/41184), Bootstrap 4.4.1 (CVE-2024-6485), DataTables 1.10.20, AdminLTE 3.0.5. External CDN loads: `ionicframework.com/ionicons/2.0.1/css/ionicons.min.css`, `fonts.googleapis.com/css?family=Source+Sans+Pro`.
- **Backend:** PHP 7.4.33 (EOL November 2022), procedural style, zero framework. MySQLi procedural/OOP. No Composer, no autoloader, no dependency injection.
- **Infrastructure:** Apache/2.4.54 (Debian), HTTP only (no TLS), port 9010. MySQL 8.4 (Docker). Docker Compose deployment. No CDN, no WAF, no reverse proxy. No `.htaccess` files. No security headers.
- **Identified Subdomains:** None. Single host at `host.docker.internal:9010`.
- **Open Ports & Services:**
  - Port 9010/TCP: HTTP — Apache/2.4.54 PHP/7.4.33 application (confirmed live)
  - MySQL: Internal Docker network only (not exposed externally)

**Confirmed Live Server Headers:**
```
Server: Apache/2.4.54 (Debian)
X-Powered-By: PHP/7.4.33
Set-Cookie: PHPSESSID=...; path=/   (no HttpOnly, no Secure, no SameSite)
```
No `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, or `Permissions-Policy` headers present.

---

## 3. Authentication & Session Management Flow

- **Entry Points:**
  - `POST /index.php` — login form (fields: `email`, `password`, `login` button)
  - `GET /logout.php` — logout (no CSRF protection)
  - `POST /settings.php` (action: `changePassword`) — password change for authenticated admin
  - **No registration endpoint exists.** New user accounts require direct database insertion.
  - **No password reset endpoint exists.** No forgot-password flow, no email sending, no token generation.

- **Mechanism (Step-by-Step):**
  1. User submits POST to `/index.php` with `email` and `password`
  2. `index.php` line 12: password is hashed with `md5($password)` (no salt)
  3. `index.php` line 14: raw SQL query `SELECT * FROM users WHERE email = '$email' AND password = '$hashed_password'` — both fields directly concatenated (SQL injection)
  4. If 1 row returned: `$_SESSION['user_id'] = $row['id']` (line 20), `$_SESSION['email'] = $row['email']` (line 21)
  5. Redirect to `dashboard.php` (line 23)
  6. `session_regenerate_id()` is **never called** — session fixation is possible
  7. Session cookie set by PHP defaults: `PHPSESSID=...; path=/` (no HttpOnly forced in code, no Secure, no SameSite)

- **Code Pointers:**
  - `index.php` lines 4-30: Full login handler
  - `includes/config.php` lines 14: `session_start()` (only session configuration)
  - `logout.php` lines 4-8: `$_SESSION = array()`, `session_destroy()`, redirect to `index.php`

### 3.1 Role Assignment Process

- **Role Determination:** None. The `users` table has no role column (`id`, `email`, `password`, `registration_date`, `updated_date` only). There is no role concept in this application.
- **Default Role:** "Authenticated" — all users have identical, unrestricted access to all functionality.
- **Role Upgrade Path:** Not applicable. No roles exist.
- **Code Implementation:** `includes/config.php` line 14 (`session_start()`); `index.php` lines 20-21 (session write). No role assignment logic anywhere.

### 3.2 Privilege Storage & Validation

- **Storage Location:** PHP file-based session storage (`/tmp`). Session stores only `user_id` (integer) and `email` (string). No role, no privilege level, no permissions stored.
- **Validation Points:** Each protected PHP file contains an inline check: `if (!isset($_SESSION['user_id'])) { header("Location: index.php"); exit(); }`. This is the **only** authorization gate in the entire application.
- **Cache/Session Persistence:** PHP default `session.gc_maxlifetime` (typically 1440 seconds). No explicit timeout configured anywhere.
- **Code Pointers:** Inline check in each protected file (e.g., `dashboard.php` line 4, `add_members.php` line 4, etc.). **Missing entirely from:** `delete_members.php`, `print_membership_card.php`, `get_membership_amount.php`.

### 3.3 Role Switching & Impersonation

- **Impersonation Features:** None. No impersonation mechanism exists.
- **Role Switching:** None. No roles exist.
- **Audit Trail:** No logging of any kind exists in the application.
- **Code Implementation:** N/A.

---

## 4. API Endpoint Inventory

**Network Surface Focus:** All PHP files reside directly in the Apache document root — every `.php` file is a network-accessible endpoint. There is no routing layer.

| Method | Endpoint Path | Required Role | Object ID Parameters | Authorization Mechanism | Description & Code Pointer |
|---|---|---|---|---|---|
| GET | `/index.php` | anon | None | None | Login form render. `index.php` |
| POST | `/index.php` | anon | None | None | Login handler. SQLi on `email`. `index.php:14` |
| GET | `/logout.php` | anon | None | None | Destroys session. No CSRF protection. `logout.php:4-8` |
| GET | `/print_membership_card.php` | **NONE (unauthenticated)** | `id` (member ID) | **NO AUTH CHECK** | Renders full member PII. Anyone can access. `print_membership_card.php:4-8` |
| GET | `/get_membership_amount.php` | **NONE (unauthenticated)** | `membershipTypeId` | **NO AUTH CHECK** | Returns membership type amount as JSON. `get_membership_amount.php:10-14` |
| GET | `/delete_members.php` | **NONE (unauthenticated)** | `id` (member ID) | **NO AUTH CHECK** | Permanently deletes member record and renewals. `delete_members.php:33-46` |
| GET | `/dashboard.php` | user | None | `isset($_SESSION['user_id'])` line 4 | Dashboard with stats. `dashboard.php` |
| GET | `/manage_members.php` | user | None | `isset($_SESSION['user_id'])` line 8 | Member list DataTable. DB query runs before auth check (line 4). `manage_members.php` |
| GET | `/add_members.php` | user | None | `isset($_SESSION['user_id'])` line 4 | Add member form. `add_members.php` |
| POST | `/add_members.php` | user | None | `isset($_SESSION['user_id'])` line 4 | Insert new member + file upload. SQLi all fields. `add_members.php:45-48` |
| GET | `/edit_member.php` | user | `id` (member ID) | `isset($_SESSION['user_id'])` line 4 | Load member for editing. SQLi via `id`. No ownership check. `edit_member.php:15-17` |
| POST | `/edit_member.php` | user | `id` (GET param) | `isset($_SESSION['user_id'])` line 4 | Update member record + file upload. SQLi all POST fields + `id`. No ownership check. `edit_member.php:59` |
| GET | `/memberProfile.php` | user | `id` (member ID) | `isset($_SESSION['user_id'])` line 4 | View member profile + PII. SQLi via `id`. No ownership check. `memberProfile.php:10-15` |
| GET | `/add_type.php` | user | None | `isset($_SESSION['user_id'])` line 4 | Add membership type form. `add_type.php` |
| POST | `/add_type.php` | user | None | `isset($_SESSION['user_id'])` line 4 | Insert membership type. SQLi on `membershipType`. `add_type.php:15` |
| GET | `/view_type.php` | user | None | `isset($_SESSION['user_id'])` line 7 | Membership types DataTable. DB query before auth check. `view_type.php:4-7` |
| POST | `/view_type.php` | user | None | `isset($_SESSION['user_id'])` line 7 | Dead code: orphaned POST handler inserts into `membership_types`. `view_type.php:24-25` |
| GET | `/edit_type.php` | user | `id` (type ID) | `isset($_SESSION['user_id'])` line 4 | Load membership type. SQLi via `id`. `edit_type.php:27-28` |
| POST | `/edit_type.php` | user | `edit_id` (POST) | `isset($_SESSION['user_id'])` line 4 | Update membership type. SQLi on all POST fields. `edit_type.php:17` |
| GET | `/delete_membership.php` | user | `id` (type ID) | `isset($_SESSION['user_id'])` line 4 | Delete membership type. SQLi via `id`. Open redirect via `HTTP_REFERER`. `delete_membership.php:10-15` |
| GET | `/renew.php` | user | `id` (member ID) | `isset($_SESSION['user_id'])` line 4 | Load member for renewal. SQLi via `id`. No ownership check. `renew.php:15-17` |
| POST | `/renew.php` | user | `id` (GET param) | `isset($_SESSION['user_id'])` line 4 | Process renewal. SQLi on `id`, `membershipType`, `totalAmount`. Client-controlled price. `renew.php:34,39` |
| GET | `/list_renewal.php` | user | None | `isset($_SESSION['user_id'])` line 7 | Renewal list DataTable. DB query before auth check. `list_renewal.php:4-7` |
| GET | `/report.php` | user | None | `isset($_SESSION['user_id'])` line 4 | Membership report form. `report.php` |
| POST | `/report.php` | user | None | `isset($_SESSION['user_id'])` line 4 | Generate member report by date range. SQLi on `fromDate`/`toDate`. `report.php:13-16` |
| GET | `/revenue_report.php` | user | None | `isset($_SESSION['user_id'])` line 4 | Revenue report form. `revenue_report.php` |
| POST | `/revenue_report.php` | user | None | `isset($_SESSION['user_id'])` line 4 | Generate revenue report by date range. SQLi on `fromDate`/`toDate`. `revenue_report.php:13-17` |
| GET | `/settings.php` | user | None | `isset($_SESSION['user_id'])` line 4 | Settings form. `settings.php` |
| POST | `/settings.php` (updateSettings) | user | None | `isset($_SESSION['user_id'])` line 4 | Update system name, currency, logo upload. SQLi + unrestricted file upload. `settings.php:10-33` |
| POST | `/settings.php` (changePassword) | user | None | `isset($_SESSION['user_id'])` line 4 | Change admin password. MD5 hashing. `settings.php:44-72` |
| GET | `/includes/config.php` | anon | None | None | Returns blank page (session_start + DB connect). No direct output but PHP executed. |

**Web-Accessible Static Files (No Auth Required):**
| URL | Status | Risk |
|---|---|---|
| `GET /uploads/01%20LOGIN%20DETAILS%20%26%20PROJECT%20INFO.txt` | 200 | **Admin credentials publicly downloadable** (`admin@mail.com` / `codeastro.com`) |
| `GET /uploads/member_photos/*` | 200 | Member photos and potentially uploaded webshells are web-accessible |
| `GET /DATABASE%20FILE/membershiphp.sql` | 200 | Full database dump with admin password hash downloadable |
| `GET /uploads/` | 403 | Directory listing disabled |
| `GET /plugins/` | 403 | Directory listing disabled |

---

## 5. Potential Input Vectors for Vulnerability Analysis

### URL Parameters (GET)

| Endpoint | Parameter | Type | Used In | File:Line |
|---|---|---|---|---|
| `/index.php` | None | — | — | — |
| `/print_membership_card.php` | `id` | Integer (untyped) | SQL: `WHERE members.id = $memberId` | `print_membership_card.php:4,8` |
| `/get_membership_amount.php` | `membershipTypeId` | Integer (untyped) | SQL: `WHERE id = $membershipTypeId` | `get_membership_amount.php:10,14` |
| `/delete_members.php` | `id` | Integer (untyped) | SQL: `WHERE member_id = $memberId` and `WHERE id = $memberId` | `delete_members.php:33,35,46` |
| `/edit_member.php` | `id` | Integer (untyped) | SQL: `WHERE id = $memberId`, reused in POST UPDATE | `edit_member.php:15,17,59` |
| `/memberProfile.php` | `id` | Integer (untyped) | SQL: `WHERE members.id = $memberId` (JOIN query) | `memberProfile.php:10,15` |
| `/edit_type.php` | `id` | Integer (untyped, null-coalesced) | SQL: `WHERE id = $edit_id` | `edit_type.php:27,28` |
| `/delete_membership.php` | `id` | Integer (untyped, null-coalesced) | SQL: `WHERE id = $delete_id` | `delete_membership.php:10,12` |
| `/renew.php` | `id` | Integer (untyped) | SQL: `WHERE id = $memberId` (SELECT + UPDATE + INSERT) | `renew.php:15,17,34,39` |

### POST Body Fields

| Endpoint | Field Name | Type | Used In | File:Line |
|---|---|---|---|---|
| `/index.php` | `email` | String | SQL: `WHERE email = '$email'` | `index.php:6,14` |
| `/index.php` | `password` | String | MD5 then SQL: `AND password = '$hashed_password'` | `index.php:7,12,14` |
| `/add_members.php` | `fullname` | String | SQL INSERT, HTML echo (Stored XSS) | `add_members.php:23,47` |
| `/add_members.php` | `dob` | String | SQL INSERT | `add_members.php:24,47` |
| `/add_members.php` | `gender` | String | SQL INSERT | `add_members.php:25,47` |
| `/add_members.php` | `contactNumber` | String | SQL INSERT, HTML echo (Stored XSS) | `add_members.php:26,47` |
| `/add_members.php` | `email` | String | SQL INSERT, HTML echo (Stored XSS) | `add_members.php:27,47` |
| `/add_members.php` | `address` | String | SQL INSERT, HTML echo (Stored XSS) | `add_members.php:28,47` |
| `/add_members.php` | `country` | String | SQL INSERT, HTML echo (Stored XSS) | `add_members.php:29,47` |
| `/add_members.php` | `postcode` | String | SQL INSERT, HTML echo (Stored XSS) | `add_members.php:30,47` |
| `/add_members.php` | `occupation` | String | SQL INSERT, HTML echo (Stored XSS) | `add_members.php:31,47` |
| `/add_members.php` | `membershipType` | Integer | SQL INSERT | `add_members.php:32,47` |
| `/add_members.php` | `photo` (file) | File upload | `move_uploaded_file()` to `uploads/member_photos/` — no validation | `add_members.php:36-40` |
| `/edit_member.php` | `fullname` | String | SQL UPDATE, HTML echo (Stored XSS) | `edit_member.php:37,59` |
| `/edit_member.php` | `dob` | String | SQL UPDATE | `edit_member.php:38,59` |
| `/edit_member.php` | `gender` | String | SQL UPDATE | `edit_member.php:39,59` |
| `/edit_member.php` | `contactNumber` | String | SQL UPDATE | `edit_member.php:40,59` |
| `/edit_member.php` | `email` | String | SQL UPDATE | `edit_member.php:41,59` |
| `/edit_member.php` | `address` | String | SQL UPDATE | `edit_member.php:42,59` |
| `/edit_member.php` | `country` | String | SQL UPDATE | `edit_member.php:43,59` |
| `/edit_member.php` | `postcode` | String | SQL UPDATE | `edit_member.php:44,59` |
| `/edit_member.php` | `occupation` | String | SQL UPDATE | `edit_member.php:45,59` |
| `/edit_member.php` | `photo` (file) | File upload | `move_uploaded_file()` to `uploads/member_photos/` — no validation | `edit_member.php:48-54` |
| `/add_type.php` | `membershipType` | String | SQL INSERT | `add_type.php:12,15` |
| `/add_type.php` | `membershipAmount` | Numeric | SQL INSERT (unquoted) | `add_type.php:13,15` |
| `/edit_type.php` | `membershipType` | String | SQL UPDATE | `edit_type.php:12,17` |
| `/edit_type.php` | `membershipAmount` | Numeric | SQL UPDATE (unquoted) | `edit_type.php:13,17` |
| `/edit_type.php` | `edit_id` | Integer | SQL UPDATE `WHERE id = $id` | `edit_type.php:15,17` |
| `/renew.php` | `membershipType` | Integer | SQL UPDATE | `renew.php:29,34` |
| `/renew.php` | `extend` | Integer | `strtotime("+$renewDuration months")` | `renew.php:30,32` |
| `/renew.php` | `totalAmount` | Decimal | SQL INSERT `total_amount = $totalAmount` (client-controlled price) | `renew.php:37,39` |
| `/report.php` | `fromDate` | String | SQL BETWEEN clause | `report.php:10,16` |
| `/report.php` | `toDate` | String | SQL BETWEEN clause | `report.php:11,16` |
| `/revenue_report.php` | `fromDate` | String | SQL BETWEEN clause | `revenue_report.php:10,17` |
| `/revenue_report.php` | `toDate` | String | SQL BETWEEN clause | `revenue_report.php:11,17` |
| `/settings.php` | `systemName` | String | SQL UPDATE, HTML echo ALL pages via sidebar (Persistent XSS) | `settings.php:10,21,33` |
| `/settings.php` | `currency` | String | SQL UPDATE, HTML echo revenue reports | `settings.php:11,21,33` |
| `/settings.php` | `logo` (file) | File upload | `move_uploaded_file()` to `uploads/$logoName` (original name, path traversal) | `settings.php:13-20` |
| `/settings.php` | `currentPassword` | String | MD5 comparison | `settings.php:46,58` |
| `/settings.php` | `newPassword` | String | MD5 hash + SQL UPDATE | `settings.php:47,59,60` |
| `/settings.php` | `confirmPassword` | String | **Read but never compared to `newPassword`** — logic bug | `settings.php:48` |

### HTTP Headers

| Header | Endpoint | Usage | File:Line |
|---|---|---|---|
| `Referer` (`$_SERVER['HTTP_REFERER']`) | `/delete_membership.php` | Used directly in `header("Location: ...")` — open redirect | `delete_membership.php:15,22` |
| `Cookie: PHPSESSID` | All protected pages | Session authentication | All protected files via `includes/config.php:14` |

### Cookie Values

| Cookie | Usage | Risk |
|---|---|---|
| `PHPSESSID` | PHP session ID — passed as `PHPSESSID=<value>; path=/`. No `HttpOnly`, `Secure`, or `SameSite` flags set in code. Session fixation possible (no `session_regenerate_id()`). | Session hijacking, fixation |

---

## 6. Network & Interaction Map

### 6.1 Entities

| Title | Type | Zone | Tech | Data | Notes |
|---|---|---|---|---|---|
| UserBrowser | Identity | Internet | Any browser | Public | External attacker or admin user |
| MembershipApp | Service | App | Apache/2.4.54, PHP/7.4.33 | PII, Tokens, Secrets | Flat-file PHP monolith; entire repo is web root; no framework |
| MySQLDB | DataStore | Data | MySQL 8.4 (Docker) | PII, Tokens, Secrets | Connected as `root` user with full privileges; latin1 charset |
| UploadsDir | ExternAsset | App | Apache static file serving | PII | `uploads/` — web-accessible; contains admin credentials text file; no PHP execution restriction |
| IonicsCDN | ThirdParty | ThirdParty | CDN (ionicframework.com) | Public | Loads ionicons CSS on every page; supply-chain risk |
| GoogleFontsCDN | ThirdParty | ThirdParty | CDN (fonts.googleapis.com) | Public | Loads Source Sans Pro font on every page; IP leakage |

### 6.2 Entity Metadata

| Title | Metadata Key: Value |
|---|---|
| MembershipApp | Host: `http://host.docker.internal:9010`; Endpoints: All `.php` files in web root; Auth: `PHPSESSID` cookie (bare `session_start()`); DB Connection: MySQLi as root; PHP Version: 7.4.33 (EOL); Web Server: Apache/2.4.54 (Debian); No TLS, no `.htaccess`, no security headers |
| MySQLDB | Engine: MySQL 8.4; Charset: latin1 (all tables); Exposure: Internal Docker network only; Credentials: root / rootpass (committed to docker-compose.yml); Tables: `members`, `membership_types`, `renew`, `settings`, `users`; App connects as root (full DDL + FILE privileges) |
| UploadsDir | Path: `uploads/` (web root); Subdirs: `uploads/member_photos/`; No `.htaccess`; No PHP execution restriction; Contains: `01 LOGIN DETAILS & PROJECT INFO.txt` (admin credentials), `mlg.png`, member photos, potential webshells; Web-accessible URL: `http://host.docker.internal:9010/uploads/` |

### 6.3 Flows (Connections)

| FROM → TO | Channel | Path/Port | Guards | Touches |
|---|---|---|---|---|
| UserBrowser → MembershipApp | HTTP | `:9010 /index.php` | None | Public |
| UserBrowser → MembershipApp | HTTP | `:9010 /print_membership_card.php?id=X` | **None** (no auth) | PII |
| UserBrowser → MembershipApp | HTTP | `:9010 /delete_members.php?id=X` | **None** (no auth) | PII |
| UserBrowser → MembershipApp | HTTP | `:9010 /get_membership_amount.php?membershipTypeId=X` | **None** (no auth) | Public |
| UserBrowser → MembershipApp | HTTP | `:9010 /dashboard.php` | auth:user | Public |
| UserBrowser → MembershipApp | HTTP | `:9010 /manage_members.php` | auth:user | PII |
| UserBrowser → MembershipApp | HTTP | `:9010 /add_members.php (POST)` | auth:user | PII |
| UserBrowser → MembershipApp | HTTP | `:9010 /edit_member.php?id=X` | auth:user | PII |
| UserBrowser → MembershipApp | HTTP | `:9010 /memberProfile.php?id=X` | auth:user | PII |
| UserBrowser → MembershipApp | HTTP | `:9010 /settings.php (POST updateSettings)` | auth:user | Secrets, PII |
| UserBrowser → MembershipApp | HTTP | `:9010 /settings.php (POST changePassword)` | auth:user | Secrets |
| UserBrowser → MembershipApp | HTTP | `:9010 /renew.php?id=X` | auth:user | PII |
| UserBrowser → MembershipApp | HTTP | `:9010 /report.php (POST)` | auth:user | PII |
| UserBrowser → MembershipApp | HTTP | `:9010 /revenue_report.php (POST)` | auth:user | PII |
| UserBrowser → UploadsDir | HTTP | `:9010 /uploads/01%20LOGIN%20DETAILS%20...txt` | None | Secrets |
| UserBrowser → UploadsDir | HTTP | `:9010 /uploads/member_photos/*.php` | None | RCE vector |
| MembershipApp → MySQLDB | TCP | Docker internal network | vpc-only | PII, Tokens, Secrets |
| MembershipApp → IonicsCDN | HTTPS | External | None | Public |
| MembershipApp → GoogleFontsCDN | HTTPS | External | None | Public |

### 6.4 Guards Directory

| Guard Name | Category | Statement |
|---|---|---|
| auth:user | Auth | Requires `isset($_SESSION['user_id'])` — checks only that session key exists. Implemented as inline check at top of each protected PHP file. No role, no token validation, no expiry. |
| no-auth | Auth | Three endpoints (`print_membership_card.php`, `delete_members.php`, `get_membership_amount.php`) have NO authentication guard whatsoever. |
| vpc-only | Network | MySQL is only accessible within the Docker internal network — not directly exposed to the host. |
| session:fixation-risk | Protocol | No `session_regenerate_id()` on login — pre-login session ID becomes the authenticated session ID. |
| cookie:insecure | Protocol | `PHPSESSID` cookie has no `Secure`, `HttpOnly` (not enforced in code), or `SameSite` flags. Transmitted over HTTP only. |
| no-csrf | Protocol | Zero CSRF protection anywhere in the application. No tokens, no SameSite cookies, no origin validation. All state-changing operations are CSRF-vulnerable. |
| no-idor-check | ObjectOwnership | No endpoint verifies that the requesting user is authorized to access the requested object. Any authenticated user can access any object by ID enumeration. |

---

## 7. Role & Privilege Architecture

### 7.1 Discovered Roles

| Role Name | Privilege Level | Scope/Domain | Code Implementation |
|---|---|---|---|
| anon | 0 | Global | No authentication required. Three network-accessible endpoints require no auth: `print_membership_card.php`, `delete_members.php`, `get_membership_amount.php`. |
| user (authenticated) | 1 | Global | `isset($_SESSION['user_id'])` check at top of each protected page. All functionality is accessible to any authenticated user — there is no higher role. |

**There is no admin role, no superuser role, no role hierarchy, and no role column in the `users` table.** The authorization model is strictly binary: authenticated or unauthenticated.

### 7.2 Privilege Lattice

```
Privilege Ordering (→ means "can access resources of"):
anon → user(authenticated)

Parallel Isolation:
None — single-tier system

Accessible to anon (no auth required):
  - /index.php (login form)
  - /logout.php
  - /print_membership_card.php?id=X  [CRITICAL: full PII exposure + SQLi]
  - /delete_members.php?id=X         [CRITICAL: destructive write + SQLi]
  - /get_membership_amount.php        [SQLi]
  - /uploads/01 LOGIN DETAILS....txt [admin credentials]
  - /DATABASE FILE/membershiphp.sql   [DB dump with password hash]

Accessible to user(authenticated) only:
  - All remaining 18 PHP endpoints
  - All functionality (member CRUD, types, renewals, reports, settings)

Note: No impersonation, no sudo mode, no role switching. Once authenticated, a session has
full application access permanently until session expires or logout.
```

### 7.3 Role Entry Points

| Role | Default Landing Page | Accessible Route Patterns | Authentication Method |
|---|---|---|---|
| anon | `/index.php` | `/index.php`, `/logout.php`, `/print_membership_card.php`, `/delete_members.php`, `/get_membership_amount.php`, `/uploads/*`, `/DATABASE FILE/membershiphp.sql` | None |
| user | `/dashboard.php` | All `.php` files in web root | `PHPSESSID` session cookie |

### 7.4 Role-to-Code Mapping

| Role | Middleware/Guards | Permission Checks | Storage Location |
|---|---|---|---|
| anon | None | None | N/A |
| user | Inline `isset($_SESSION['user_id'])` check at top of each PHP file | `!isset($_SESSION['user_id'])` → redirect to `index.php` + `exit()` | PHP file-based session (`/tmp/sess_*`); `$_SESSION['user_id']` + `$_SESSION['email']` |

---

## 8. Authorization Vulnerability Candidates

### 8.1 Horizontal Privilege Escalation Candidates

| Priority | Endpoint Pattern | Object ID Parameter | Data Type | Sensitivity |
|---|---|---|---|---|
| **Critical** | `/print_membership_card.php?id={id}` | `id` (member row ID) | PII (name, address, membership number, photo) | **Unauthenticated** — anyone can enumerate all member records |
| **Critical** | `/delete_members.php?id={id}` | `id` (member row ID) | Destructive operation | **Unauthenticated** — anyone can delete any member record |
| High | `/memberProfile.php?id={id}` | `id` (member row ID) | Full member PII | Any authenticated session can view any member's full profile |
| High | `/edit_member.php?id={id}` | `id` (GET, reused in POST UPDATE) | Full member PII + photo | Any authenticated session can edit any member's record |
| High | `/renew.php?id={id}` | `id` (member row ID) | Renewal/financial data | Any authenticated session can renew any member; `totalAmount` is client-controlled |
| Medium | `/edit_type.php?id={id}` | `id` (membership type ID) | Membership configuration | Any authenticated session can edit any membership type |
| Medium | `/delete_membership.php?id={id}` | `id` (membership type ID) | Membership configuration | Any authenticated session can delete any membership type |
| Low | `/get_membership_amount.php?membershipTypeId={id}` | `membershipTypeId` | Membership pricing | **Unauthenticated** — low sensitivity but SQLi vector |

### 8.2 Vertical Privilege Escalation Candidates

The application has only one privilege tier (authenticated user). There is no "admin" role to escalate to. However, the following endpoints represent "all-powerful" functionality accessible to any authenticated user:

| Functionality | Endpoint | Risk Level |
|---|---|---|
| System-wide settings (name, currency) | `POST /settings.php` (updateSettings) | High — affects all pages via persistent XSS in `system_name` |
| Logo upload (PHP webshell to web root) | `POST /settings.php` (updateSettings, logo field) | **Critical** — RCE via PHP webshell upload |
| Password change | `POST /settings.php` (changePassword) | High — can lock out the admin account |
| Bulk member deletion via SQLi | `GET /delete_members.php?id=X OR 1=1` | Critical — unauthenticated mass deletion |
| Database exfiltration via SQLi | Any endpoint with SQLi | Critical — MySQL root = full DB + FILE access |

**Note:** Since there is only one user account and no roles, any authenticated session IS the admin. Vertical escalation is not applicable — all escalation is lateral (unauthenticated → authenticated).

### 8.3 Context-Based Authorization Candidates

| Workflow | Endpoint | Expected Prior State | Bypass Potential |
|---|---|---|---|
| Multi-step member edit | `POST /edit_member.php` + `?id=X` | GET must load member first; `$memberId` comes from `$_GET['id']` and is reused in POST handler | POST can be sent without prior GET; `member_id` hidden form field is never read |
| Multi-step renewal | `POST /renew.php` + `?id=X` | GET must load member; renewal amount calculated client-side | `totalAmount` is a POST field — send arbitrary renewal amount; `member_id` hidden field never validated server-side |
| Membership type edit | `POST /edit_type.php` | GET must load type; `edit_id` sent as hidden field | `edit_id` in POST body is attacker-controlled — any authenticated user can UPDATE any row |
| Password change | `POST /settings.php` (changePassword) | Must know current password | `confirmPassword` is read at line 48 but **never compared to `newPassword`** — password confirmation bypass |
| Delete then redirect | `GET /delete_membership.php?id=X` | Should originate from `view_type.php` | `Referer` header is used as redirect target — open redirect after delete |

---

## 9. Injection Sources

### SQL Injection Sources

**UNAUTHENTICATED SQL Injection (Critical — no login required):**

| # | Source | Sink | Flow | File:Line |
|---|---|---|---|---|
| 1 | `$_GET['id']` | `WHERE members.id = $memberId` (SELECT JOIN) | `$memberId = $_GET['id']` → `$selectQuery = "... WHERE members.id = $memberId"` | `print_membership_card.php:4 → :8` |
| 2 | `$_GET['id']` | `WHERE member_id = $memberId` (SELECT), `WHERE member_id = $memberId` (DELETE), `WHERE id = $memberId` (DELETE) | `$memberId = $_GET['id']` → 3 raw queries | `delete_members.php:33 → :35,:39,:46` |
| 3 | `$_GET['membershipTypeId']` | `WHERE id = $membershipTypeId` (SELECT) | `$membershipTypeId = $_GET['membershipTypeId']` → raw query | `get_membership_amount.php:10 → :14` |

**Authenticated SQL Injection:**

| # | Source | Sink | Flow | File:Line |
|---|---|---|---|---|
| 4 | `$_POST['email']` | `WHERE email = '$email'` | `$email = $_POST['email']` → `"... WHERE email = '$email' AND password = '...'` | `index.php:6 → :14` |
| 5 | `$_GET['id']` | `WHERE id = $memberId` (SELECT + UPDATE) | `$memberId = $_GET['id']` → SELECT and POST UPDATE reuse same var | `edit_member.php:15 → :17,:59` |
| 6 | `$_POST['fullname']` | `VALUES ('$fullname', ...)` INSERT | All 10 POST fields → raw INSERT string | `add_members.php:23-32 → :47` |
| 7 | `$_POST['fullname']` through all POST fields | `SET fullname='$fullname',...` UPDATE | All 9 POST fields → raw UPDATE string | `edit_member.php:37-45 → :59` |
| 8 | `$_GET['id']` | `WHERE id = $memberId` | `$memberId = $_GET['id']` → `"SELECT * FROM members WHERE id = $memberId"` | `memberProfile.php:10 → :15` |
| 9 | `$_POST['membershipType']` | `VALUES ('$membershipType', ...)` INSERT | Direct concatenation | `add_type.php:12 → :15` |
| 10 | `$_GET['id']` | `WHERE id = $edit_id` SELECT | Null-coalesced `$edit_id = $_GET['id'] ?? null` → raw query | `edit_type.php:27 → :28` |
| 11 | `$_POST['membershipType']`, `$_POST['membershipAmount']`, `$_POST['edit_id']` | `SET type='$membershipType',...WHERE id = $id` UPDATE | All 3 POST fields → raw UPDATE | `edit_type.php:12-15 → :17` |
| 12 | `$_GET['id']` | `WHERE id = $delete_id` DELETE | `$delete_id = $_GET['id'] ?? null` → raw DELETE | `delete_membership.php:10 → :12` |
| 13 | `$_GET['id']` | SELECT + UPDATE + INSERT with `$memberId` and `$totalAmount` | `$memberId = $_GET['id']`; `$totalAmount = $_POST['totalAmount']` → raw queries | `renew.php:15,29-31 → :17,:34,:39` |
| 14 | `$_POST['fromDate']`, `$_POST['toDate']` | `BETWEEN '$fromDate' AND '$toDate'` SELECT | Date fields → raw BETWEEN clause | `report.php:10-11 → :16` |
| 15 | `$_POST['fromDate']`, `$_POST['toDate']` | `BETWEEN '$fromDate' AND '$toDate'` SELECT | Date fields → raw BETWEEN clause | `revenue_report.php:10-11 → :17` |
| 16 | `$_POST['systemName']`, `$_POST['currency']` | `SET system_name='$systemName',...` UPDATE | Direct concatenation | `settings.php:10-11 → :21,:33` |

### Unrestricted File Upload Sources (RCE via PHP Webshell)

| # | Source | Sink | Validation | Stored At | File:Line |
|---|---|---|---|---|---|
| 1 | `$_FILES['photo']` | `move_uploaded_file($tmp, 'uploads/member_photos/' . $uniquePhotoName)` | None (extension extracted with `pathinfo()` and used verbatim) | `uploads/member_photos/{timestamp}_{uniqid}.{ext}` | `add_members.php:36-40` |
| 2 | `$_FILES['photo']` | `move_uploaded_file($tmp, 'uploads/member_photos/' . $uniquePhotoName)` | None | `uploads/member_photos/{basename}_{time}.{ext}` | `edit_member.php:48-54` |
| 3 | `$_FILES['logo']['name']` | `move_uploaded_file($tmp, 'uploads/' . $logoName)` | None — original filename used as-is, no `basename()` call | `uploads/{original_filename}` (path traversal risk) | `settings.php:14-20` |

### Open Redirect / HTTP Header Injection Sources

| # | Source | Sink | Flow | File:Line |
|---|---|---|---|---|
| 1 | `$_SERVER['HTTP_REFERER']` | `header("Location: " . $_SERVER['HTTP_REFERER'])` | Attacker-controlled `Referer` header → `Location:` response header | `delete_membership.php:15` (success) and `:22` (else branch) |

### Path Traversal Sources

| # | Source | Sink | Flow | File:Line |
|---|---|---|---|---|
| 1 | `$_FILES['logo']['name']` | `move_uploaded_file($tmp, 'uploads/' . $logoName)` | `$logoName = $_FILES['logo']['name']` used without `basename()` — `../index.php` as filename would overwrite files outside `uploads/` | `settings.php:14-20` |

### Stored XSS Injection Sources (for XSS Specialist)

**All database fields that echo to HTML without `htmlspecialchars()` — universal absence of output encoding:**

| Source Field | Written By | Read/Echoed By | HTML Context | File:Line (sink) |
|---|---|---|---|---|
| `members.fullname` | `add_members.php POST`, `edit_member.php POST` | `manage_members.php`, `memberProfile.php`, `dashboard.php`, `print_membership_card.php`, `renew.php`, `list_renewal.php`, `report.php` | HTML body, attribute values | Multiple (see pre-recon §9) |
| `members.contact_number` | `add_members.php POST` | `manage_members.php`, `memberProfile.php`, `list_renewal.php` | HTML body | Multiple |
| `members.email` | `add_members.php POST` | `manage_members.php`, `memberProfile.php`, `report.php` | HTML body | Multiple |
| `members.address` | `add_members.php POST` | `memberProfile.php`, `manage_members.php`, `print_membership_card.php` | HTML body | Multiple |
| `members.country`, `postcode`, `occupation` | `add_members.php POST` | `memberProfile.php` | HTML body | `memberProfile.php:129-131` |
| `settings.system_name` | `settings.php POST` | `includes/header.php` (`<title>`), `includes/sidebar.php` | HTML body (ALL pages) | `includes/header.php:13`, `includes/sidebar.php:28` |
| `settings.currency` | `settings.php POST` | `revenue_report.php`, `view_type.php` | HTML body | Multiple |
| `membership_types.type` | `add_type.php POST`, `edit_type.php POST` | `view_type.php`, `memberProfile.php`, `manage_members.php` | HTML body | Multiple |
| `$_GET['id']` (reflected) | N/A | `edit_type.php` hidden input | HTML attribute (`value=""`) | `edit_type.php:72` |
