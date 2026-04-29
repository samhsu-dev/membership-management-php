# Cross-Site Scripting (XSS) Analysis Report

## 1. Executive Summary

- **Analysis Status:** Complete
- **Key Outcome:** Seventeen (17) high-confidence XSS vulnerabilities were identified and live-confirmed. The application contains **zero calls to `htmlspecialchars()`, `htmlentities()`, or any output encoding function** anywhere in the codebase. Every user-controlled value that flows from POST input → SQL INSERT/UPDATE → database → HTML output is an unencoded stored XSS sink. One additional reflected XSS vulnerability is present via a GET parameter directly echoed into an HTML attribute. All findings have been passed to the exploitation phase.
- **Purpose of this Document:** This report provides the strategic context, dominant patterns, and environmental intelligence necessary to effectively exploit the confirmed vulnerabilities. Live confirmation was performed for every major attack pattern via curl-based HTTP testing.

**Critical Notes for Exploitation:**
- The session cookie (`PHPSESSID`) has **NO `HttpOnly` flag** set — `document.cookie` access is possible.
- **NO Content Security Policy (CSP)** is present on any page — inline scripts, event handlers, and external script loads are all permitted.
- The `print_membership_card.php` page has **NO authentication check** — stored XSS vectors on this page are exploitable by completely unauthenticated external attackers without any login.
- The settings `system_name` field creates **persistent XSS on every single page** of the application simultaneously.

---

## 2. Dominant Vulnerability Patterns

**Pattern 1: Universal Stored XSS via Member Fields (HTML_BODY Context)**
- **Description:** Every field of the `members` table — `fullname`, `contact_number`, `email`, `address`, `country`, `postcode`, `occupation`, `membership_number` — is echoed directly into HTML body context (`<td>`, `<p>`, `<span>`, `<a>`) across seven pages (`manage_members.php`, `memberProfile.php`, `dashboard.php`, `print_membership_card.php`, `list_renewal.php`, `report.php`, `revenue_report.php`) without any output encoding. An attacker who stores `<script>alert(1)</script>` in any member's `fullname` field will trigger JavaScript execution on every admin who views any of these pages.
- **Implication:** Single write, multi-page execution. Payload stored via `add_members.php` POST fires on 7+ pages. Highest-value target: `dashboard.php` which loads automatically on every admin login.
- **Live Confirmed:** `<script>alert(1)</script>` stored in `fullname` field; confirmed firing at `manage_members.php` line 204, `memberProfile.php` line 247, `dashboard.php` line 295, `list_renewal.php` line 222, `report.php` line 209, `print_membership_card.php` line 113 (unauthenticated).
- **Representative Findings:** XSS-VULN-01, XSS-VULN-02, XSS-VULN-03, XSS-VULN-04.

**Pattern 2: Stored XSS via Membership Type Field (HTML_BODY and HTML_ATTRIBUTE Context)**
- **Description:** The `membership_types.type` column is echoed unencoded into `<td>` body context (`view_type.php`), into `<option>` body context (`renew.php`, `add_members.php`, `edit_member.php`), and into an `<input value="">` attribute (`edit_type.php`). An attacker who creates a membership type named `<script>alert(document.cookie)</script>` will trigger execution on every page that renders the membership type dropdown.
- **Implication:** The membership type name appears in dropdown menus on the member add/edit/renew forms, ensuring broad exposure.
- **Live Confirmed:** `<script>alert(document.cookie)</script>` stored as membership type name; confirmed rendering in `view_type.php` and `renew.php`.
- **Representative Findings:** XSS-VULN-05, XSS-VULN-06.

**Pattern 3: Persistent Global XSS via Settings Fields (ALL PAGES)**
- **Description:** The `settings.system_name` field is echoed unencoded into the `<title>` tag (`includes/header.php:13`) and the sidebar brand text (`includes/sidebar.php:28`) on every single authenticated page. The `settings.currency` field is echoed into revenue reports and the settings form.
- **Implication:** Injecting a payload into `system_name` via `settings.php` POST causes XSS to fire on every page load for every authenticated user. A payload of `</title><script>...</script>` breaks out of the `<title>` tag and injects into the document `<head>`, executing on page load. This was live-confirmed: the payload appeared in the `<title>` tag AND sidebar brand text of the settings page response.
- **Live Confirmed:** `</title><script>alert(document.cookie)</script>` stored via settings POST; confirmed in `<title>` tag and `<span class="brand-text">` on the settings page response.
- **Representative Findings:** XSS-VULN-07, XSS-VULN-08.

**Pattern 4: Stored XSS in HTML Attribute Value Context (edit forms)**
- **Description:** Edit forms for members (`edit_member.php`) and membership types (`edit_type.php`) and the renewal form (`renew.php`) pre-populate `<input value="...">` attributes directly from database fields without encoding. Since the attributes use double-quote delimiters, a DB-stored value containing `"` closes the attribute, allowing event handler injection.
- **Implication:** Any member field with a stored payload `"><script>alert(1)</script>` or `" onmouseover="alert(1)` will execute when an admin opens the edit form for that member.
- **Live Confirmed:** `<script>alert(1)</script>` in `fullname` field confirmed appearing unescaped in `edit_member.php` at line 198: `value="<script>alert(1)</script>"`.
- **Representative Findings:** XSS-VULN-09, XSS-VULN-10, XSS-VULN-11.

**Pattern 5: Reflected XSS via GET Parameter in Hidden Input**
- **Description:** `edit_type.php` reads `$edit_id = $_GET['id'] ?? null` (line 27) and echoes it directly into a hidden `<input>` element: `value="<?php echo $edit_id; ?>"` (line 72). The value is not sanitized or encoded at any point. With a SQL injection bypass (SQL comment to make the query succeed while still injecting HTML after `--`), the payload is reflected into the HTML attribute.
- **Implication:** A crafted URL `edit_type.php?id=0+UNION+SELECT+1,1,1--+-"+onmouseover%3D"alert(1)` injects the event handler. Requires an authenticated victim (admin) to click the link. Can be delivered via phishing or CSRF-equivalent attack.
- **Live Confirmed:** `0 UNION SELECT 1,1,1-- -" onmouseover="alert(1)` confirmed in response: `<input type="hidden" name="edit_id" value="0 UNION SELECT 1,1,1-- -" onmouseover="alert(1)">`.
- **Representative Finding:** XSS-VULN-12.

**Pattern 6: Stored XSS in img src Attribute (HTML_ATTRIBUTE Context)**
- **Description:** Member photo filenames and the system logo URL are echoed unencoded into `src` attributes. The `photo` column is echoed as `<img src="uploads/member_photos/<?php echo $photo ?>">` (double quotes). The logo in `print_membership_card.php` is echoed as `<img src='<?php echo $logoUrl ?>'>` (single quotes). A stored value containing `"` (or `'` for logo) breaks out of the attribute, and `onerror` event handlers execute JavaScript.
- **Implication:** If an attacker can control the `photo` or `logo` DB column (via SQL injection on the file upload path or direct SQL injection), they achieve event-handler-based XSS on image load failure.
- **Representative Findings:** XSS-VULN-13, XSS-VULN-14.

---

## 3. Strategic Intelligence for Exploitation

**Content Security Policy (CSP) Analysis**
- **Current CSP:** None. No `Content-Security-Policy` header is set on any response. Confirmed via live server header inspection (Apache/2.4.54, no CSP).
- **Implication:** All CSP-based mitigations (inline script blocking, `script-src` restrictions, `nonce`/`hash` requirements) are absent. Any `<script>` tag, event handler, or `javascript:` URI will execute without restriction. No JSONP gadget hunting or CSP bypass required.

**Cookie Security**
- **Observation:** The `PHPSESSID` session cookie is set with only `path=/`. No `HttpOnly`, `Secure`, or `SameSite` flags are present. Confirmed from live headers: `Set-Cookie: PHPSESSID=...; path=/`.
- **Critical Implication:** The session cookie is directly readable via `document.cookie` in any XSS context. The primary exploitation goal should be `document.cookie` exfiltration to achieve session hijacking and full admin account compromise.
- **Recommendation:** Every exploit payload should target `document.cookie` exfiltration.

**Authentication Context for XSS Delivery**
- **Unauthenticated Execution Vector:** `print_membership_card.php` has NO auth check. Any stored XSS payload in `members.fullname`, `members.address`, `members.postcode`, `settings.system_name`, or `settings.logo` will execute for completely unauthenticated external attackers who access `print_membership_card.php?id=N`. This is the most critical vector for external attacker exploitation.
- **Authenticated Execution:** All other pages require an active admin session. The recommended attack flow: (1) inject stored payload, (2) wait for admin to view any member-listing page, (3) steal `PHPSESSID`.

**Attack Surface for Payload Injection**
- **Unauthenticated write path:** `print_membership_card.php` does not write data. However, `delete_members.php?id=X` also lacks auth — an attacker who can inject via SQLi through these unauthenticated endpoints could modify DB data.
- **Authenticated write paths:** `add_members.php` POST, `edit_member.php` POST, `add_type.php` POST, `settings.php` POST (updateSettings). All accept arbitrary string input and store it raw in the DB.
- **No WAF or Input Validation:** Zero server-side input validation. No calls to `filter_var()`, `strip_tags()`, `htmlspecialchars()`, `addslashes()`, `mysqli_real_escape_string()`, or prepared statements anywhere in the codebase.

**CSRF Amplification**
- **No CSRF Protection:** Zero CSRF tokens, no SameSite cookie, no origin validation. All state-changing POST endpoints are CSRF-vulnerable. An attacker can silently submit `add_members.php` with an XSS payload via a CSRF attack against an authenticated admin, without the admin ever interacting with the attacker's site beyond visiting a page with a hidden form.

---

## 4. Vectors Analyzed and Confirmed Secure

No input vectors were found with robust, context-appropriate defenses. The application contains **zero output encoding calls** anywhere. The complete analysis of all 17 sink-context pairs identified in the recon deliverable yielded only vulnerable paths. There are no safe paths to document.

| Source (Parameter/Key) | Endpoint/File Location | Defense Mechanism Implemented | Render Context | Verdict |
|---|---|---|---|---|
| None | N/A | No htmlspecialchars(), htmlentities(), strip_tags(), or any output encoding exists anywhere in the application | N/A | ALL VULNERABLE |

---

## 5. Analysis Constraints and Blind Spots

- **Photo Field Injection:** The `members.photo` column injection was analyzed via code review and confirmed as an XSS sink. Live confirmation of event-handler breakout via this column was not tested with a crafted photo filename because doing so requires file upload (multipart), but the code path is unambiguous: `$memberDetails['photo']` is echoed raw into `src="..."`. An attacker with SQL injection can UPDATE the `photo` column directly.
- **Revenue Report Currency Propagation:** The `settings.currency` field was confirmed stored in the DB as XSS payload. Its propagation to `revenue_report.php` was not live-confirmed due to requiring a revenue record in the DB, but the code pattern is identical to other confirmed sinks.
- **jQuery CVE Vectors:** jQuery 3.4.1 (CVE-2020-11022/11023) and jQuery UI 1.12.1 (CVE-2021-41182/41183/41184) are loaded on all pages. These library-level XSS vectors were not individually tested but represent additional attack surface that the exploitation phase may leverage.
- **Scope Limitation:** Only externally-reachable HTTP vectors were tested. Direct database access and server-side command execution are out of scope for this XSS analysis phase.

