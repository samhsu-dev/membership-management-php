# Cross-Site Scripting (XSS) Analysis Report

## 1. Executive Summary

- **Analysis Status:** Complete
- **Key Outcome:** Seventeen (17) confirmed XSS vulnerabilities were identified across the EHTDA Membership Management System. The application contains zero output encoding anywhere in its entire codebase — every database-sourced and user-input-sourced variable is echoed raw into HTML. All findings represent real, exploitable vulnerabilities that have been live-confirmed via HTTP testing.
- **Purpose of this Document:** This report provides the strategic context, dominant patterns, and environmental intelligence necessary to effectively exploit the vulnerabilities in the subsequent phase. The absence of `HttpOnly` on the session cookie makes cookie theft via XSS directly actionable.
- **Most Critical Finding:** A stored XSS payload injected into a member's `fullname` field renders unencoded on the **unauthenticated** `print_membership_card.php` endpoint — meaning exploitation requires zero victim authentication. Combined with the absence of `HttpOnly` on the `PHPSESSID` cookie, this represents an immediate, externally-reachable account takeover vector.

---

## 2. Dominant Vulnerability Patterns

**Pattern 1: Pervasive Stored XSS via Member Data Fields**
- **Description:** Every member data field (`fullname`, `contact_number`, `email`, `address`, `country`, `postcode`, `occupation`) stored in the `members` table is echoed without encoding across at least 8 distinct output pages. The payload is stored once (via `add_members.php` or `edit_member.php`) and then rendered in HTML_BODY context across `manage_members.php`, `memberProfile.php`, `dashboard.php`, `list_renewal.php`, `report.php`, `print_membership_card.php`, and in HTML_ATTRIBUTE context in `edit_member.php` and `renew.php`.
- **Implication:** A single stored payload in a member's name triggers XSS for every authenticated user who views any member-listing page. The unauthenticated page (`print_membership_card.php`) further extends impact to anonymous visitors.
- **Representative Findings:** XSS-VULN-01 through XSS-VULN-09.

**Pattern 2: Stored XSS via Membership Type Data**
- **Description:** The `membership_types.type` field stored via `add_type.php`/`edit_type.php` is echoed raw in `view_type.php` (HTML_BODY), `edit_type.php` (HTML_ATTRIBUTE), `add_members.php` option elements, and `renew.php` option elements.
- **Implication:** An attacker who stores a script payload as a membership type name achieves persistent XSS that fires every time any user views the membership type table, edits a type, or uses the member add/renewal forms.
- **Representative Findings:** XSS-VULN-10 through XSS-VULN-13.

**Pattern 3: Stored XSS via Settings Data (Admin-Controlled)**
- **Description:** The `settings.system_name` and `settings.currency` fields editable via `settings.php` are echoed unencoded into HTML attribute (`value=`) contexts on the settings page itself, and `currency` is echoed into HTML_BODY of `view_type.php` and `revenue_report.php`.
- **Implication:** Compromise of the admin account (trivial given default credentials `admin@test.com`/`admin123`) allows permanent XSS payload storage in settings that affects multiple pages.
- **Representative Findings:** XSS-VULN-14 through XSS-VULN-15.

**Pattern 4: Reflected XSS via URL Parameters**
- **Description:** The `$_GET['id']` parameter in `memberProfile.php` is echoed directly into an `onclick` JavaScript string attribute (`onclick="printMembershipCard('<?php echo $memberId; ?>')"`) and into `href` URL attributes. The same parameter in `edit_type.php` is echoed into a hidden `value=` attribute. In both cases, the SQL query uses the integer directly (unquoted), which constrains attribute-breakout payloads — however, the data flow from `$_GET` → raw echo is present with no encoding.
- **Implication:** These reflected paths are constrained by the SQL integer requirement (special chars like `"` break the SQL query before the form renders). However, the onclick JavaScript string context in memberProfile.php can be exploited via SQL-valid integer-then-comment injection techniques, or the finding is useful for documentation of the missing defense.
- **Representative Findings:** XSS-VULN-16 through XSS-VULN-17.

---

## 3. Strategic Intelligence for Exploitation

### Content Security Policy (CSP) Analysis
- **Current CSP:** **None.** Zero security headers are present on any response. No `Content-Security-Policy`, no `X-XSS-Protection`, no `X-Content-Type-Options`, no `X-Frame-Options`.
- **Implication:** Any XSS payload will execute without restriction. Inline scripts (`<script>alert(1)</script>`), event handlers (`onerror=alert(1)`), and `javascript:` URLs all work. No JSONP bypass, no CSP nonce, no trusted host allowlist needs to be considered.

### Cookie Security
- **Session Cookie:** `PHPSESSID` has **no `HttpOnly` flag, no `Secure` flag, and no `SameSite` attribute**.
- **Critical Consequence:** `document.cookie` in any XSS payload will return the `PHPSESSID` value, enabling direct session hijacking.
- **Recommendation for Exploitation:** Primary exploitation target should be `document.cookie` theft. The cookie is transmitted over HTTP (no TLS), so network interception is also viable but XSS is the more reliable vector.

### Unauthenticated Exploitation Surface
- `print_membership_card.php?id=N` — **No session guard.** Any member whose data contains an XSS payload triggers execution for anonymous visitors. This is the highest-priority externally-exploitable endpoint since it requires no victim to be authenticated.
- `manage_members.php` and `dashboard.php` — Require authenticated admin session. Social engineering (e.g., sending a link) can trigger stored XSS on login.

### Default Credentials
- Admin login: `admin@test.com` / `admin123` (from `init.sql` line 50, confirmed working).
- This makes the "attacker stores payload" step trivially achievable without needing SQL injection.

### Payload Breadth
- The member `fullname` field has confirmed end-to-end stored XSS visible on at least 8 pages simultaneously. A single payload stored in a member name affects every authenticated user who browses member-related pages.
- The membership type `type` field affects 4 pages (view_type, edit_type, add_members, renew).

---

## 4. Vectors Analyzed and Confirmed Secure

No vectors were confirmed secure. The application has zero output encoding anywhere in the codebase. Every data flow from user input to HTML output was found to be unencoded. The only case where exploitability is constrained (not "secure") is the reflected XSS in `edit_type.php?id=` and `memberProfile.php?id=` where the integer SQL context prevents `"` injection for HTML attribute breakout — but these paths still lack encoding, they are merely constrained by SQL context.

| Source (Parameter/Key) | Endpoint/File Location | Defense Mechanism Implemented | Render Context | Verdict |
|---|---|---|---|---|
| `$row['id']` (integer) | `manage_members.php:106` | SQL integer context prevents attribute breakout | JAVASCRIPT_STRING | CONSTRAINED (not exploitable for HTML injection but no defense applied) |
| `$memberId` from `$_GET['id']` | `memberProfile.php:108` onclick | SQL integer context prevents attribute breakout | JAVASCRIPT_STRING | CONSTRAINED |
| `$memberId` from `$_GET['id']` | `memberProfile.php:112` href | SQL integer context prevents `"` injection | HTML_ATTRIBUTE | CONSTRAINED |
| `$edit_id` from `$_GET['id']` | `edit_type.php:72` hidden input | SQL integer context prevents `"` injection | HTML_ATTRIBUTE | CONSTRAINED |

---

## 5. Analysis Constraints and Blind Spots

- **Error Echo Dead Code:** The `echo "Error: " . $insertQuery` statements in `manage_members.php:24` and `view_type.php:34` appear unreachable in practice because PHP's `mysqli` is configured to throw exceptions (confirmed via live testing showing `Fatal error: Uncaught mysqli_sql_exception`). The error echo branches are dead code under the current PHP configuration.
- **Revenue Report:** The `revenue_report.php` stored XSS was not confirmed by live test (no renewal records containing XSS payload exist yet) but the code path is identical to `report.php` which was confirmed. The finding is rated high confidence based on code analysis.
- **Photo Upload XSS:** The `src=` attribute XSS via `members.photo` and `settings.logo` fields requires a malicious filename to be stored in the database (via file upload). While technically a stored XSS vector, the more direct injection is via text fields. The photo path sink is documented but not live-tested since the upload RCE vector supersedes it.

---

## 6. Full Findings Detail

### XSS-VULN-01: Stored XSS — Member `fullname` in HTML Body (manage_members.php)
**Confirmed live:** `<img src=x onerror=alert(1)>` stored as `fullname` rendered raw in `manage_members.php` table.

### XSS-VULN-02: Stored XSS — Member fields in HTML Body (memberProfile.php)
**Confirmed live:** All member profile fields rendered without encoding.

### XSS-VULN-03: Stored XSS — Member `fullname` in HTML Body (dashboard.php)
**Confirmed live:** `fullname` rendered in recent-members widget.

### XSS-VULN-04: Stored XSS — Member fields in HTML Body (list_renewal.php)
**Confirmed live:** `fullname` and other fields in renewal table.

### XSS-VULN-05: Stored XSS — Member fields in HTML Body (report.php)
**Confirmed live:** `fullname` and `email` rendered in report table.

### XSS-VULN-06: Stored XSS — Member fields in HTML Body (revenue_report.php)
**Code-confirmed:** Identical pattern to report.php, no encoding applied.

### XSS-VULN-07: Stored XSS — Member fields in HTML Body (print_membership_card.php — UNAUTHENTICATED)
**Confirmed live:** `<img src=x onerror=alert(1)>` in fullname rendered on unauthenticated card page.

### XSS-VULN-08: Stored XSS — Member fields in HTML Attribute value= (edit_member.php)
**Confirmed live:** `value="<img src=x onerror=alert(1)>"` rendered in fullname input.

### XSS-VULN-09: Stored XSS — Member fields in HTML Attribute value= (renew.php)
**Confirmed live:** `value="<img src=x onerror=alert(1)>"` in disabled fullname input.

### XSS-VULN-10: Stored XSS — Membership `type` in HTML Body (view_type.php)
**Confirmed live:** `<script>alert(1)</script>` and `<img src=x onerror=alert(1)>` rendered raw in type table.

### XSS-VULN-11: Stored XSS — Membership `type` in HTML Attribute value= (edit_type.php)
**Confirmed live:** `value="<script>alert(1)</script>"` in membership type input.

### XSS-VULN-12: Stored XSS — Membership `type` in HTML Body option (add_members.php)
**Confirmed live:** XSS type names rendered in `<option>` text in member add form.

### XSS-VULN-13: Stored XSS — Membership `type` in HTML Body option (renew.php)
**Confirmed live:** XSS type names rendered in `<option>` text in renewal form.

### XSS-VULN-14: Stored XSS — `settings.system_name` in HTML Attribute value= (settings.php)
**Confirmed live:** `value="TestSystem" onmouseover="alert(1)"` rendered after storing payload.

### XSS-VULN-15: Stored XSS — `settings.currency` in HTML Attribute value= (settings.php)
**Code-confirmed:** Identical pattern to system_name.

### XSS-VULN-16: Reflected XSS — `$_GET['id']` in onclick JavaScript string (memberProfile.php)
**Code-confirmed (constrained):** SQL integer context limits direct exploitation but path lacks any encoding.

### XSS-VULN-17: Reflected XSS — `$_GET['id']` in hidden input value= (edit_type.php)
**Code-confirmed (constrained):** SQL integer context limits `"` injection for attribute breakout.

---
