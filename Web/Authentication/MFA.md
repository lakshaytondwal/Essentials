# Multi-Factor Authentication

## 1. OTP Leakage

OTP leakage in an XHR response usually stems from flawed 2FA design and insecure coding practices. The most common causes are:

* **Server-side mishandling of responses:** The backend validates the OTP but mistakenly includes it in the API response instead of returning only a success or failure status.
* **Poor security awareness:** Developers prioritize functionality and overlook the risk of exposing sensitive data in responses.
* **Debug data left in production:** OTPs or validation details are included for testing purposes and not removed before deployment.

At its core, this is a failure of secure response design: sensitive secrets should never be echoed back to the client, under any circumstance.

### Exploiting OTP Leakage

![login](/img/MFA/1.png)

![login](/img/MFA/2.png)

Once on the MFA page, the application triggers an XHR request to the `/token` endpoint. The response to this request has a size of 16 bytes, indicating a minimal payload returned by the server.

![login](/img/MFA/3.png)

We can use that code as an OTP.

---

## 2. Logic Flaw or Insecure Coding?

In some applications, flawed logic or insecure implementation allows access to protected areas (such as the dashboard) without fully completing authentication. An attacker may bypass the 2FA step and gain access without submitting a valid OTP.

This typically occurs due to improper session management, weak access control enforcement, or backend logic that fails to strictly require successful 2FA verification before granting access to sensitive resources.

### Exploiting

![login](/img/MFA/4.png)

![login](/img/MFA/5.png)

Instead of entering the OTP, the attacker might try to manipulate the URL or bypass the OTP step altogether. For example, the attacker might try to directly access the dashboard URL (e.g., `http://mfa.thm/labs/second/dashboard`) without completing the required authentication steps.

If the application doesn't properly check the session state or enforce 2FA or the application's logic is flawed, the attacker might gain access to the dashboard.

![login](/img/MFA/6.png)

### Diving deeper into the code

The below code is part of the code that is used in the `/mfa` page. As you can see, the `$_SESSION['authenticated']` is issued after the completion of the 2FA process.

```php
# Function that verifies the submitted 2FA token
function verify_2fa_code($code) {
    if (!isset($_SESSION['token']))
    return false;

    return $code === $_SESSION['token'];
}

# Function called in the /mfa page
if (verify_2fa_code($_POST['code'])) { #If successful, the user will be redirected to the dashboard.
    $_SESSION['authenticated'] = true; # Session that is used to check if the user completed the 2FA
    header('Location: ' . ROOT_DIR . '/dashboard');
    return;
}
```

Considering the above implementation is secure, some instances of dangling issuance of the `$_SESSION['authenticated']` after the first step of authentication will bypass the above code, as shown below.

```php
function authenticate($email, $password){
  $pdo = get_db_connection();
  $stmt = $pdo->prepare("SELECT `password` FROM users WHERE email = :email");
  $stmt->execute(['email' => $email]);
  $user = $stmt->fetch(PDO::FETCH_ASSOC);

  return $user && password_verify($password, $user['password']);
}

if (authenticate($email, $password)) {
    $_SESSION['authenticated'] = true; # This flag should only be issued after the MFA completion
    $_SESSION['email'] = $_POST['email'];
    header('Location: ' . ROOT_DIR . '/mfa');
    return;
}
```

Since the application's dashboard only checks for the value of `$_SESSION['authenticated']`, whether it's true or false, the attacker can easily bypass the 2FA page, considering the attacker has prior knowledge of the application's endpoints.

To remediate this vulnerability, the cookie or session that is used in authentication checks should be split into two parts. The first part is the one that sets the session after successful username and password verification; the sole purpose of this session is to submit a 2FA token. The second session should only be after the OTP is validated.

---

## 3. Beating the Auto-Logout Feature

In some applications, failing the 2FA challenge forces the user back to the initial login step (username and password). This behavior is typically implemented as a defense against brute-force attacks on the OTP mechanism.

By requiring full reauthentication after repeated or failed OTP attempts, the application reduces the risk of automated guessing and ensures that only a legitimately authenticated user can continue attempting the second authentication factor.

### Common Reasons for This Behavior

* **Session Invalidation:** After a failed 2FA attempt, the application may invalidate the user’s session as a security measure. This forces the user to restart the authentication process from the beginning.

* **Rate-Limiting and Lockout Policies:** To prevent brute-force attacks against the OTP mechanism, the application may enforce rate-limiting or temporary lockout controls. Once a defined threshold of failed attempts is reached, the user is redirected to the initial login step.

* **Security-Driven Redirection:** Some systems are intentionally designed to redirect users back to the login page after multiple failed 2FA attempts. This ensures credentials are revalidated before another 2FA attempt is allowed.

### Exploitation

The application hosted at `http://mfa.thm/labs/third` automatically logs the user out after a failed 2FA attempt. Each time a user logs in, the server generates a new 4-digit PIN for verification.

> **Note:** In real-world implementations, OTP values typically span from 0000 to 9999 (4 digits) and more commonly use 6-digit codes (000000–999999). The reduced range in this lab environment is intentional, allowing brute-force testing to complete in a reasonable timeframe for demonstration purposes.

To automate the authentication cycle and repeatedly handle forced logouts, a custom script such as [MFAbyepass.py](/Scripting/Python/Samples/MFAbyepass.py) can be used. The script programmatically performs the following sequence:

* Initiates a fresh session
* Authenticates with valid credentials
* Submits an OTP value
* Detects server redirects
* Repeats the process if the session is invalidated

By recreating the session after each failed attempt and programmatically handling redirects, the script eliminates manual reauthentication and enables efficient testing of the 2FA enforcement logic.

This approach highlights how automation can be used to evaluate whether session management and 2FA validation are properly synchronized within an application’s authentication flow.

```bash
user@tryhackme$ $ python3 MFAbyepass.py
Logged in successfully.
Trying OTP: 1337
DEBUG: OTP submission response status code: 302
Unsuccessful OTP attempt, redirected to login page. OTP: 1337
Logged in successfully.
Trying OTP: 1337
DEBUG: OTP submission response status code: 302
Unsuccessful OTP attempt, redirected to login page. OTP: 1337
Logged in successfully.
Trying OTP: 1337
DEBUG: OTP submission response status code: 302
Session cookies: {'PHPSESSID': '57burqsvce3odaif2oqtptbl13'}
```

Once a successful OTP submission occurs, the server issues a valid session cookie such as: `PHPSESSID=57burqsvce3odaif2oqtptbl13`

This `PHPSESSID` represents a fully authenticated session tied to the dashboard access.

At this point, the cookie can be reused in subsequent requests to access protected resources (e.g., `/labs/third/dashboard`) without repeating the login and 2FA steps, as long as the session remains valid and unexpired.

In practical terms, this means:

* The session token can be imported into a browser or intercepting proxy.
* Any request containing this valid `PHPSESSID` will be treated as authenticated.
* If the server does not properly bind the session to additional security controls (IP binding, user-agent validation, or strict session regeneration policies), the session can be reused until timeout or invalidation.

This reinforces a critical principle in authentication security: once issued, a session identifier becomes the real key. Protecting session integrity is just as important as protecting credentials or OTP values, because possession of a valid session cookie often equals full account access.

---
