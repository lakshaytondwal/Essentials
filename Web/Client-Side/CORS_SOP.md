# **SOP & CORS**

> SOP blocks cross-origin data access. CORS selectively allows it via server-defined headers enforced by the browser.

## **1. Same-Origin Policy (SOP)**

**Definition:**
SOP restricts how a web page from one origin can interact with resources from another origin.

**Origin =** `scheme (protocol) + hostname + port`

### **Same origin only if all match:**

* Protocol (http vs https)
* Domain (example.com vs api.example.com)
* Port (80 vs 8080)

### **Examples**

* `https://test.com:80` → same as `https://test.com:80`
* `https://test.com` vs `https://test.com:8080` → different (port)
* `http://test.com` vs `https://test.com` → different (protocol)

## **2. What SOP Actually Enforces**

### **Allowed**

* Sending cross-origin requests
* Loading resources (images, scripts, iframes)

### **Blocked**

* Reading response data via JavaScript (fetch, XHR)
* Accessing DOM across origins

### **Core Rule**

> Cross-origin requests are allowed, but reading responses is restricted.

## **3. Why SOP Exists**

Prevents:

* Malicious sites from reading sensitive data from another origin
* Unauthorized access to user data (sessions, APIs, personal info)

## **4. Important Clarifications**

* SOP does NOT block requests
* SOP blocks **access to responses**
* Same domain ≠ same origin (protocol + port matter)

## **5. CORS (Cross-Origin Resource Sharing)**

**Definition:**
CORS is a mechanism that allows servers to relax SOP using HTTP response headers.

### **Key Idea**

> Server declares policy, browser enforces it.

## **6. Core CORS Headers**

### **Access-Control-Allow-Origin (ACAO)**

```txt
Access-Control-Allow-Origin: https://example.com
```

* Defines which origin can read the response

Values:

* Specific origin → secure
* `*` → allow all (unsafe for sensitive data)

### **Access-Control-Allow-Methods**

```txt
Access-Control-Allow-Methods: GET, POST, PUT
```

* Allowed HTTP methods

### **Access-Control-Allow-Headers**

```txt
Access-Control-Allow-Headers: Content-Type, Authorization
```

* Allowed custom headers

### **Access-Control-Allow-Credentials**

```txt
Access-Control-Allow-Credentials: true
```

* Allows cookies/auth data in cross-origin requests

**Important:**

* Cannot use with `ACAO: *`
* Must specify exact origin

### **Access-Control-Max-Age**

```txt
Access-Control-Max-Age: 3600
```

* Caches preflight response

## **7. Simple vs Preflight Requests**

### **Simple Requests**

Conditions:

* Method: GET, HEAD, POST
* Content-Type:

  * `application/x-www-form-urlencoded`
  * `multipart/form-data`
  * `text/plain`
* No custom headers

Behavior:

* Sent directly with `Origin` header
* Browser checks ACAO in response

**Important:**

* Cookies may be sent automatically (if allowed by browser policy)

### **Preflight Requests (OPTIONS)**

Triggered when:

* Method is PUT, DELETE, etc.
* Custom headers used
* Non-standard Content-Type

#### **Flow**

* 1 Browser sends:

```txt
OPTIONS /api
Origin: https://attacker.com
Access-Control-Request-Method: POST
Access-Control-Request-Headers: Authorization
```

* 2 Server responds:

```txt
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Methods: POST
Access-Control-Allow-Headers: Authorization
```

* 3 If valid → actual request sent
* 4 If invalid → request blocked

## **8. CORS Request Flow**

1. Browser sends request with `Origin`
2. Server processes request normally
3. Server adds CORS headers
4. Browser decides:

   * If allowed → JS can read response
   * If not → response blocked

## **9. ACAO Configurations**

### **Single Origin**

```txt
Access-Control-Allow-Origin: https://example.com
```

* Secure, recommended

### **Multiple Origins (Dynamic)**

* Server checks against allowlist
* Returns matching origin

### **Wildcard**

```txt
Access-Control-Allow-Origin: *
```

* Allows all origins
* Safe only for public, non-sensitive data

### **With Credentials**

```txt
Access-Control-Allow-Origin: https://example.com
Access-Control-Allow-Credentials: true
```

* Allows cookies/auth
* Must NOT use `*`

## **10. Common CORS Misconfigurations (CTF Gold)**

### **10.1 ACAO: * + Credentials**

```txt
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

* Invalid by spec, but sometimes misused
* Leads to data exposure

### **10.2 Reflecting Origin (Critical)**

Server does:

```txt
Access-Control-Allow-Origin: <Origin header>
```

* No validation
* Attacker controls origin
* Full SOP bypass

### **10.3 Weak Regex Validation**

Example:

```txt
/example.com$/
```

Bypass:

* `evil-example.com`
* `example.com.attacker.com`

### **10.4 Null Origin Allowed**

```txt
Access-Control-Allow-Origin: null
```

Attack:

* Use `file://` or sandboxed iframe
* Send requests from "null" origin

### **10.5 Overly Broad Allowlist**

* Trusting too many domains
* Includes compromised or attacker-controlled domains

## **11. Secure CORS Handling**

* Use strict allowlist
* Validate origin properly (exact match)
* Avoid regex unless carefully tested
* Reject `null` origin unless required
* Never reflect origin blindly
* Avoid `*` for sensitive endpoints
* Use credentials only when necessary

## **12. Critical Security Insight**

* SOP prevents **reading data**, not sending requests
* CORS controls **who can read responses**
* Misconfigured CORS = **data exfiltration**

---
