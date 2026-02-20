# Passive Reconnaissance

## 1. **Google Dorking**

### 1.1 Operators

| **Operator / Pattern**  | **What it finds**         | **Example**                       |
| ----------------------- | ------------------------- | --------------------------------- |
| `site:`                 | Limit search to domain    | `site:example.com`                |
| `site:*.domain.com`     | Subdomains                | `site:*.example.com`              |
| `filetype:`             | Specific file types       | `filetype:pdf confidential`       |
| `ext:`                  | Alternate filetype search | `ext:env`                         |
| `intitle:`              | Term in page title        | `intitle:"admin panel"`           |
| `allintitle:`           | ALL terms in title        | `allintitle:admin login`          |
| `inurl:`                | Term in URL               | `inurl:login`                     |
| `allinurl:`             | ALL terms in URL          | `allinurl:admin login`            |
| `intext:`               | Term in page content      | `intext:"password"`               |
| `allintext:`            | ALL terms in content      | `allintext:username password`     |
| `allinanchor:`          | ALL terms in anchor text  | `allinanchor:"reset password"`    |
| `" "`                   | Exact phrase match        | `"internal use only"`             |
| `OR`                    | Logical OR                | `admin OR dashboard`              |
| `-`                     | Exclude term              | `login -facebook`                 |
| `()`                    | Group logic               | `(admin OR root) login`           |
| `*`                     | Wildcard                  | `"how to * exploit"`              |
| `AROUND(n)`             | Proximity search          | `password AROUND(3) reset`        |
| `before:`               | Results before date       | `before:2021 breach`              |
| `after:`                | Results after date        | `after:2023 leak`                 |
| `intitle:"index of"`    | Open directories          | `intitle:"index of" backup`       |
| `inurl:/api/`           | API endpoints             | `site:example.com inurl:/api/`    |
| `inurl:admin`           | Admin panels              | `site:example.com inurl:admin`    |
| `"sql syntax"`          | SQL errors                | `"you have an error in your sql"` |
| `"stack trace"`         | Debug info leaks          | `"exception stack trace"`         |
| `filetype:log`          | Log files                 | `filetype:log error`              |
| `filetype:sql`          | DB dumps                  | `filetype:sql`                    |
| `site:github.com`       | Source/code leaks         | `site:github.com example.com`     |
| `site:pastebin.com`     | Paste leaks               | `site:pastebin.com example`       |
| `site:s3.amazonaws.com` | Open S3 buckets           | `site:s3.amazonaws.com example`   |
| `cache:`                | Cached page               | `cache:example.com`               |
| `related:`              | Related sites             | `related:example.com`             |

### 1.2 Examples

```txt
# --- Sensitive Data / Credentials ---
filetype:sql (intext:password OR intext:pass OR intext:passwd)
filetype:env (DB_PASSWORD OR API_KEY OR SECRET_KEY)
intext:"username" intext:"password"
intext:"INSERT INTO `users`"
filetype:log intext:ERROR

# --- Admin Panels / Auth Pages ---
intitle:"admin login"
intitle:"site administration: please log in"
inurl:admin intitle:login
inurl:/dashboard/login

# --- Open Directories / Backups ---
intitle:"index of" (backup OR dump OR sql)
ext:bak OR ext:old OR ext:backup
inurl:/backup

# --- Debug / Error / Stack Traces ---
"you have an error in your sql syntax"
"exception stack trace"
"Fatal error: Uncaught"

# --- Source Code / Config Leaks ---
site:github.com "example.com" "API_KEY"
site:gitlab.com ".env"

# --- Cloud Storage Exposure ---
site:s3.amazonaws.com "example"
site:storage.googleapis.com "backup"

# --- Cameras / IoT / Exposed Devices ---
allintitle:"Network Camera NetworkCamera"
intitle:"Live View / - AXIS"
intitle:"LiveView / - AXIS"
inurl:axis-cgi/jpg
inurl:"view/view.shtml"
inurl:indexFrame.shtml "Axis Video Server"
inurl:"MultiCameraFrame?Mode=Motion"
inurl:/view.shtml
inurl:/view/index.shtml
intitle:"EvoCam" inurl:"webcam.html"
"mywebcamXP server!"

# --- Personal / HR OSINT ---
intitle:"curriculum vitae" filetype:doc
filetype:pdf "resume"
"confidential" "internal use only"
```

* `allin*` operators are stricter than `in*` → fewer but higher-signal results
* Combine `site:` + `filetype:` + `allintext:` for best recon

For more [Exploit DB](https://www.exploit-db.com/google-hacking-database)

## 2. **Web**

These tools helps us discover about a webserver

* whois
* [Netcraft](https://sitereport.netcraft.com/)

**Reconnaissance tools like WHOIS, Netcraft, traditional DNS querying, zone transfers, and dnsenum are increasingly limited:** WHOIS is often obscured by privacy services and GDPR; Netcraft provides only basic hosting/OS info and is ineffective against CDNs or cloud infrastructure. Standard DNS lookups and zone transfers rarely reveal true origin servers due to CDNs, cloud IPs, and restricted AXFR access, making tools like dnsenum less reliable. Modern reconnaissance relies on **passive DNS, certificate transparency logs, historical DNS data, subdomain enumeration, and intelligence platforms like Shodan, Censys, and SecurityTrails** to accurately map active infrastructure.

---
