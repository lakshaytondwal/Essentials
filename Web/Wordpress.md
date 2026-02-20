# Wordpress

## 1. WordPress Identification

WordPress websites can often be identified through characteristic directories and files such as:

* `/wp-content/`
* `/wp-includes/`
* `/wp-admin/`
* `wp-config.php`
* `readme.html`

For example:

* Accessing `https://target.com/wp-content/` or `https://target.com/wp-includes/` may confirm WordPress usage.
* The presence of `/wp-admin/` typically redirects to the WordPress login page.
* `wp-config.php` exists in the root directory (though it should not be publicly accessible).
* `readme.html` may reveal the WordPress version if left exposed.

However, these identifiers can be altered, hidden, or restricted by the site implementer. Security-conscious administrators may:

* Rename directories
* Block directory listing
* Restrict access via `.htaccess`
* Use security plugins to mask WordPress fingerprints

Therefore, manual identification alone is not always reliable.

---

## 2. WPScan

WPScan is a dedicated WordPress vulnerability scanner used for enumerating themes, plugins, users, and known vulnerabilities.

### Basic Command

```bash
wpscan --url https://target.com
```

### Commonly Used Flags

| Flag                             | Description                 |
| -------------------------------- | --------------------------- |
| `--url`                          | Target URL                  |
| `--enumerate u`                  | Enumerate users             |
| `--enumerate p`                  | Enumerate plugins           |
| `--enumerate t`                  | Enumerate themes            |
| `--api-token`                    | Use WPScan API token        |
| `--random-user-agent`            | Randomize user-agent string |
| `--plugins-detection aggressive` | Aggressive plugin detection |

Example:

```bash
wpscan --url https://target.com --enumerate u,p,t --api-token YOUR_TOKEN --random-user-agent
```

### WPScan API (Free Tier)

WPScan provides a vulnerability database API.

* A free API token can be obtained by registering on the official WPScan website.
* The free plan allows a limited number of API requests per day (suitable for small assessments and labs).
* The API enables vulnerability checks against discovered plugins, themes, and WordPress core versions.

Without the API token, WPScan can still enumerate components, but it will not provide vulnerability data from the official database.

---

## 3. User Enumeration via REST API

WordPress REST API may expose user information through:

```url
https://target.com/wp-json/wp/v2/users
```

If not restricted, this endpoint can reveal:

* Usernames
* Display names
* User IDs
* Author slugs

Attackers can use this information for brute-force attacks or credential stuffing.

Mitigation:

* Disable or restrict REST user enumeration.
* Use security plugins to limit exposure.
* Implement rate limiting and strong authentication controls.

---

## 4. Password Bruteforcing with WPScan

After obtaining valid usernames, WPScan can perform password brute-force attacks against the WordPress login.

### Basic Syntax

```bash
wpscan --url https://target.com -U usernames.txt -P passwords.txt
```

### Username and Password Flags

| Flag | Description               |
| ---- | ------------------------- |
| `-U` | File containing usernames |
| `-u` | Single username           |
| `-P` | File containing passwords |
| `-p` | Single password           |

### Optional Flags

```bash
--password-attack xmlrpc
--max-threads 10
--random-user-agent
```

XML-RPC mode can increase attack efficiency if enabled.

---
