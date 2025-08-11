# SQL Injection Cheatsheet

## Summary

1. Introducing the SQL Injection Vulnerability
2. Exploiting SQL Injection Vulnerabilities
3. Exploiting Blind SQL Injection Vulnerabilities
4. Modern SQL Injection Payloads (MySQL 5+, PostgreSQL, MSSQL)
5. Automation and Testing Tools

## 1. Introducing the SQL Injection Vulnerability

SQL Injection (SQLi) occurs when user input is embedded directly into SQL queries without proper sanitization.  
This allows attackers to manipulate queries and gain unauthorized access to:

- Database version and metadata
- Table and column names
- Authentication data (usernames/passwords)
- Sensitive business information

**Key Prevention:** Always use **prepared statements** / **parameterized queries**.

## 2. Exploiting SQL Injection Vulnerabilities

### Step 1 — Checking for SQL Injection

Example target URL:

```console
http://www.website.com/articles.php?id=3
```

Test:

```console
http://www.website.com/articles.php?id=3'
```
