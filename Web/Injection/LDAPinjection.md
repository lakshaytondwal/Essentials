# LDAP Injection

## 1. LDAP Search Queries

LDAP search queries retrieve information from a directory service.

* **389** → LDAP (plain / StartTLS)
* **636** → LDAPS (SSL/TLS)

### 1.1 Core Components

**Base DN (Distinguished Name):** Starting point in the directory tree.

**Scope:** Defines search depth:

* `base` → only the base DN
* `one` → immediate children
* `sub` → base DN + all descendants

**Filter:** Conditions entries must match (RFC 4515 syntax).

**Attributes:** Specifies which fields to return.

**Basic Syntax:**

```bash
(base DN) (scope) (filter) (attributes)
```

### 1.2 LDAP Filters

Filters define matching criteria.

**Common Operators:**

* `=` → equality
* `=*` → presence
* `>=` → greater than
* `<=` → less than
* `*` → wildcard (any characters)

### 1.3 Filter Examples

**Simple:**

```bash
(cn=John Doe)
```

**Wildcard:**

```bash
(cn=J*)
```

**Logical Operators:**

* `&` → AND
* `|` → OR
* `!` → NOT

**Complex Example:**

```bash
(&(objectClass=user)(|(cn=John*)(cn=Jane*)))
```

### Example

```bash
ldapsearch -x -H ldap://MACHINE_IP:389 -b "dc=ldap,dc=thm" "(ou=People)"
```

* `-x` → simple authentication
* `-H` → target server
* `-b` → base DN
* Filter → searches under `ou=People`

Used for directory administration and testing. Improper input handling can lead to LDAP Injection.

---

## 2. Injection

**Definition:** LDAP Injection occurs when user input is inserted into LDAP queries without proper validation or escaping.

**Cause:** Applications dynamically build LDAP queries using unsanitized user input.

**Impact:** Attackers can manipulate queries to:

* Bypass authentication
* Access unauthorized data
* Modify directory entries

**Concept:** Similar to SQL Injection, but targets LDAP queries instead of SQL databases.

**Common Attack Vectors:**

* **Authentication Bypass** → Alter login queries to access accounts without valid credentials.
* **Unauthorized Data Access** → Modify search filters to retrieve restricted information.
* **Data Manipulation** → Inject queries that change or add directory attributes.

Making an LDAP Injection attack involves several key steps, from identifying the injection point to successfully exploiting the vulnerability.

![img](/img/LDAPi/1.png)

---

## 3. Exploitation

LDAP Injection is especially dangerous in authentication systems where user input is directly embedded into LDAP queries.

### 3.1 Vulnerable Authentication Code

```php
<?php
$username = $_POST['username'];
$password = $_POST['password'];

$ldap_server = "ldap://localhost";
$ldap_dn = "ou=People,dc=ldap,dc=thm";
$admin_dn = "cn=tester,dc=ldap,dc=thm";
$admin_password = "tester"; 

$ldap_conn = ldap_connect($ldap_server);
if (!$ldap_conn) {
    die("Could not connect to LDAP server");
}

ldap_set_option($ldap_conn, LDAP_OPT_PROTOCOL_VERSION, 3);

if (!ldap_bind($ldap_conn, $admin_dn, $admin_password)) {
    die("Could not bind to LDAP server with admin credentials");
}

// LDAP search filter
$filter = "(&(uid=$username)(userPassword=$password))";

$search_result = ldap_search($ldap_conn, $ldap_dn, $filter);

if ($search_result) {
    $entries = ldap_get_entries($ldap_conn, $search_result);
    if ($entries['count'] > 0) {
        foreach ($entries as $entry) {
            if (is_array($entry) && isset($entry['cn'][0])) {
                $message = "Welcome, " . $entry['cn'][0] . "!\n";
            }
        }
    } else {
        $error = true;
    }
} else {
    $error = "LDAP search failed\n";
}
?>
```

The filter is built using unsanitized user input:

```php
$filter = "(&(uid=$username)(userPassword=$password))";
```

An attacker can inject LDAP operators to manipulate the query logic.

### 3.2 Authentication Bypass Techniques

**Tautology-Based Injection:**

Tautology-based injection involves inserting conditions into an LDAP query that are inherently true, thus ensuring the query always returns a positive result, irrespective of the intended logic. This method is particularly effective against LDAP queries constructed with user input that is not adequately sanitised. For example, consider an LDAP authentication query where the username and password are inserted directly from user input:

```bash
(&(uid={userInput})(userPassword={passwordInput}))
```

An attacker could provide a tautology-based input, such as `*)(|(&` for `{userInput}` and `pwd)` for `{passwordInput}` which transforms the query into:

```bash
(&(uid=*)(|(&)(userPassword=pwd)))
```

This query effectively bypasses password checking due to how logical operators are used within the filter. The query consists of two parts, combined using an AND (`&`) operator.

1. `(uid=*)`: This part of the filter matches any entry with a `uid` attribute, essentially all users, because the wildcard `*` matches any value.

2. `(|(&)(userPassword=pwd))`: The OR (`|`) operator, meaning that any of the two conditions enclosed needs to be true for the filter to pass. In LDAP, an empty AND (`(&)`) condition is always considered true. The other condition checks if the `userPassword` attribute matches the value `pwd`, which can fail if the user is not using `pwd` as their password.

Putting it all together, the second part of the filter `(|(&)(userPassword=pwd))` will always be evaluated as true because of the `(&)` condition. The OR operator only needs one of its enclosed conditions to be true, and since `(&)` is always true, the entire OR condition is true regardless of whether `(userPassword=pwd)` is true or false.

Therefore, this results in a successful query return for any user without verifying the correct password, bypassing the password-checking mechanism.

**Wildcard Injection:**

Wildcards (`*`) are used in LDAP queries to match any sequence of characters, making them powerful tools for broad searches. However, when user input containing wildcards is not correctly sanitised, it can lead to unintended query results, such as bypassing authentication by matching multiple or all entries. For example, if the search query is like:

```bash
(&(uid={userInput})(userPassword={passwordInput}))
```

An attacker might use a wildcard as input in both uid and userPassword. Using a `*` for `{userInput}` could force the query to ignore specific usernames and focus instead on the password. However, since a wildcard is also present in the `{passwordInput}`, it does not validate the content of the password field against a specific expected value. Instead, it only checks for the presence of the `userPassword` attribute, regardless of its content.

This means that the query will return a positive match for any user without verifying that the password provided during authentication matches the stored password. As a result, this effectively bypasses the password-checking mechanism.

### 3.3 Authentication Bypass Example

Based on the code above, the application constructs an LDAP query for authentication based on user input without proper sanitisation.

An attacker can exploit this by submitting a username and password with a character the application does not anticipate, such as an asterisk (*) for the uid and userPassword attribute value. This makes the condition always evaluates to true, effectively bypassing the password check:

**Injected Username and Password:** `username=*&password=*`

![img](/img/LDAPi/2.png)

**Resulting LDAP Query Component:** `(&(uid=*)(userPassword=*))`

![img](/img/LDAPi/3.png)

This injection always makes the LDAP query's condition true. However, using just the `*` will always fetch the first result in the query. To target the data beginning in a specific character, an attacker can use a payload like `f*`, which searches for a uid that begins with the letter f.

![img](/img/LDAPi/4.png)

---

## 4. Blind LDAP Injection

Blind LDAP Injection is a more subtle variant of LDAP Injection, where the attacker does not receive direct output from the injected payload. Instead, information is inferred from the application's behaviour.

Unlike classic LDAP Injection, the response does not explicitly reveal query results. Instead, attackers observe:

* Differences in application messages
* Behavioural changes
* Logical response variations

Even without visible data, the vulnerability remains exploitable because the LDAP filter is still constructed using unsanitised user input.

### 4.1 Vulnerable Code Example

Below is an example where the application performs an LDAP search but provides only limited feedback:

```php
$username = $_POST['username'];
$password = $_POST['password'];

$ldap_server = "ldap://localhost"; 
$ldap_dn = "ou=users,dc=ldap,dc=thm";
$admin_dn = "cn=tester,dc=ldap,dc=thm"; 
$admin_password = "tester"; 

$ldap_conn = ldap_connect($ldap_server);
if (!$ldap_conn) {
    die("Could not connect to LDAP server");
}

ldap_set_option($ldap_conn, LDAP_OPT_PROTOCOL_VERSION, 3);

if (!ldap_bind($ldap_conn, $admin_dn, $admin_password)) {
    die("Could not bind to LDAP server with admin credentials");
}

$filter = "(&(uid=$username)(userPassword=$password))";
$search_result = ldap_search($ldap_conn, $ldap_dn, $filter);

if ($search_result) {
   $entries = ldap_get_entries($ldap_conn, $search_result);
    if ($entries['count'] > 0) {
        foreach ($entries as $entry) {
            if (is_array($entry)) {
                if (isset($entry['cn'][0])) {
                    if($entry['uid'][0] === $_POST['username']){
                        $message = "Welcome, " . $entry['cn'][0] . "!\n";
                    }else{
                        $message = "Something is wrong in your password.\n";
                    }
                }
            }
        }
    } else {
        $error = true;
    }
} else {
    echo "LDAP search failed\n";
}

ldap_close($ldap_conn);
```

The filter remains dynamically constructed:

```php
$filter = "(&(uid=$username)(userPassword=$password))";
```

Although detailed results are not displayed, behavioural differences allow inference.

### 4.2 Boolean-Based Blind LDAP Injection

An attacker can inject conditions into the username field to force the LDAP query to evaluate to true or false.

#### Injected Username and Password (URL Encoded)

```bash
username=a*%29%28%7C%28%26&password=pwd%29
```

Decoded payload:

```bash
username=a*)(|(&
password=pwd)
```

![img](/img/LDAPi/5.png)

Resulting LDAP Query:

```bash
(&(uid=a*)(|(&)(userPassword=pwd)))
```

![img](/img/LDAPi/6.png)

Explanation:

* `(uid=a*)` checks if any user exists whose UID starts with "a".
* `(|(&)(userPassword=pwd))` always evaluates to true because `(&)` is true.
* The outer AND evaluates to true if such a user exists.

If the application returns "Something is wrong in your password", the attacker confirms that a UID starting with "a" exists.

No direct data exposure occurs.
The response behaviour becomes the oracle.

### 4.3 Character Enumeration

To discover additional characters, the attacker modifies the prefix.

#### Injected Username and Password (Next Attempt)

```bash
username=ab*%29%28%7C%28%26&password=pwd%29
```

![img](/img/LDAPi/7.png)

Resulting LDAP Query:

```bash
(&(uid=ab*)(|(&)(userPassword=pwd)))
```

![img](/img/LDAPi/8.png)

Interpretation:

* If the response still indicates a password error → UID begins with "ab".
* If the response changes → the second character is not "b".

This process can be repeated character-by-character to reconstruct attribute values such as usernames or emails.

The attacker transforms the application into a Boolean decision engine.

### 4.4 Techniques for Extracting Information

**1. Boolean Exploitation:**

* Inject conditions that evaluate to true or false
* Observe response differences
* Deduce attribute values incrementally

**2. Error-Based Inference:**

* Trigger malformed filters
* Observe differences in application behaviour
* Infer filter structure or attribute existence

Even minimal feedback is sufficient when logic is controllable.

### 4.5 Automating the Attack

Manual enumeration is inefficient. Automation accelerates extraction.

The provided Python [script](/Scripting/Python/Samples/BlindLDAPi.py) performs automated Boolean-based enumeration by:

* Defining a character set
* Iteratively appending characters to the injected payload
* Sending POST requests
* Parsing the response
* Detecting behavioural success indicators
* Building the discovered value incrementally

Core injection logic used in the script:

```python
data = {'username': f'{successful_chars}{char}*)(|(&','password': 'pwd)'}
```

If the response contains the success indicator, the character is confirmed and appended.

![img](/img/LDAPi/9.png)

Using `*` as the password ensures `(userPassword=*)` evaluates as true, reducing authentication validation to attribute existence checks.

---

## 5. Real-World Considerations and Advanced LDAP Injection Scenarios

The previous sections demonstrate LDAP Injection in a controlled, instructional environment. Real-world deployments are rarely this simple.

In production environments, LDAP commonly backs:

* Single Sign-On (SSO)
* Enterprise identity management
* VPN authentication
* Email systems
* Privilege and group-based authorization

This dramatically increases impact. An injection vulnerability in LDAP is often an identity-layer compromise, not just a login bypass.

### 5.1 Authentication via Bind vs Search

Many real-world systems (especially enterprise deployments) do not authenticate users by comparing `userPassword` in a search filter.

Instead, they:

1. Search for the user DN (Distinguished Name)
2. Attempt to bind as that user with the provided password

Example flow:

```text
1. Search for: (uid=username)
2. Retrieve DN → cn=John Doe,ou=Users,dc=corp,dc=local
3. Attempt ldap_bind(user_dn, password)
```

In this case:

* Wildcard injection against `userPassword` will not work.
* Tautology-based bypass may fail.
* Injection must target the search phase instead.

If the search filter is injectable, an attacker could:

* Alter which DN is retrieved
* Target privileged accounts
* Influence authorization logic

Authentication logic changes the exploitation strategy.

### 5.2 Targeting Authorization, Not Authentication

In many applications, LDAP controls authorization via group membership.

Example filter:

```bash
(&(uid=$username)(memberOf=cn=admins,ou=groups,dc=corp,dc=local))
```

If injectable, an attacker could attempt to manipulate group checks:

* Force `memberOf=*`
* Inject OR conditions
* Modify the logical structure

This can result in privilege escalation without bypassing authentication.

Real-world attackers often aim for elevated access rather than simple login bypass.

### 5.3 Attribute Enumeration in Enterprise Directories

Enterprise directories often contain sensitive attributes:

* Email addresses
* Department names
* Phone numbers
* Manager relationships
* Group memberships
* Service account identifiers

Blind LDAP Injection can be used to enumerate:

* Valid usernames
* Internal naming conventions
* Organizational structure
* Administrative account identifiers

This information is highly valuable for:

* Password spraying
* Phishing campaigns
* Lateral movement

Even partial enumeration reduces attacker uncertainty.

### 5.4 Escaping and Special Character Handling

LDAP filters follow RFC 4515 encoding rules.

Special characters that must be escaped:

* `*`
* `(`
* `)`
* `\`
* NULL byte

Failure to escape these characters allows filter manipulation.

Proper mitigation includes:

* Using `ldap_escape()` in PHP
* Enforcing strict input validation
* Avoiding manual string concatenation
* Using parameterized APIs where available

If user input can alter parentheses or logical operators, the filter tree is compromised.

### 5.5 Active Directory Nuances

In environments using Microsoft Active Directory:

* Authentication typically relies on bind, not `userPassword` comparisons.
* Password attributes are not readable in plaintext.
* Certain attributes require elevated permissions to query.

However:

* LDAP injection can still manipulate search filters.
* Authorization logic is often LDAP-based.
* Group membership checks are common injection targets.

The attack surface shifts — it does not disappear.

### 5.6 Defensive Architecture Principles

Preventing LDAP Injection requires structural controls:

* Separate data from query logic.
* Never build filters via string concatenation.
* Use least-privileged bind accounts.
* Disable anonymous binds.
* Log and monitor abnormal filter patterns.
* Implement rate limiting against enumeration attempts.

Security is not about hiding error messages.
It is about preventing input from altering logic.

---

## 6. Advanced Exploitation Methods

In real environments, LDAP Injection is rarely exploited as a single-step login bypass. Attackers adapt their technique depending on authentication flow, error handling, and directory configuration.

Below are practical exploitation methods seen outside lab scenarios.

### 6.1 LDAP Injection Against Bind-Based Authentication

When authentication uses a **search → bind** workflow, the attacker targets the search stage.

Example vulnerable search:

```bash
(uid=$username)
```

If injectable, an attacker may attempt:

```bash
*)(|(uid=admin))
```

Resulting filter:

```bash
(uid=*)(|(uid=admin))
```

If poorly structured, this can:

* Return multiple entries
* Return privileged accounts
* Influence which DN is selected for the bind attempt

If the application blindly binds using the first returned DN, authentication may occur against an unintended account.

This does not always produce instant admin access — but it can redirect authentication logic in dangerous ways.

### 6.2 Privilege Escalation via Group Manipulation

Many applications verify access using LDAP group membership:

```bash
(&(uid=$username)(memberOf=cn=admins,ou=groups,dc=corp,dc=local))
```

If injectable, an attacker might attempt:

```bash
*)(memberOf=*)
```

Resulting filter:

```bash
(&(uid=*)(memberOf=*))
```

If the application logic checks only for a successful result count, this may:

* Validate existence of *any* group membership
* Bypass role-specific checks
* Grant unintended access

In poorly implemented systems, authorization filters are easier to break than authentication filters.

### 6.3 Blind Enumeration of Valid Accounts

Even when authentication bypass fails, enumeration remains powerful.

An attacker can:

* Discover valid usernames
* Identify service accounts
* Map naming conventions
* Identify high-value targets (e.g., accounts containing “admin”, “svc”, “backup”)

Example Boolean payload:

```bash
(&(uid=a*)(objectClass=person))
```

Iterating through characters reveals valid account prefixes.

This supports:

* Credential stuffing
* Password spraying
* Targeted phishing

Enumeration is often phase one of a larger intrusion chain.

### 6.4 Attribute Extraction via Conditional Testing

Blind injection can extract attribute values character by character.

Example target:

```bash
(&(uid=administrator)(mail=a*))
```

If true → administrator email starts with “a”.

Incrementally modify:

```bash
(&(uid=administrator)(mail=ad*))
(&(uid=administrator)(mail=adm*))
```

This allows full reconstruction of:

* Email addresses
* Employee IDs
* Internal identifiers

Time-consuming manually. Trivial with automation.

### 6.5 Time-Based Blind LDAP Injection

Less common but possible in certain implementations.

If application response time varies based on query complexity, attackers may:

* Inject deeply nested logical operators
* Trigger expensive wildcard searches
* Compare response latency

Example concept (theoretical):

```bash
(|(uid=a*)(uid=aaaaaaaaaaaaaaaaaaaa*))
```

If processing large wildcard searches causes measurable delay, timing can leak information.

This is highly environment-dependent and not universally exploitable.

### 6.6 Chaining LDAP Injection with Other Attacks

LDAP Injection often acts as an enabling vulnerability.

Once enumeration succeeds, attackers may chain with:

* Password spraying
* Kerberos attacks
* Privilege escalation techniques
* Lateral movement within internal networks

LDAP rarely exists alone. It is typically integrated into:

* Active Directory
* Identity federation systems
* Web application authentication layers

Compromising LDAP logic can weaken the entire trust boundary.

### Practical Reality

In real engagements, attackers prioritize:

1. Enumeration
2. Privilege escalation via group checks
3. Exploiting weak bind logic
4. Leveraging extracted data for follow-up attacks

Straight “login bypass with *” works in labs.
Strategic directory manipulation works in enterprises.

LDAP Injection is not flashy.
It is structural.

And structural weaknesses are the ones that collapse systems quietly.
