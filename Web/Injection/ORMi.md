# ORM Injection

ORM (Object-Relational Mapping) is a programming technique that maps objects in code to relational database tables. It lets developers interact with databases using native language syntax instead of writing raw SQL. This improves readability, reduces boilerplate, and keeps business logic separate from database logic.

An ORM acts as a bridge between object-oriented code and relational databases by abstracting tables, rows, and queries into classes and objects. Its key benefits include:

* **Reducing boilerplate code:** Automatically generates SQL from object operations.
* **Increasing productivity:** Developers focus on logic instead of query construction.
* **Ensuring consistency:** Database operations follow standardized patterns.
* **Enhancing maintainability:** Schema changes are easier to reflect in models.

**Commonly Used ORM Frameworks:**

* Doctrine (PHP)
* Hibernate (Java)
* SQLAlchemy (Python)
* Entity Framework (C#)
* Active Record (Ruby on Rails)

---

## 1. How ORM Works

### Mapping Between Objects in Code and Database Tables

ORM maps classes to tables, properties to columns, and instances to rows. In Laravel’s Eloquent ORM, a model represents a database table:

```php
namespace App\Models;
use Illuminate\Database\Eloquent\Model;

class User extends Model
{
    protected $table = 'users';

    protected $fillable = [
        'name', 'email', 'password',
    ];
}
```

Here, the `User` class maps to the `users` table. Eloquent translates object operations into SQL queries behind the scenes.

### Common ORM Operations (Create, Read, Update, Delete)

ORM frameworks streamline CRUD operations.

**Create:**

```php
use App\Models\User;

$user = new User();
$user->name = 'Admin';
$user->email = 'admin@example.com';
$user->password = bcrypt('password');
$user->save();
```

`save()` generates and executes an `INSERT` query. `bcrypt()` hashes the password before storage.

**Read:**

```php
use App\Models\User;

$user = User::find(1);
$allUsers = User::all();
$admins = User::where('email', 'admin@example.com')->get();
```

* `find(1)` → `SELECT` by ID
* `all()` → `SELECT * FROM users`
* `where(...)->get()` → `SELECT ... WHERE ...`

**Update & Delete:**

Update: retrieve a model, modify attributes, call `save()`.
Delete: retrieve the model, call `delete()`.

Eloquent prepares and executes the corresponding SQL automatically.

### Comparing SQL Injection and ORM Injection

Both exploit unsafe database interaction, but at different layers.

**SQL Injection:** Targets raw SQL queries.

```SQL
SELECT * FROM users WHERE username = 'admin' OR '1'='1';
```

The injected `OR '1'='1'` always evaluates true, bypassing checks.

**ORM Injection:** Exploits unsafe ORM query construction.

```php
$userRepository->findBy(['username' => "admin' OR '1'='1"]);
```

If improperly handled, the injected condition alters the generated SQL.

| Aspect             | SQL Injection                              | ORM Injection                                      |
| ------------------ | ------------------------------------------ | -------------------------------------------------- |
| Level of Injection | Raw SQL queries                            | ORM query construction                             |
| Complexity         | Direct manipulation of SQL                 | Requires ORM-specific knowledge                    |
| Detection          | Often detectable via WAFs and logs         | Harder due to abstraction                          |
| Mitigation         | Prepared statements, parameterized queries | Safe ORM methods, validation, strict configuration |

### Configuring the Environment

Using Laravel’s Eloquent ORM:

Install Laravel:

`composer create-project --prefer-dist laravel/laravel thm-project`

**Configure Database Credentials:**

Edit the `.env` file:

```env
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=your_database_name
DB_USERNAME=your_database_user
DB_PASSWORD=your_database_password
```

**Setting up Migrations:**

Migrations manage schema changes.

Create a migration: `php artisan make:migration create_users_table --create=users`

Generated migration file:

```php
<?php
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class CreateUsersTable extends Migration
{
    public function up()
    {
        Schema::create('users', function (Blueprint $table) {
            $table->id();
            $table->string('name');
            $table->string('email')->unique();
            $table->string('password');
            $table->timestamps();
        });
    }

    public function down()
    {
        Schema::dropIfExists('users');
    }
}
```

`up()` defines the table structure; `down()` rolls it back.

Run: `php artisan migrate`

Migrations align database schema with application models. Poor configuration or unsafe query construction can introduce vulnerabilities like ORM injection, making secure schema design and proper input handling essential.

---

## 2. Identifying ORM Injection

### Techniques for Testing ORM Injection

* **Manual code review:** Look for raw query methods (`whereRaw()`, `DB::raw()`) and string concatenation with user input.
* **Automated scanning:** Use tools that detect unsafe dynamic query construction.
* **Input validation testing:** Inject payloads (e.g., SQL keywords, control characters) to observe query behavior.
* **Error-based testing:** Trigger malformed input to reveal query structure via error messages.

### Frameworks and ORM Injection Testing

| Framework     | ORM Library   | Common Vulnerable Methods          |
| ------------- | ------------- | ---------------------------------- |
| Laravel       | Eloquent ORM  | `whereRaw()`, `DB::raw()`          |
| Ruby on Rails | Active Record | `where("name = '#{input}'")`       |
| Django        | Django ORM    | `extra()`, `raw()`                 |
| Spring        | Hibernate     | `createQuery()` with concatenation |
| Node.js       | Sequelize     | `sequelize.query()`                |

Unsafe raw methods increase injection risk. Safer alternatives use parameterized queries (`where()`, `filter()`, etc.) with proper validation.

### Exploring the Target Application

**Techniques to Identify the Framework:**

* **Verifying cookies:** Session naming patterns can indicate the framework.

![img](/img/ORMi/1.png)

* **Reviewing source code:** Comments or meta tags may reveal framework signatures.

![img](/img/ORMi/2.png)

* **Analysing HTTP headers:** Inspect using browser dev tools or Burp Suite.
* **URL structure:** Routing patterns can hint at specific frameworks.
* **Login and error pages:** Some frameworks have distinctive error formats.

After identifying Laravel via cookies, test behavior by injecting input such as: `1'`

![img](/img/ORMi/3.png)

If the application returns an error like: `SQLSTATE[42000]: Syntax error or access violation`

it indicates improper input handling and possible unsafe query concatenation. Laravel’s characteristic error structure and query patterns confirm Eloquent usage.

For security assessments, identifying ORM injection is crucial. Exploitation is possible when user input is unsanitized or passed into raw query methods. Prevention requires parameterized queries, strict validation, secure migrations, and regular code reviews supported by automated security tools.

---

## 3. ORM Injection - Weak Implementation

![img](/img/ORMi/4.png)

Let’s examine the vulnerable source code used for the **Email (Vulnerable)** input field:

```php
public function searchBlindVulnerable(Request $request)
{
    $users = [];
    $email = $request->input('email');
    $users = Admins::whereRaw("email = '$email'")->get();
    if ($users) {
        return view('user', ['users' => $users]);
    } else {
        return view('user', ['message' => 'User not found']);
    }
}
```

### Function Breakdown

The `searchBlindVulnerable()` function retrieves user records based on a supplied email:

* **Retrieve input:** Captures the `email` parameter from the HTTP request.
* **Construct query:** Uses `whereRaw()` to directly insert the email into a raw SQL condition.
* **Execute query:** Executes the query and stores the result in `$users`.
* **Return view:** Returns user data if found; otherwise, displays “User not found”.

### The Vulnerability

The issue is the direct use of `whereRaw()` with unsanitised user input. Because the input is embedded into the query string, attackers can manipulate the SQL logic.

If an attacker enters: `1' OR '1'='1`

The resulting SQL becomes:

```sql
SELECT * FROM users WHERE email = '1' OR '1'='1';
```

Since `'1'='1'` is always true, the query returns all records.

### Detailed Exploitation

* **Malicious input:** The attacker submits `1' OR '1'='1`.
* **Query construction:**

```php
$users = User::whereRaw("email = '1' OR '1'='1'")->get();
```

* **Query execution:** Eloquent translates this into:

`SELECT * FROM users WHERE email = '1' OR '1'='1';`

* **Result:** All user records are returned, potentially exposing sensitive data.

![img](/img/ORMi/5.png)

### Implementing Secure ORM Queries

A secure implementation avoids raw query construction and uses parameterized methods:

```php
public function searchBlindSecure(Request $request)
{
    $email = $request->input('email');
    $users = User::where('email', $email)->get();
    if (isset($users) && count($users) > 0) {
        return view('user', ['users' => $users]);
    } else {
        return view('user', ['message' => 'User not found']);
    }
}
```

### Why This Is Secure

* **Parameterized queries:** `where()` binds user input as data, not executable SQL.
* **Automatic escaping:** Eloquent safely handles special characters.
* **Clear query logic:** Using ORM-native methods improves maintainability and auditability.

**Key Takeaway:**

The vulnerable use of `whereRaw()` directly injects user input into SQL, enabling attackers to manipulate query logic. The secure version prevents this by relying on parameterized ORM methods. Proper input validation and avoiding raw query construction are essential to mitigating ORM injection risks.

---

## 4. ORM Injection - Vulnerable Implementation

Secure coding matters, but vulnerabilities often appear when developers rely on outdated or misconfigured ORM libraries. Even when application code looks clean, flaws inside the ORM or query builder itself can introduce injection points. Common causes include improper handling of query parameters, unsafe dynamic sorting, or weak validation logic.

Keeping ORM libraries updated and reviewing changelogs for security fixes is essential. Using a vulnerable version effectively outsources your security risk to someone else’s bug.

### Practical Example

A known issue affected versions of the Laravel query builder package prior to 1.17.1. The flaw allowed SQL injection via unsanitised sorting parameters. In this scenario, the [Spatie query builder](https://github.com/spatie/laravel-query-builder) was used, which internally relies on Laravel’s query builder.

Consider the endpoint: `https://example.org/query_users?sort=name`

This retrieves users sorted by the `name` column.

![img](/img/ORMi/6.png)

Laravel translates this to: `SELECT * FROM users ORDER BY name ASC LIMIT 2`

### Injection Attempt

If `sort=name'` is submitted, the application throws an error about an invalid column:

![img](/img/ORMi/7.png)

The goal is to bypass the `LIMIT 2` restriction and retrieve more rows. Direct concatenation into the `ORDER BY` clause does not work easily because we must escape the clause correctly.

The exploitation relies on the `->` operator in MySQL, which acts as shorthand for `json_extract()`. By combining this operator with a crafted payload like `"%27))`, it becomes possible to break out of the intended JSON extraction context and alter the query structure.

### Final Payload

* **Initial query:**
  `SELECT * FROM users ORDER BY name ASC LIMIT 2`

* **Breaking the query:**
  Injecting `name->"%27))` interferes with how Laravel parses the sort parameter and how MySQL interprets JSON extraction.

* **Crafted payload:**
  `name->"%27)) SQL INJECTION QUERY #`

  * `->` triggers JSON extraction parsing.
  * `"%27))` terminates the JSON string and condition.
  * `SQL INJECTION QUERY` represents attacker-controlled SQL.
  * `#` comments out the remaining query to prevent syntax errors.

* **Example exploit URL:**

  `https://example.org/query_users?sort=name-%3E%22%27))%20LIMIT%2010%23`

* **Resulting query sent to MySQL:**

  `SELECT * FROM 'users' ORDER BY json_unquote(json_extract('name', '$.""')) LIMIT 10#"')) ASC LIMIT 2`

The injected `LIMIT 10` overrides the intended restriction, returning more rows than permitted.

![img](/img/ORMi/8.png)

**Key Takeaway:**

This example demonstrates that even structured ORM-based queries can become vulnerable when user-controlled parameters are passed into dynamic query builders without strict validation. Sorting, filtering, and pagination parameters are common blind spots.

Input validation, strict whitelisting of sortable fields, and maintaining updated dependencies are critical. ORM abstraction does not eliminate injection risk; it only shifts where that risk appears.

---

## 5. Few Important Practices

* **Input validation:** Validate input on both client and server sides. Enforce expected format, type, and length using built-in validators or regular expressions.
* **Parameterized queries:** Use prepared statements so inputs are treated strictly as data. Never concatenate user input into SQL.
* **Proper ORM usage:** Rely on ORM-native methods instead of raw queries. Ensure correct configuration and parameterization of any custom SQL.
* **Escaping and sanitisation:** Escape special characters and sanitize input before processing or storage.
* **Allowlist validation:** Accept only explicitly permitted values. Allowlisting is more reliable than trying to block known malicious patterns.

### Application in Popular Frameworks

Modern ORM frameworks provide secure abstractions, but protection depends on proper usage. Doctrine (PHP), SQLAlchemy (Python), Hibernate (Java), and Entity Framework (.NET) all support parameter binding and safe query construction.

**Doctrine (PHP)**
Use named parameters with prepared queries:

```php
$query = $entityManager->createQuery('SELECT u FROM User u WHERE u.username = :username');
$query->setParameter('username', $username);
$users = $query->getResult();
```

**SQLAlchemy (Python)**
Use the ORM query API, which handles parameter binding automatically:

```py
from sqlalchemy.orm import sessionmaker
Session = sessionmaker(bind=engine)
session = Session()
user = session.query(User).filter_by(username=username).first()
```

**Hibernate (Java)**
Bind named parameters in HQL:

```java
String hql = "FROM User WHERE username = :username";
Query query = session.createQuery(hql);
query.setParameter("username", username);
List results = query.list();
```

**Entity Framework (.NET)**
Use LINQ queries, which generate parameterized SQL:

```C#
var user = context.Users.FirstOrDefault(u => u.Username == username);
```

Across frameworks, the principle is the same: never let user input shape query structure. Use parameter binding, strict validation, and framework-native abstractions to prevent ORM injection vulnerabilities.

---
