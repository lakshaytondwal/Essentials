# Filter Evasion

In advanced SQL injection attacks, evading filters is crucial for successfully exploiting vulnerabilities. Modern web applications often implement defensive measures to sanitise or block common attack patterns, making simple SQL injection attempts ineffective. As pentesters, we must adapt using more sophisticated techniques to bypass these filters. This section will cover such methods, including character encoding, no-quote SQL injection, and handling scenarios where spaces cannot be used. We can effectively penetrate web applications with stringent input validation and security controls by understanding and applying these techniques.

## 1. Character Encoding

Character encoding involves converting special characters in the SQL injection payload into encoded forms that may bypass input filters.

* **URL Encoding:** URL encoding is a common method where characters are represented using a percent (%) sign followed by their ASCII value in hexadecimal. For example, the payload `' OR 1=1--` can be encoded as `%27%20OR%201%3D1--`. This encoding can help the input pass through web application filters and be decoded by the database, which might not recognise it as malicious during initial processing.

* **Hexadecimal Encoding:** Hexadecimal encoding is another effective technique for constructing SQL queries using hexadecimal values. For instance, the query `SELECT * FROM users WHERE name = 'admin'` can be encoded as `SELECT * FROM users WHERE name = 0x61646d696e`. By representing characters as hexadecimal numbers, the attacker can bypass filters that do not decode these values before processing the input.

* **Unicode Encoding:** Unicode encoding represents characters using Unicode escape sequences. For example, the string `admin` can be encoded as `\u0061\u0064\u006d\u0069\u006e`. This method can bypass filters that only check for specific ASCII characters, as the database will correctly process the encoded input.

### 1.1 **Example**

In this example, we explore how developers can implement basic filtering to prevent SQL injection attacks by removing specific keywords and characters from user input. However, we will also see how attackers can bypass these defences using character encoding techniques like URL encoding.

Here's the PHP code `search_books.php` that handles the search functionality:

```php
$book_name = $_GET['book_name'] ?? '';
$special_chars = array("OR", "or", "AND", "and" , "UNION", "SELECT");
$book_name = str_replace($special_chars, '', $book_name);
$sql = "SELECT * FROM books WHERE book_name = '$book_name'";
echo "<p>Generated SQL Query: $sql</p>";
$result = $conn->query($sql) or die("Error: " . $conn->error . " (Error Code: " . $conn->errno . ")");
if ($result->num_rows > 0) {
    while ($row = $result->fetch_assoc()) {
...
..
```

Here's the Javascript code in the `index.html` page that provides the user interface for searching books:

```js
function searchBooks() {
const bookName = document.getElementById('book_name').value;
const xhr = new XMLHttpRequest();
xhr.open('GET', 'search_books.php?book_name=' + encodeURIComponent(bookName), true);
   xhr.onload = function() {
       if (this.status === 200) {
           document.getElementById('results').innerHTML = this.responseText;
```

In the above example, the developer has implemented a basic defence mechanism to prevent SQL injection attacks by removing specific SQL keywords, such as `OR`, `AND`, `UNION`, and `SELECT`. The filtering uses the `str_replace` function, which strips these keywords from the user input before they are included in the SQL query. This filtering approach aims to make it harder for attackers to inject malicious SQL commands, as these keywords are essential for many SQL injection payloads.

**Preparing the Payload:**

Let's go through the process of preparing an SQL injection payload step-by-step, showing how URL encoding can bypass basic defences. First, let’s see what happens with a normal input that contains special characters or SQL keywords. When we search for a book named `Intro to PHP`, we get the successful result as shown below:

![img](/img/SQLFilterEvasion/1.png)

But what if we try to break the query by adding special characters like `'`, `;`, etc? We will get the following output:

![img](/img/SQLFilterEvasion/2.png)

The SQL query is not executing correctly, which probably means there is a chance of SQL Injection. Let's try to inject the payload `"Intro to PHP' OR 1=1"`. We will get the following output:

![img](/img/SQLFilterEvasion/3.png)

So, what is happening here? When this input is passed to the PHP script, the `str_replace` function will strip out the OR keyword and the single quote, resulting in a sanitised input that will not execute the intended SQL injection. This input is ineffective because the filtering removes the critical components needed for the SQL injection to succeed.

To bypass the filtering, we need to encode the input using URL encoding, which represents special characters and keywords in a way that the filter does not recognise and remove. Here is the example payload `1%27%20||%201=1%20--+`.

* `%27` is the URL encoding for the single quote (').
* `%20` is the URL encoding for a space ( ).
* `||` represents the SQL OR operator.
* `%3D` is the URL encoding for the equals sign (=).
* `%2D%2D` is the URL encoding for --, which starts a comment in SQL.

In the above payload, `1'` closes the current string or value in the SQL query. For example, if the query is looking for a book name that matches 1, adding `'` closes the string, making the rest of the input part of the SQL statement. `|| 1=1` part uses the SQL `OR` operator to add a condition that is always true. This condition ensures that the query returns true for all records, bypassing the original condition that was supposed to restrict the results. Similarly, `--` starts a comment in SQL, causing the database to ignore the rest of the query. This is useful to terminate any remaining part of the query that might cause syntax errors or unwanted conditions. To ensure proper spacing, `+` add a space after the comment, ensuring that the comment is properly terminated and there are no syntax issues.

From the console, we can see that clicking the search button makes an AJAX call to `search_book.php`.

![img](/img/SQLFilterEvasion/4.png)

Let's use the payload directly on the PHP page to avoid unnecessary tweaking/validation from the client.  Let's visit the URL `http://MACHINE_IP/encoding/search_books.php?book_name=Intro%20to%20PHP%27%20OR%201=1` with the standard payload `Intro to PHP' OR 1=1`, and you will see an error.

![img](/img/SQLFilterEvasion/5.png)

Now, URL encode the payload `Intro to PHP' || 1=1 --+` using [Cyber Chef](https://gchq.github.io/CyberChef/) and try to access the URL with an updated payload. We will get the following output dumping the complete information:

![img](/img/SQLFilterEvasion/6.png)

The payload works because URL encoding represents the special characters and SQL keywords in a way that bypasses the filtering mechanism. When the server decodes the URL-encoded input, it restores the special characters and keywords, allowing the SQL injection to execute successfully. Using URL encoding, attackers can craft payloads that bypass basic input filtering mechanisms designed to block SQL injection. This demonstrates the importance of using more robust defences, such as parameterised queries and prepared statements, which can prevent SQL injection attacks regardless of the input's encoding.

## 2. No-Quote SQL Injection

No-Quote SQL injection techniques are used when the application filters single or double quotes or escapes.

* **Using Numerical Values:** One approach is to use numerical values or other data types that do not require quotes. For example, instead of injecting `' OR '1'='1`, an attacker can use `OR 1=1` in a context where quotes are not necessary. This technique can bypass filters that specifically look for an escape or strip out quotes, allowing the injection to proceed.

* **Using SQL Comments:** Another method involves using SQL comments to terminate the rest of the query. For instance, the input `admin'--` can be transformed into `admin--`, where the `--` signifies the start of a comment in SQL, effectively ignoring the remainder of the SQL statement. This can help bypass filters and prevent syntax errors.

* **Using `CONCAT()` Function:** Attackers can use SQL functions like `CONCAT()` to construct strings without quotes. For example, `CONCAT(0x61, 0x64, 0x6d, 0x69, 0x6e)` constructs the string `admin`. The `CONCAT()` function and similar methods allow attackers to build strings without directly using quotes, making it harder for filters to detect and block the payload.

## 3. No Spaces Allowed

When spaces are not allowed or are filtered out, various techniques can be used to bypass this restriction.

* **Comments to Replace Spaces:** One common method is to use SQL comments (/**/) to replace spaces. For example, instead of `SELECT * FROM users WHERE name = 'admin'`, an attacker can use `SELECT/**/*FROM/**/users/**/WHERE/**/name/**/='admin'`. SQL comments can replace spaces in the query, allowing the payload to bypass filters that remove or block spaces.

* **Tab or Newline Characters:** Another approach is using tab (\t) or newline (\n) characters as substitutes for spaces. Some filters might allow these characters, enabling the attacker to construct a query like `SELECT\t*\tFROM\tusers\tWHERE\tname\t=\t'admin'`. This technique can bypass filters that specifically look for spaces.

* **Alternate Characters:** One effective method is using alternative URL-encoded characters representing different types of whitespace, such as `%09` (horizontal tab), `%0A` (line feed), `%0C` (form feed), `%0D` (carriage return), and `%A0` (non-breaking space). These characters can replace spaces in the payload.

### 3.1 **Example**

In this scenario, we have an endpoint, `http://MACHINE_IP/space/search_users.php?username=?` that returns user details based on the provided username. The developer has implemented filters to block common SQL injection keywords such as OR, AND, and spaces (%20) to protect against SQL injection attacks.

Here is the PHP filtering added by the developer.

```php
$special_chars = array(" ", "AND", "and" ,"or", "OR" , "UNION", "SELECT");
$username = str_replace($special_chars, '', $username);
$sql = "SELECT * FROM user WHERE username = '$username'";
```

If we use our standard payload `1%27%20||%201=1%20--+` on the endpoint, we can see that even through URL encoding, it is not working.

![img](/img/SQLFilterEvasion/7.png)

The SQL query shows that the spaces are being omitted by code. To bypass these protections, we can use URL-encoded characters that represent different types of whitespace or line breaks, such as `%09` (horizontal tab), `%0A` (line feed). These characters can replace spaces and still be interpreted correctly by the SQL parser.

The original payload `1' OR 1=1 --` can be modified to use newline characters instead of spaces, resulting in the payload `1'%0A||%0A1=1%0A--%27+`. This payload constructs the same logical condition as `1' OR 1=1 --` but uses newline characters to bypass the space filter.

The SQL parser interprets the newline characters as spaces, transforming the payload into `1' OR 1=1 --`. Therefore, the query will be interpreted from `SELECT * FROM users WHERE username = '$username'` to `SELECT * FROM users WHERE username = '1' OR 1=1 --`.

Now, if we access the endpoint through an updated payload, we can view all the details.

![img](/img/SQLFilterEvasion/8.png)

To summarise, it is important to understand that no single technique guarantees a bypass when dealing with filters or Web Application Firewalls (WAFs) designed to prevent SQL injection attacks. However, here are some tips and tricks that can be used to circumvent these protections. This table highlights various techniques that can be employed to try and bypass filters and WAFs:

| Scenario | Description | Example |
| -------- | ------------- | --------- |
| Keywords like SELECT are banned | SQL keywords can often be bypassed by changing their case or inserting inline comments to fragment them. | `SElEcT * FrOm users` or `SE/**/LECT * FROM/**/users` |
| Spaces are banned | Alternative whitespace characters or comments can replace spaces to evade filters. | `SELECT%0A*%0AFROM%0Ausers` or `SELECT/**/*/**/FROM/**/users` |
| Logical operators like AND, OR are banned | Alternative logical operators or concatenation can be used to bypass keyword restrictions. | `username = 'admin' && password = 'password'` or `username = 'admin'/**/[PIPE][PIPE]/**/1=1 --` |
| Common keywords like UNION, SELECT are banned | Equivalent representations such as hexadecimal or character encoding can bypass keyword-based filters. | `SElEcT * FROM users WHERE username = CHAR(0x61,0x64,0x6D,0x69,0x6E)` |
| Specific keywords like OR, AND, SELECT, UNION are banned | Obfuscation techniques using string functions or inline comments can disguise restricted SQL keywords. | `SElECT * FROM users WHERE username = CONCAT('a','d','m','i','n')` or `SElEcT/**/username/**/FROM/**/users` |

**Note:** `[PIPE][PIPE]` is `||`

In real environments, the queries you apply and the visibility of filtered keywords are not directly possible. As a pentester, it is important to understand that SQL injection testing often involves a hit-and-trial approach, requiring patience and perseverance. Each environment can have unique filters and protections, making it necessary to adapt and try different techniques to find a successful injection vector.
