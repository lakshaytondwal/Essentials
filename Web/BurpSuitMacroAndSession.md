# Burp Suite Macro and Session Handling

In this secenario additional measures have been implemented to make brute-forcing more difficult. We can tackle this by using Burp Suit's Macro and Session Handling

## 1. Catching the Request

Begin by capturing a request to `http://MACHINE_IP/admin/login/` and reviewing the response. Here is an example of the response:

```http
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 20 Aug 2021 22:31:16 GMT
Content-Type: text/html; charset=utf-8
Connection: close
Set-Cookie: session=eyJ0b2tlbklEIjoiMzUyNTQ5ZjgxZDRhOTM5YjVlMTNlMjIzNmI0ZDlkOGEifQ.YSA-mQ.ZaKKsUnNsIb47sjlyux_LN8Qst0; HttpOnly; Path=/
Vary: Cookie
Front-End-Https: on
Content-Length: 3922
---
<form method="POST">
    <div class="form-floating mb-3">
        <input class="form-control" type="text" name=username  placeholder="Username" required>
        <label for="username">Username</label>
    </div>
    <div class="form-floating mb-3">
        <input class="form-control" type="password" name=password  placeholder="Password" required>
        <label for="password">Password</label>
    </div>
    <input type="hidden" name="loginToken" value="84c6358bbf1bd8000b6b63ab1bd77c5e">
    <div class="d-grid"><button class="btn btn-warning btn-lg" type="submit">Login!</button></div>
</form>
```

In this response, we notice that alongside the username and password fields, there is now a session cookie set, as well as a **CSRF (Cross-Site Request Forgery)** token in the form as a hidden field. Refreshing the page reveals that both the **session** cookie and the **loginToken** change with each request. This means that for every login attempt, we need to extract valid values for both the session cookie and the loginToken.

To accomplish this, we will use Burp Macros to define a repeated set of actions (macro) to be executed before each request. This macro will extract unique values for the session cookie and loginToken, replacing them in every subsequent request of our attack.

## 2. Technique

* Navigate to `http://MACHINE_IP/admin/login/`. Activate Intercept in the Proxy module and attempt to log in. Capture the request and send it to Intruder.

* Configure the positions the same way as we did for brute-forcing the support login:
  * Set the attack type to "Pitchfork".
  * Clear all predefined positions and select only the username and password form fields. Our macro will handle the other two positions.

![img](/img/Burp/1.png)

* Now switch over to the Payloads tab and load in the username and password wordlists.
Up until this point, we have configured Intruder in almost the same way as our normal credential stuffing attack; this is where things start to get more complicated.

* With the username and password parameters handled, we now need to find a way to grab the ever-changing loginToken and session cookie. Unfortunately, "recursive grep" won't work here due to the redirect response, so we can't do this entirely within Intruder – we will need to build a macro.
Macros allow us to perform the same set of actions repeatedly. In this case, we simply want to send a GET request to `/admin/login/`.

* Fortunately, setting this up is a straightforward process.

  * Switch over to the main "Settings" tab at the top-right of Burp.
  * Click on the "Sessions" category.
  * Scroll down to the bottom of the category to the "Macros" section and click the Add button.
  * The menu that appears will show us our request history. If there isn't a GET request to `http://MACHINE_IP/admin/login/` in the list already, navigate to this location in your browser, and you should see a suitable request appear in the list.
  * With the request selected, click OK.
  * Finally, give the macro a suitable name, then click OK again to finish the process.

There are a lot of steps here, comparatively speaking, so the following GIF shows the entire process:

![img](/img/Burp/2.gif)

* Now that we have a macro defined, we need to set Session Handling rules that define how the macro should be used.

  * Still in the "Sessions" category of the main settings, scroll up to the "Session Handling Rules" section and choose to Add a new rule.
  * A new window will pop up with two tabs in it: "Details" and "Scope". We are in the Details tab by default

![img](/img/Burp/3.png)

* Fill in an appropriate description, then switch to the Scope tab.
* In the "Tools Scope" section, deselect every checkbox other than Intruder – we do not need this rule to apply anywhere else.
* In the "URL Scope" section, choose "Use suite scope"; this will set the macro to only operate on sites that have been added to the global scope. If you have not set a global scope, keep the "Use custom scope" option as default and add `http://MACHINE_IP/` to the scope in this section.

![img](/img/Burp/4.png)

* Now we need to switch back over to the Details tab and look at the "Rule Actions" section.

  * Click the Add button – this will cause a dropdown menu to appear with a list of actions we can add.
  * Select "Run a Macro" from this list.
  * In the new window that appears, select the macro we created earlier.

As it stands, this macro will now overwrite all of the parameters in our Intruder requests before we send them; this is great, as it means that we will get the loginTokens and session cookies added straight into our requests. That said, we should restrict which parameters and cookies are being updated before we start our attack:

* Select "Update only the following parameters and headers", then click the Edit button next to the input box below the radio button.
* In the "Enter a new item" text field, type "loginToken". Press Add, then Close.
* Select "Update only the following cookies", then click the relevant Edit button.
* Enter "session" in the "Enter a new item" text field. Press Add, then Close.
* Finally, press OK to confirm our action.

The following GIF demonstrates this final stage of the process:

![img](/img/Burp/5.gif)

* Click OK, and we're done!

* You should now have a macro defined that will substitute in the CSRF token and session cookie. All that's left to do is switch back to Intruder and start the attack!

**Note:** You should be getting 302 status code responses for every request in this attack. If you see 403 errors, then your macro is not working properly.

* As with the support login credential stuffing attack we carried out, the response codes here are all the same (302 Redirects). Once again, order your responses by length to find the valid credentials. Your results won't be quite as clear-cut as last time – you will see quite a few different response lengths: however, the response that indicates a successful login should still stand out as being significantly shorter.

* Use the credentials you just found to log in (you may need to refresh the login page before entering the credentials).
