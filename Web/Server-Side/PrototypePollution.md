# Prototype Pollution

Prototype pollution occurs when an attacker manipulates an object’s prototype, affecting **all instances** inheriting from it. Since JavaScript relies heavily on prototypes, this can lead to shared property tampering or injected behavior across the entire application.

On its own, it’s often not directly exploitable. It becomes dangerous when chained with vulnerabilities like XSS or CSRF.

**Core idea:** attacker gains control over prototype → modifies shared behavior → impacts every object using it.

**A Common Example:**

Let's assume, we have a basic prototype for `Person` with an `introduce` method. The attacker aims to manipulate the behaviour of the `introduce` method across all instances by altering the prototype.

```js
// Base Prototype
let personPrototype = {
  introduce: function() {
    return `Hi, I'm ${this.name}.`;
  }
};

// Constructor
function Person(name) {
  let person = Object.create(personPrototype);
  person.name = name;
  return person;
}

// Instance
let ben = Person('Ben');
```

**Attack via `__proto__`:**

```js
ben.__proto__.introduce = function() {
  console.log("You've been hacked, I'm Bob");
}
console.log(ben.introduce());
```

**What happened:**

* Prototype originally had a safe method
* Attacker modified it via `__proto__`
* Change propagates to **all instances**, including existing ones
* `ben.introduce()` now executes attacker-controlled code

**Takeaway:** modifying prototype = modifying behavior globally

---

## 1. Exploitation - XSS

Key targets:

* `__proto__` → direct prototype reference
* `constructor.prototype` → indirect but powerful path

If attacker controls something like:

```js
Person[x][y] = val
```

Then:

* `x = "__proto__"` → modifies prototype directly
* `x = "constructor", y = "prototype"` → modifies prototype indirectly

In a more intricate scenario, when an attacker has control over `x`, `y`, and `val` in a structure like `Person[x][y][z] = val`, assigning `x` as constructor and `y` as prototype leads to a new property defined by `z` being established across all objects in the application with the assigned `val`. This latter approach necessitates a more complex arrangement of object properties, making it less prevalent in practice.

### 1.1 Property Definition by Path

Functions that set object properties based on a given path (like `object[a][b][c] = value`) can be dangerous if the path components are controlled by user input. These functions should be inspected to ensure they don't inadvertently modify the object's prototype. Consider an endpoint that allows users to update reviews about any friend.

**Initial Object Structure:**

Before any updates are made, we have an initial friends array containing an object representing a friend's profile. Each profile object includes properties such as id, name, reviews, and albums.

```js
let friends = [
  {
    id: 1,
    name: "testuser",
    age: 25,
    country: "UK",
    reviews: [],
    albums: [{}],
    password: "xxx",
  }
];

_.set(friend, input.path, input.value);
```

**Input Received from User:**

The user wants to add a review for their friend. They provide a payload containing the path where the review should be added (reviews.content) and the review content (`<script>alert(anycontent)</script>`).

An attacker updates the path to target the prototype:

```json
{ "path": "reviews[0].content", "value": "&#60;script&#62;alert('anycontent')&#60;/script&#62;" };
```

We use the `_set` function from lodash to apply the payload and add the review content to the specified path within the friend's profile object.

**Resulting Object Structure:**

After executing the code, the friends array will be modified to include the user's review. However, due to a lack of proper input validation, the review content provided by the user (`<script>alert('anycontent')</script>`) was directly added to the profile object without proper sanitisation.

```js
let friends = [
  {
    id: 1,
    name: "testuser",
    age: 25,
    country: "UK",
    reviews: [
      "<script>alert('anycontent')</script>"
    ],
    albums: [{}],
    password: "xxx",
  }
];
```

### 1.2 Arbitrary Property Injection

Suppose the attacker wants to insert a malicious property into the friend's profile. In that case, they provide a payload containing the path where the property should be added (`isAdmin`) and the value for the malicious property (true).

```js
const payload = { "path": "isAdmin", "value": true };
```

After executing the code, the `friends` array will be modified to include the malicious property isAdmin in the friend's profile object. The `friends` object will have the following structure:

```js
let friends = [
  {
    id: 1,
    name: "testuser",
    age: 25,
    country: "UK",
    reviews: [],
    albums: [],
    password: "xxx",
    isAdmin: true // Malicious property inserted by the attacker
  }
];
```

---

## 2. Exploitation - Property Injection

### 2.1 Object Recursive Merge

This function involves recursively merging properties from source objects into a target object. An attacker can exploit this functionality if the merge function does not validate its inputs and allows merging properties into the prototype chain. Considering the same social network example, let's assume the following code. Suppose the application has a function to merge user settings:

```js
// Vulnerable recursive merge function
function recursiveMerge(target, source) {
    for (let key in source) {
        if (source[key] instanceof Object) {
            if (!target[key]) target[key] = {};
            recursiveMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
}

// Endpoint to update user settings
app.post('/updateSettings', (req, res) => {
    const userSettings = req.body; // User-controlled input
    recursiveMerge(globalUserSettings, userSettings);
    res.send('Settings updated!');
});
```

An attacker sends a request with a nested object containing `__proto__`:

```json
{ "__proto__": { "newProperty": "value" } } 
```

* **Object Clone:** Object cloning is a similar functionality that allows deep clone operations to copy properties from the prototype chain to another one inadvertently. Testing should ensure that these functions only clone the user-defined properties of an object and filter special keywords like `__proto__`, constructor, etc. A possible use case is that the application backend clones objects to create new user profiles:

### 2.2 Practical Example

Let's explore the Clone album feature. The clone album allows users to clone an album by providing a new name.

![img](/img/PrototypePollution/1.png)

```html
<form action="/clone-album/1" method="post" class="mb-4">
        <h2 class="mb-3">Clone Album of Josh</h2>
        <div class="form-group">
            <label for="selectedAlbum">Select an Album to Clone:</label>
            <select class="form-control" name="selectedAlbum" id="selectedAlbum">
                    <option value="Trip to US">
                        Trip to US
                    </option>
            </select>
        </div>
        <div class="form-group">
            <label for="newAlbumName">New Album Name:</label>
            <input type="text" class="form-control" name="newAlbumName" id="newAlbumName"
                placeholder="Enter new album name">
        </div>
        <button type="submit" class="btn btn-primary">Clone Album</button>
    </form>
```

The client-side code takes the name as input and calls the API endpoint `/clone-album/{album_ID}` to clone the album. As discussed in previous tasks, Prototype pollution alone is rarely exploitable; however, once combined with other attack vectors like XSS, it can provide a better attack surface. Now, let's go through the server-side code.

```js
app.post("/clone-album/:friendId", (req, res) => {
  const { friendId } = req.params;
  const { selectedAlbum, newAlbumName } = req.body;
  const friend = friends.find((f) => f.id === parseInt(friendId));
  if (!friend) {
    console.log("Friend not found");
    return res.status(404).send("Friend not found");
  }
  const albumToClone = friend.albums.find(
    (album) => album.name === selectedAlbum
  );
  if (albumToClone && newAlbumName) {
    let clonedAlbum = { ...albumToClone };
    try {
      const payload = JSON.parse(newAlbumName);
      merge(clonedAlbum, payload);
    } catch (e) {
    }

function merge(to, from) {
  for (let key in from) {
    if (typeof to[key] == "object" && typeof from[key] == "object") {
      merge(to[key], from[key]);
    } else {
      to[key] = from[key];
    }
  }
  return to;
}
```

In the above code,  the servers receive a JSON object containing the album's name, copy the album that needs to be copied into another object, and change the name of the newly created copy by calling the merge function.

We know the merge function is an ideal candidate for prototype pollution if it blindly copies all the objects and properties without sanitising based on keys. We can see that the merge function made by the developer lacked any such sanitisation filters. What if we send a request that contains `__proto__` with a `newProperty` and value as mentioned below:

```json
{"__proto__": {"newProperty": "hacked"}}
```

The merge function will consider the `__proto__`  as a property and will call `obj.__proto__.newProperty=value`. By doing this, `newProperty` is not added directly to the friend object. Instead, it's added to the friend object's prototype. This means `newProperty` is not visibly part of the friend's properties (like name, age, etc.) but is still accessible. Let's clone an album by visiting Josh's profile and using the above payload as an album name.

![img](/img/PrototypePollution/2.png)

* **Effect on All Objects of the Same Type:** Since all friend objects share the same prototype (they are created from the same template or constructor), adding `newProperty` to the prototype means all friend objects now have access to `newProperty`. It's like adding a new feature to the template; now, every object created from that template has this new feature.
* **Observing the Change:** Even though `newProperty` is not directly visible when you print the friend object, it is still there. You can access it by calling `friend.newProperty`, which will show `testValue`.
* **How newProperty Becomes Visible:** When you add `newProperty` via the prototype, it doesn't exist directly on the individual objects (like each friend) but on their prototype. However, when you access a property on an object, JavaScript first looks for that property on the object itself. If it's not found, JavaScript looks up the prototype chain until it finds it (or reaches the end of the chain).
* **Rendering on Screen:** In the EJS template, when you loop through the properties of a friend object using a `for...in loop` (`<% for (let key in friend) { %> ... <% } %>`) and display them, this loop iterates over all enumerable properties of the friend object, including those inherited from the prototype. Therefore, even though `newProperty` is not directly on the friend object but on its prototype, it still shows up in this loop and is rendered on the screen.

---

## 3. Exploitation - Denial of Service

Prototype pollution, a critical vulnerability in JavaScript applications, can lead to a Denial of Service (DoS) attack, among other severe consequences. This occurs when an attacker manipulates the prototype of a widely used object, causing the application to behave unexpectedly or crash altogether. In JavaScript, objects inherit properties and methods from their prototype, and altering this prototype impacts all objects that share it.

For example, if an attacker pollutes the `Object.prototype.toString` method, every subsequent call to this method by any object will execute the altered behaviour. In a complex application where `toString` is frequently used, this can lead to unexpected results, potentially causing the application to malfunction. The `toString` method is universally used in JavaScript. It's automatically invoked in many contexts, especially when an object needs to be converted to a string.

If the polluted method leads to inefficient processing or an infinite loop, it can exhaust system resources, effectively causing a DoS condition. Moreover, prototype pollution can also interfere with the application's business logic. Altering essential methods or properties might trigger unhandled exceptions or errors, leading to the termination of processes or services. This could render the server unresponsive in web applications, denying service to legitimate users.

### 3.1 Practical Example

As discussed, we have a method `Object.prototype.toString` that converts an object to a String datatype.

```html
<form action="/clone-album/1" method="post" class="mb-4">
        <h2 class="mb-3">Clone Album of Josh</h2>
        <div class="form-group">
            <label for="selectedAlbum">Select an Album to Clone:</label>
            <select class="form-control" name="selectedAlbum" id="selectedAlbum">
                    <option value="Trip to US">
                        Trip to US
                    </option>
            </select>
        </div>
        <div class="form-group">
            <label for="newAlbumName">New Album Name:</label>
            <input type="text" class="form-control" name="newAlbumName" id="newAlbumName"
                placeholder="Enter new album name">
        </div>
        <button type="submit" class="btn btn-primary">Clone Album</button>
    </form>
```

* We see that this function is calling the merge function, which merges two objects. What if we try to send a payload that will override an existing function like `toString()`, and then if we call it on some object, it will cause abrupt behaviour for the server?
* To prepare a payload, let's take a simple JSON code that will override the `toString` function as shown below:

```json
{"__proto__": {"toString": "Just crash the server"}}
```

Enter the payload instead of the new album name, as shown below:

![img](/img/PrototypePollution/3.png)

* Let's decode the payload once the `app.js` receives the request, parses the JSON, and assigns the `toString` function value in the `__proto__` property of the friend object.
* This creates an abrupt behaviour as `toString` is widely used among different objects. When we click on Clone Album, the application crashes, as shown below:

![img](/img/PrototypePollution/4.png)

* The `TypeError` we get is `Object.prototype.toString.call` is not a function, as we have already overridden that function using Prototype pollution.
* You can override several other built-in objects/functions like `toJSON`, `valueOf`, `constructor`, etc., but the application won't crash in all behaviours. It entirely depends on the function that you are overriding.

---

## 4. Automating the Process

### Major Issues During Identification

Identifying prototype pollution is a tricky problem in any language particularly in JavaScript, because of the way JavaScript lets one object share its features with another. Detecting this problem automatically with software tools is really hard because it's not straightforward like other common website security problems. Each website or web application is different, and figuring out where prototype pollution might happen requires someone to look closely at the website's code, understand how it works, and see where mistakes might be made.

Unlike other security issues that can be found by looking for specific patterns or signs, finding prototype pollution needs a deep dive into the website's code by a pentester/developer. It's all about understanding the complex ways objects in JavaScript can affect each other and spotting where something might go wrong. Security tools can help point out possible issues, but they can't catch everything. That's why having people who know how to read and analyse code carefully is so important.

### Few Important Scripts

Several tools and projects have been developed within the security and open-source communities to aid in the automation of finding prototype pollution vulnerabilities. Here are a few renowned GitHub repositories that provide tools, libraries, or insights into detecting prototype pollution vulnerabilities:

* [NodeJsScan](https://github.com/ajinabraham/nodejsscan) is a static security code scanner for Node.js applications. It includes checks for various security vulnerabilities, including prototype pollution. Integrating NodeJsScan into your development workflow can help automatically identify potential security issues in your codebase.
* [Prototype Pollution Scanner](https://github.com/KathanP19/protoscan) is a tool designed to scan JavaScript code for prototype pollution vulnerabilities. It can be used to analyse codebases for patterns that are susceptible to pollution, helping developers identify and address potential security issues in their applications.
* [PPFuzz](https://github.com/dwisiswant0/ppfuzz) is another fuzzer designed to automate the process of detecting prototype pollution vulnerabilities in web applications. By fuzzing input vectors that might interact with object properties, PPFuzz can help identify points in an application that are susceptible to prototype pollution.
* Client-side detection by [BlackFan](https://github.com/BlackFan/client-side-prototype-pollution) is focused on identifying prototype pollution vulnerabilities in client-side JavaScript. It includes examples of how prototype pollution can be exploited in browsers to perform XSS attacks and other malicious activities. It's a valuable resource for understanding the impact of prototype pollution on the client-side.

While identifying prototype pollution, the pentester should look for instances where user-controlled input might influence the keys or properties being merged, defined, or cloned. Verifying that the application properly sanitises and validates such input against modifying the prototype chain is crucial in preventing prototype pollution vulnerabilities.

---

## 5. Mitigation

### Pentesters

* **Input Fuzzing and Manipulation:** Interact with user inputs extensively, especially those used to interact with prototype-based structures, and fuzz them with a variety of payloads. Look for scenarios where untrusted data can lead to prototype pollution.
* **Context Analysis and Payload Injection:** Analyse the application's codebase to understand how user inputs are used within prototype-based structures. Inject payloads into these contexts to test for prototype pollution vulnerabilities.
* **CSP Bypass and Payload Injection:** Evaluate the effectiveness of security headers such as CSP in mitigating prototype pollution. Attempt to bypass CSP restrictions and inject payloads to manipulate prototypes.
* **Dependency Analysis and Exploitation:** Conduct a thorough analysis of third-party libraries and dependencies used by the application. Identify outdated or vulnerable libraries that may introduce prototype pollution vulnerabilities. Exploit these vulnerabilities to manipulate prototypes and gain unauthorised access or perform other malicious actions.
* **Static Code Analysis:** Use static code analysis tools to identify potential prototype pollution vulnerabilities during the development phase. These tools can provide insights into insecure coding patterns and potential security risks.

### Secure Code Developers

* **Avoid Using `__proto__`:** Refrain from using the `__proto__` property as it is mosltly susceptible to prototype pollution. Instead, use `Object.getPrototypeOf()` to access the prototype of an object in a safer manner.
* **Immutable Objects:** Design objects to be immutable when possible. This prevents unintended modifications to the prototype, reducing the impact of prototype pollution vulnerabilities.
* **Encapsulation:** Encapsulate objects and their functionalities, exposing only necessary interfaces. This can help prevent unauthorised access to object prototypes.
* **Use Safe Defaults:** When creating objects, establish safe default values and avoid relying on user inputs to set prototype properties. Initialise objects securely to minimise the risk of pollution.
* **Input Sanitisation:** Sanitise and validate user inputs thoroughly. Be cautious when using user-controlled data to modify object prototypes. Apply strict input validation practices to mitigate injection risks.
* **Dependency Management:** Regularly update and monitor dependencies. Choose well-maintained libraries and frameworks, and stay informed about any security updates or patches related to prototype pollution.
* **Security Headers:** Implement security headers such as Content Security Policy (CSP) to control the sources from which resources can be loaded. This can help mitigate the risk of loading malicious scripts that manipulate prototypes.

---
