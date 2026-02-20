# JWT Security – Structured Summary

[JWT IO](https://jwt.io/)

---

## Chapter 1: Understanding JWTs

### 1.1 What is a JWT?

A **JWT (JSON Web Token)** is a compact, URL-safe token used to represent claims between two parties. It is typically used in **API authentication and authorization**.

It consists of three parts, each **Base64URL-encoded**:

```console
Header.Payload.Signature
```

Example:

```console
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJhZG1pbiI6dHJ1ZX0.
dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

### 1.2 JWT Structure

| Part      | Description                                                 |
| --------- | ----------------------------------------------------------- |
| Header    | Specifies the algorithm (e.g., HS256, RS256) and type (JWT) |
| Payload   | Contains claims like `sub`, `exp`, `admin`, `aud`, etc.     |
| Signature | Ensures the token's integrity using a cryptographic key     |

The header and payload are **not encrypted**, only **Base64URL-encoded**. The signature is used to detect tampering.

---

## Chapter 2: Why JWTs Are Not Encrypted

JWTs are typically **not encrypted** by design. The structure is intended to be **transparent**, readable by the recipient, and verifiable via signature.

### 2.1 Common Misunderstanding

Many expect tokens to be secret, but in JWTs:

* The **payload is readable** (including claims like `admin: true`)
* Confidentiality is **not guaranteed**
* **Integrity** is the primary security goal, via signature

If confidentiality is required, the token should be encrypted using **JWE (JSON Web Encryption)**, though JWE adoption is relatively rare due to complexity and performance costs.

### 2.2 Performance Consideration

* JWTs are designed for **stateless authentication**
* No need to store sessions in the database
* **No encryption** means faster processing, especially in microservices handling thousands of tokens per second

This trade-off prioritizes speed and simplicity over secrecy.

---

## Chapter 3: Task 4 – JWT Signing

This task introduces **JWT signature validation** using cryptographic algorithms.

### 3.1 Algorithms

* **HS256 (HMAC + SHA-256)**: A shared secret signs the token. Same key is used to verify.
* **RS256 (RSA Signature)**: Asymmetric. A private key signs the token, and a public key is used to verify.

Only the **signature** is protected cryptographically, not the payload or header.

### 3.2 Real-World Analogy

JWTs are like digitally signed letters:

* Everyone can **read** the contents (Base64)
* Only the signature proves it was **authentically created**

---

## Chapter 4: Task 5 – Signature Validation Mistakes

### 4.1 Vulnerabilities and Exploits

#### 1. Signature Not Verified

* Some servers parse the payload **without verifying** the signature.
* This allows attackers to **strip the signature** and modify the payload, e.g., flipping `admin: false` to `admin: true`.

**Exploit:** Remove or change the signature part of the token and access admin routes.

#### 2. Algorithm “None” Attack

* Change the JWT `alg` field to `"none"`
* Remove the signature
* Some libraries (if misconfigured) **accept it as valid**

**Exploit:** Craft a signature-less token and gain access as admin.

#### 3. Weak Secrets

* Use Hashcat (mode 16500) with a dictionary wordlist to brute-force weak **HMAC secrets**
* Once found, sign your own token

**Exploit:** Crack the key and forge valid tokens.

#### 4. HS256/RS256 Confusion

* Server accepts **both algorithms**
* Attacker changes `alg` from `RS256` to `HS256`
* Sends the public key as HMAC secret

**Exploit:** Sign your own token using the public key as the HMAC key.

---

## Chapter 5: Task 6 – JWT Lifetimes

### 5.1 Vulnerability

* If a token **does not include an `exp` claim**, it **never expires**
* The user retains access indefinitely, even after logout or role changes

### 5.2 Exploit

Use an old or stolen token without expiration to authenticate long after the session should be invalid.

### 5.3 Fixes

* Always include an `exp` (expiry) claim
* Implement token refresh logic
* Maintain a token revocation list (blacklist)

---

## Chapter 6: Task 7 – Cross-Service Relay Attack

### 6.1 Scenario

* Two services: `appA` and `appB`
* A central auth server issues tokens
* Tokens include an `aud` (audience) claim

### 6.2 Vulnerability

* `aud` is **not validated properly**
* A token valid for `appB` (where you’re admin) is accepted by `appA`

### 6.3 Exploit

* Log into `appB` and get a token with `aud: appB` and `admin: true`
* Use it to authenticate on `appA` and gain admin access

### 6.4 Remediation

* Always enforce strict `aud` claim validation
* Prevent cross-service token reuse
* Use separate token issuers or keys per audience

---

## Chapter 7: Realistic Use and Security Practices

### 7.1 Is Base64 Encoding Realistic?

Yes, in almost all real-world JWT implementations:

* **Base64URL encoding** is used to safely transfer data over HTTP
* Only the **signature** is cryptographically protected
* Encryption is **rare** unless confidentiality is necessary

### 7.2 Why Not Use Encrypted Tokens?

* JWTs are not secrets — they are **signed statements**, not encrypted messages
* If sensitive data must be hidden, it should be:

  * Stored elsewhere (e.g., in a database)
  * Encrypted separately
  * JWT payload can include only a reference ID

---

## Chapter 8: Summary Table

| Task | Vulnerability                 | Exploit                             | Flag             |
| ---- | ----------------------------- | ----------------------------------- | ---------------- |
| 4    | Weak understanding of signing | Misconfigurations in HS256/RS256    | Conceptual       |
| 5    | Signature validation flaws    | Strip sig, change alg, crack secret | example2–5 flags |
| 6    | Missing expiration (`exp`)    | Use old tokens forever              | example6 flag    |
| 7    | `aud` not validated           | Cross-service token reuse           | example7 flag    |

---

## Chapter 9: Best Practices for JWT Security

1. **Always verify signatures**

   * Use libraries that enforce this strictly
   * Never trust decoded payloads unless verified

2. **Whitelist only known algorithms**

   * Reject `none`, `HS256` if using asymmetric keys

3. **Use strong secrets**

   * At least 256-bit keys
   * Rotate secrets periodically

4. **Validate claims**

   * Check `exp`, `iat`, `nbf`
   * Check `aud` and `iss` strictly

5. **Avoid sensitive data in payload**

   * Never store passwords, card info, etc.

6. **Implement token rotation and revocation**

   * Support refresh tokens and blacklists

---
