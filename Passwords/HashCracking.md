# Hash Cracking

## 1. John the Ripper

```bash
# Commonly useful John options (quick notes)

--list=formats        # List all supported hash formats
--format=[HASH TYPE]  # Explicitly set hash type (same as -format:crypt; --format is preferred)
--wordlist=FILE       # Specify wordlist explicitly (often used with --rules)
--incremental         # Brute-force mode (no wordlist)
--show [HASH FILE]    # Display cracked passwords from john.pot for a specified file.
--users=USER[,USER]   # Show/crack only specific users
--session=NAME        # Name a cracking session
--restore             # Resume the last (or named) session
--status              # Show progress of a running session
--fork=N              # Parallel cracking using N processes
--rules               # Apply word-mangling rules to the wordlist (adds mutations)
--mask=?l?l?l?l?d     # Mask attack (pattern-based brute force)
```

> **Notes:**
>
> * Cracked passwords shown by `--show` are stored in `/root/.john/john.pot`.
> * John accepts both `--option=value` and `-option:value` syntax (e.g., `--format=crypt` ≡ `-format:crypt`).
> * Hash formats are usually auto-detected, but specifying `--format` avoids misdetection.
> * `--rules` + wordlist is usually more effective than a raw wordlist.
> * `--rules` are specified in `/etc/john/john.conf` and take external help regarding that.

---

## 2. Hashcat

```bash
hashcat -m [NUM] -a [NUM] [HashFile] [Wordlist] -o [Output file]
```

```bash
# Most Common hash mode(-m)
0 = MD5
100 = SHA1
1000 = NTLM
1400 = SHA256
1700 = SHA512
# Attack mode (-a)
0 = Straight
1 = Combination
3 = Brute-force
6 = Hybrid Wordlist + Mask
7 = Hybrid Mask + Wordlist
```

### The Salt

Hashcat needs salt in a hash file in this format:

```hash.txt
hash:salt

5f4dcc3b5aa765d61d8327deb882cf99:xyzsalt
```

Hashcat uses the salt internally. It does NOT guess salt. We must know **where the salt is combined with the password**, and select the appropriate Hashcat `-m` mode accordingly, because each mode defines a specific salt position (prefix, suffix, or other structure).

**Salt can found in Database, Hash dump, Source code, Binary analysis, Network traffic.**

---

## 3. Demo

### Linux Password Cracking

On Linux systems, `/etc/passwd` defines **accounts** (usernames, UIDs, login shells, and whether a login is possible), while `/etc/shadow` stores **credentials** (password hashes and aging data). Although `/etc/shadow` includes the username alongside the hash and is sufficient for password cracking, `/etc/passwd` is required to determine whether a cracked account actually exists, is usable, and is allowed to log in. In short: *`shadow` holds the secret; `passwd` determines whether that secret can be used*.

```bash
sudo john --format=crypt --wordlist=[WORDLIST] /etc/shadow
sudo john --show /etc/shadow
```

### Windows Password Cracking

> **Note:** These methods may only be applicable on windows 7 and older versions of windows.

**Method 1:**

We will use `pwdump7.exe` in this method. The requirements are:

* Administrator access to the windows machine.
* Ablility to deliver `pwdump7.exe` on the target machine.

```cmd
C:\Users\Administrator> pwdump7.exe > hash.txt
```

* Now exfiltrate the `hash.txt` to our machine.

```bash
john --format=NT --wordlist=rockyou.txt hash.txt
```

**Method 2:**

This method assumes you have already exfiltrated the `SAM` and `SYSTEM` files.

```hash
samdump SYSTEM SAM > hash.txt
```

we can use same procedure from here.

---
