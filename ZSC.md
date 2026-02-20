# OWASP-ZSC

[OWASP ZAP](https://github.com/OWASP/ZSC)

```bash
shellcode                   generate shellcode
shellcode>generate          generate shellcode
shellcode>search            search shellstorm
shellcode>download          download from shellstorm
shellcode>shell_storm_list  list shellstorm shellcodes

obfuscate                   generate obfuscated code

back                        go back
clear                       clear screen
help                        show help
update                      check for updates
about                       about
restart                     restart
version                     show version
exit | quit                 exit
#                           comment
zsc -h, --help              basic help
```

> **Note:** Use `TAB ⭾` to see the available options from that point, as shown below.

```bash
zsc/shellcode> 
download          generate          search            shell_storm_list
```

## Shellcode

**Shellcode** is a small piece of **machine-level code (binary instructions)** designed to be executed directly by the CPU, usually as a **payload during exploitation**.

* It is called “shellcode” because it traditionally opens a **command shell**, but it can perform any action (run commands, create connections, execute programs).
* It is written in **assembly or generated as raw bytes**, not high-level languages.
* Tools like OWASP ZSC can **generate and obfuscate shellcode** to make it harder to detect or analyze.
* Shellcode runs **directly in memory**, without needing compilation or an interpreter.

## Obfuscation

* Provides **script-level obfuscation** for supported interpreted languages (JavaScript, Perl, PHP, Python, Ruby).
* Uses simple techniques such as:
  * **Encoded payload wrapping** (Base64, hex, unicode)
  * **Indirect execution** (`eval`, `exec`)
  * **Basic structural distortion** to hide readable logic
* Operates at the **source/script and shellcode generation stage**, not after compilation.
* **Does not obfuscate compiled binaries** (.exe, ELF, Mach-O) and does not perform binary-level obfuscation.
* Obfuscated shellcode can be embedded into compiled programs, but ZSC does **not obfuscate the compiled program itself**.

```txt
Start ZSC → Obfuscate → Select Language → Select Script File → Choose Encoding/Obfuscation → Generate Obfuscated Script
```

---
